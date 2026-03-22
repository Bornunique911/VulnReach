"""Tainter Agent — source-to-sink taint analysis via the `tainter` CLI.

Flow:
  Step 1 — Pre-flight: verify tainter is on PATH and repo_path exists
  Step 2 — Run `tainter scan` against the repo, capture JSON output
  Step 3 — Parse flows into (file, function, sink) triples
  Step 4 — Cross-reference flows with known CVE vulnerabilities
  Step 5 — Emit ReachabilityFinding per CVE with CONFIRMED / LIKELY verdict
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.agent import BaseAgent
from core.models import AgentResult, ReachabilityFinding, ScanContext
from correlation.engine import reachability_verdict

logger = logging.getLogger(__name__)

# How long to wait for tainter scan to complete (seconds)
_SCAN_TIMEOUT = 120

# Tainter output format flag — assumes tainter supports --format json
_TAINTER_FORMAT = "json"


class TainterAgent(BaseAgent):
    tool_name = "tainter"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        # ------------------------------------------------------------------
        # Step 1 — Pre-flight
        # ------------------------------------------------------------------
        if not context.repo_path:
            return self._skipped("missing_repo_path")

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return self._skipped("repo_path_not_found")

        tainter_bin = shutil.which("tainter")
        if not tainter_bin:
            logger.warning("[tainter] tainter not found on PATH — skipping")
            return self._skipped("tainter_not_on_path")

        # ------------------------------------------------------------------
        # Step 2 — Run tainter scan
        # ------------------------------------------------------------------
        raw_output, scan_meta = await self._run_scan(tainter_bin, repo_path)
        if raw_output is None:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"status": "failed", **scan_meta},
            )

        # ------------------------------------------------------------------
        # Step 3 — Parse flows
        # ------------------------------------------------------------------
        flows, parse_meta = self._parse_flows(raw_output)
        logger.info(f"[tainter] Parsed {len(flows)} taint flows from output")

        # ------------------------------------------------------------------
        # Step 4 + 5 — Cross-reference with vulnerabilities and emit findings
        # ------------------------------------------------------------------
        findings = self._correlate(flows, context.vulnerabilities, repo_path=repo_path)

        return AgentResult(
            tool_name=self.tool_name,
            findings=[f.model_dump() for f in findings],
            metadata={
                "status": "ok",
                "finding_count": len(findings),
                "flow_count": len(flows),
                "flows": flows,
                "scan": scan_meta,
                "parse": parse_meta,
            },
        )

    # ------------------------------------------------------------------
    # Step 2 — Run tainter scan
    # ------------------------------------------------------------------

    async def _run_scan(
        self, tainter_bin: str, repo_path: Path
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """
        Run: tainter scan <repo_path> --format json

        Returns (stdout_text, meta). stdout_text is None on failure.
        """
        cmd = ["/Library/Frameworks/Python.framework/Versions/3.11/bin/tainter", "scan", str(repo_path), "--format", _TAINTER_FORMAT]
        logger.info(f"[tainter] Running: {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=_SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error(f"[tainter] Scan timed out after {_SCAN_TIMEOUT}s")
            return None, {"error": "scan_timeout", "cmd": " ".join(cmd)}

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        meta: Dict[str, Any] = {
            "cmd": " ".join(cmd),
            "returncode": proc.returncode,
        }

        if proc.returncode != 0:
            logger.error(
                f"[tainter] Scan failed (rc={proc.returncode}): {stderr_text[:500]}"
            )
            meta["stderr"] = stderr_text[:500]
            # returncode 1 sometimes just means "findings found" — try to parse anyway
            if stdout_text.strip():
                logger.info("[tainter] Non-zero rc but stdout present — attempting parse")
                return stdout_text, meta
            return None, meta

        if stderr_text.strip():
            meta["stderr_warnings"] = stderr_text[:300]

        return stdout_text, meta

    # ------------------------------------------------------------------
    # Step 3 — Parse flows
    # ------------------------------------------------------------------

    def _parse_flows(
        self, raw_output: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Parse tainter JSON output into a list of flow dicts.

        Expected tainter JSON schema (best-effort — adapt if CLI differs):
        {
          "flows": [
            {
              "source": {"file": "...", "line": N, "type": "..."},
              "sink":   {"file": "...", "line": N, "type": "...", "function": "..."},
              "path":   [...],
              "packages": ["requests", ...]   // optional
            }
          ]
        }

        If the top-level is a list, treat each element as a flow directly.
        """
        raw = raw_output.strip()
        if not raw:
            return [], {"error": "empty_output"}

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(f"[tainter] JSON parse failed: {exc} — trying line-delimited")
            # Try newline-delimited JSON (one flow per line)
            flows = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    flows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            if flows:
                return flows, {"format": "ndjson", "flow_count": len(flows)}
            return [], {"error": "json_parse_failed", "detail": str(exc)}

        # Normalise to a list of flow dicts
        if isinstance(data, list):
            flows = data
        elif isinstance(data, dict):
            flows = data.get("flows") or data.get("results") or data.get("vulnerabilities") or []
            if not isinstance(flows, list):
                flows = [data]  # single flow wrapped in dict
        else:
            return [], {"error": "unexpected_output_type", "type": type(data).__name__}

        return flows, {"format": "json", "flow_count": len(flows)}

    # ------------------------------------------------------------------
    # Step 4 + 5 — Correlate flows with CVE vulnerabilities
    # ------------------------------------------------------------------

    def _correlate(
        self,
        flows: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        repo_path: Optional[Path] = None,
    ) -> List[ReachabilityFinding]:
        """
        Match taint flows to vulnerable packages.

        A flow is associated with a package when:
          - The flow's sink type / function name contains the package import name, OR
          - The flow explicitly lists the package in a `packages` field, OR
          - The sink file path contains the package name.

        Verdicts:
          CONFIRMED  — taint flow reaches a sink associated with this package
          LIKELY     — package is imported/used but no direct taint flow found
          UNLIKELY   — no import or flow evidence
        """
        # Build a set of (package_import_name, sink_function, sink_file) triples
        # from all taint flows so we can do O(1) lookups per vuln.
        flow_packages: Set[str] = set()         # packages mentioned in flows
        flow_sinks: List[Dict[str, Any]] = []   # full sink info for metadata

        for flow in flows:
            # Packages explicitly listed by tainter
            explicit_pkgs = flow.get("packages") or []
            for pkg in explicit_pkgs:
                flow_packages.add(pkg.lower())

            # Also index sink details — support both flat and nested formats:
            #   Flat:   {"function": "yaml.load", "file": "app.py", ...}
            #   Nested: {"definition": {"module": "yaml", "function": "load"},
            #            "location":   {"file": "app.py", ...}, "code": "..."}
            sink = flow.get("sink") or {}
            sink_def = sink.get("definition") or {}
            sink_loc = sink.get("location") or {}

            # Function: prefer nested definition.function, fall back to flat keys
            sink_fn = (
                sink_def.get("function")
                or sink.get("function")
                or sink.get("type")
                or ""
            ).lower()

            # File: prefer nested location.file, fall back to flat key
            sink_file = Path(
                sink_loc.get("file") or sink.get("file") or ""
            ).name.lower()

            # Module/package: from definition.module (nested format only)
            sink_module = (sink_def.get("module") or "").lower()
            if sink_module and len(sink_module) >= 4:
                flow_packages.add(sink_module)

            flow_sinks.append({
                "function": sink_fn,
                "file": sink_file,
                "line": sink_loc.get("line") or sink.get("line"),
                "type": sink.get("type"),
            })

            # Heuristic: if the sink file is named after a package (e.g. requests/api.py)
            # extract the parent directory name as a package hint
            full_sink_path = sink_loc.get("file") or sink.get("file") or ""
            parts = Path(full_sink_path).parts
            for part in parts:
                if len(part) >= 4:  # skip short path components
                    flow_packages.add(part.lower())

            # Sink source file import scan — read the file that contains the
            # taint sink and extract all top-level imports. This catches cases
            # where the tainter CLI misclassifies the module (e.g. DRF's
            # rest_framework.response.Response reported as flask.Response).
            if repo_path and full_sink_path:
                try:
                    p = Path(full_sink_path)
                    if not p.is_absolute() or not p.exists():
                        p = repo_path / full_sink_path
                    if p.exists() and p.suffix == ".py":
                        import re as _re
                        src = p.read_text(encoding="utf-8", errors="replace")
                        for m in _re.finditer(
                            r"^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                            src,
                            _re.MULTILINE,
                        ):
                            pkg = m.group(1).lower()
                            if len(pkg) >= 3:
                                flow_packages.add(pkg)
                except Exception:
                    pass

        findings: List[ReachabilityFinding] = []

        for vuln in vulnerabilities:
            pypi_name = (vuln.get("package") or "").lower()
            if not pypi_name:
                continue

            # Resolve known PyPI → import name mismatches
            import_name = _PYPI_TO_IMPORT.get(pypi_name, pypi_name)

            cves = vuln.get("cve_id") or []
            if not isinstance(cves, list):
                cves = [cves]
            if not cves:
                cves = [None]

            # Check if any flow involves this package
            flow_hit = (
                import_name in flow_packages
                or pypi_name in flow_packages
                or any(
                    import_name in s["function"] or import_name in s["file"]
                    for s in flow_sinks
                )
            )

            # Also check sink function names for package-specific sink patterns
            # e.g. requests.get, yaml.load, subprocess.call
            sink_match = any(
                self._sink_matches_package(s, import_name)
                for s in flow_sinks
            )

            taint_reachable = flow_hit or sink_match

            # Gather matched sink files for evidence
            matched_files = list({
                s["file"] for s in flow_sinks
                if self._sink_matches_package(s, import_name)
            })[:5]

            for cve in cves:
                import_detected = bool(vuln.get("is_used", True))
                call_chain_exists = taint_reachable

                verdict = reachability_verdict(
                    import_detected=import_detected,
                    call_chain_exists=call_chain_exists,
                    sink_reachable=taint_reachable,
                )
                confidence = 0.90 if taint_reachable else 0.60

                findings.append(
                    ReachabilityFinding(
                        cve_id=cve,
                        package=vuln.get("package"),
                        import_detected=import_detected,
                        call_chain_exists=call_chain_exists,
                        sink_reachable=taint_reachable,
                        verdict=verdict,
                        confidence=confidence,
                        evidence_type="taint",
                        function=None,
                        files=matched_files or [],
                    )
                )

        return findings

    def _sink_matches_package(self, sink: Dict[str, Any], import_name: str) -> bool:
        """
        Return True if a sink record is attributable to the given package.
        Checks sink function name and file path for the import name.
        """
        if len(import_name) < 4:
            return False  # too short to match safely
        fn = sink.get("function") or ""
        file_ = sink.get("file") or ""
        return import_name in fn or import_name in file_

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _skipped(self, reason: str) -> AgentResult:
        logger.info(f"[tainter] Skipped — {reason}")
        return AgentResult(
            tool_name=self.tool_name,
            findings=[],
            metadata={"status": "skipped", "reason": reason},
        )


# Known PyPI name → importable package name mappings
_PYPI_TO_IMPORT: Dict[str, str] = {
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "mysqlclient": "MySQLdb",
    "pyjwt": "jwt",
    # Django ecosystem
    "djangorestframework": "rest_framework",
    "psycopg2-binary": "psycopg2",
    "django-cors-headers": "corsheaders",
    "django-filter": "django_filters",
    "celery": "celery",
    # Other common mismatches
    "python-jose": "jose",
    "python-multipart": "multipart",
    "httpx": "httpx",
}