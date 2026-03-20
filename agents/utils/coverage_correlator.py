"""Shared coverage correlation logic.

Used by DynamicReachabilityAgent (Docker/Schemathesis) and
PytestCoverageAgent to translate a coverage.py JSON report into
ReachabilityFinding objects.

Both agents produce coverage.json in the standard coverage.py format:
  {
    "files": {
      "/path/to/file.py": {
        "executed_lines": [1, 2, 3, ...],
        "functions": {
          "func_name": {"executed_lines": [4, 5], ...}
        }
      }
    }
  }
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import ReachabilityFinding
from agents.utils.import_resolver import (
    resolve_import_name as _resolve_import_name,
    word_match as _word_match,
    path_component_match as _path_component_match,
)

logger = logging.getLogger(__name__)

# Minimum package name length to match safely (avoids 're', 'os', etc.)
_MIN_PKG_MATCH_LEN = 4


def build_hit_sets(
    coverage_data: Dict[str, Any],
) -> tuple[set[str], set[str], set[str]]:
    """Parse coverage.json into three hit sets.

    Returns:
        (call_hit_files, import_hit_files, hit_functions)

        call_hit_files   — last-2-component paths where ≥1 function body ran
                           (e.g. "urllib3/__init__.py"). Preserves the package
                           directory so path_component_match can find it.
                           When coverage.py has no per-function breakdown,
                           any file with executed lines is conservatively
                           classified as a call hit.
        import_hit_files — paths where module-level code ran but every
                           function reported zero executed lines (import-time
                           load only, no actual call).
        hit_functions    — function names (and "rel-path:funcname" pairs) that
                           had at least one executed line.
    """
    call_hit_files: set[str] = set()
    import_hit_files: set[str] = set()
    hit_functions: set[str] = set()

    for file_path, file_data in coverage_data.get("files", {}).items():
        executed = file_data.get("executed_lines") or []
        if not executed:
            # File was measured but nothing ran — measuring artefact only.
            continue

        # Keep last 2 path components so package dir is preserved:
        # e.g. /app/site-packages/urllib3/__init__.py → urllib3/__init__.py
        # This allows path_component_match("urllib3", "urllib3/__init__.py") to work.
        _parts = Path(file_path).parts
        rel = str(Path(*_parts[-2:])) if len(_parts) >= 2 else Path(file_path).name
        functions: dict = file_data.get("functions") or {}

        if not functions:
            # No per-function data (older coverage.py) — conservatively call-hit.
            call_hit_files.add(rel)
        else:
            any_func_called = False
            for func_name, func_data in functions.items():
                if func_data.get("executed_lines"):
                    any_func_called = True
                    hit_functions.add(func_name)
                    hit_functions.add(f"{rel}:{func_name}")

            if any_func_called:
                call_hit_files.add(rel)
            else:
                # Package imported (module-level ran) but nothing called.
                import_hit_files.add(rel)

    return call_hit_files, import_hit_files, hit_functions


def _build_static_function_index(
    static_findings: List[Dict[str, Any]],
) -> Dict[str, set[str]]:
    """Build CVE → {app function names} from static analysis findings.

    Static findings contain function chains like
    ``"src.app.render_test, flask.render_template_string"``.
    We extract the **app-side** function names (the callers, not the library
    sinks) so we can check if they were executed at runtime.
    """
    index: Dict[str, set[str]] = {}
    for finding in static_findings:
        cve = finding.get("cve_id")
        if not cve:
            continue
        raw_fn = finding.get("function") or ""
        for fn in raw_fn.split(","):
            fn = fn.strip().lower()
            if not fn:
                continue
            # Keep function names that look like app code (contain a dot
            # like "src.app.render_test") or plain names like "yaml_unsafe".
            # Skip library sinks (flask.*, jinja2.*, etc.) — those won't
            # appear in app-code coverage.
            index.setdefault(cve, set()).add(fn)
            # Also add the bare function name (last segment after dots)
            bare = fn.rsplit(".", 1)[-1]
            if bare:
                index.setdefault(cve, set()).add(bare)
    return index


def correlate_coverage(
    coverage_data: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    import_map: Optional[Dict[str, str]] = None,
    evidence_type: str = "dynamic",
    static_findings: Optional[List[Dict[str, Any]]] = None,
) -> List[ReachabilityFinding]:
    """Cross-reference a coverage.py JSON report with vulnerability findings.

    Args:
        coverage_data:  Parsed coverage.json dict (``{"files": {...}}``)
        vulnerabilities: List of vulnerability dicts from Trivy/ScanContext.
        import_map:     Optional dist_name → module_name map (from MetadataAgent).
        evidence_type:  ``"dynamic"`` (Docker/Schemathesis) or ``"pytest"``.
        static_findings: Optional list of static analysis findings (from tainter
                         / python_reachability) used to cross-reference: if a
                         static call chain's app-side function was executed at
                         runtime, the library package is considered dynamically
                         reachable even though coverage only measured app code.

    Verdicts emitted per CVE:
        CONFIRMED  → call_hit  (a function in the package was actually invoked)
        LIKELY     → import_hit (package was loaded but nothing was called)
        LIKELY     → no hit at all (package not observed in coverage)
    """
    call_hit_files, import_hit_files, hit_functions = build_hit_sets(coverage_data)

    # Index for cross-referencing static call chains with runtime coverage.
    # If static analysis says render_test → flask.render_template_string
    # and coverage shows render_test was executed, Flask is runtime-confirmed.
    static_fn_index = _build_static_function_index(static_findings or [])

    findings: List[ReachabilityFinding] = []

    for vuln in vulnerabilities:
        pypi_name = (vuln.get("package") or "").lower()
        if not pypi_name:
            continue

        import_name = _resolve_import_name(pypi_name, import_map).lower()

        cves = vuln.get("cve_id", [])
        if isinstance(cves, str):
            cves = [cves]
        if not cves:
            cves = [None]

        call_hit = False
        import_only_hit = False

        # Strategy 1: Direct library path/function match in coverage
        if len(import_name) >= _MIN_PKG_MATCH_LEN:
            call_hit = any(
                _path_component_match(import_name, f) for f in call_hit_files
            ) or any(
                _word_match(import_name, fn) for fn in hit_functions
            )
            if not call_hit:
                import_only_hit = any(
                    _path_component_match(import_name, f) for f in import_hit_files
                )

        # Strategy 2: Cross-reference static call chains with coverage.
        # Coverage typically only measures app code (src/app.py), not library
        # site-packages.  But if static analysis shows an app function calls
        # into a vulnerable library AND that app function was executed at
        # runtime, the library is transitively confirmed reachable.
        if not call_hit:
            for cve in cves:
                if cve and cve in static_fn_index:
                    static_fns = static_fn_index[cve]
                    # Check if any of the static call chain functions were hit
                    hit_fns_lower = {fn.lower() for fn in hit_functions}
                    if static_fns & hit_fns_lower:
                        call_hit = True
                        import_only_hit = False
                        logger.info(
                            f"[coverage] {pypi_name} ({cve}): runtime-confirmed "
                            f"via static call chain — matched functions: "
                            f"{static_fns & hit_fns_lower}"
                        )
                        break

        if call_hit:
            verdict = "CONFIRMED"
            confidence = 0.95
            sink_reachable = True
            import_time_hit = False
        elif import_only_hit:
            verdict = "LIKELY"
            confidence = 0.65
            sink_reachable = False
            import_time_hit = True
        else:
            verdict = "LIKELY"
            confidence = 0.50
            sink_reachable = False
            import_time_hit = False

        all_hit_files = call_hit_files | import_hit_files
        for cve in cves:
            findings.append(
                ReachabilityFinding(
                    cve_id=cve,
                    package=vuln.get("package"),
                    import_detected=True,
                    call_chain_exists=call_hit,
                    sink_reachable=sink_reachable,
                    import_time_hit=import_time_hit,
                    verdict=verdict,
                    confidence=confidence,
                    evidence_type=evidence_type,
                    function=None,
                    files=list(all_hit_files)[:5],
                )
            )

    return findings
