"""EvidenceGraphBuilder — normalise raw scan outputs into a stable AI input.

The LLM (NextStepsReasoner) must never consume raw scanner JSON directly.
Raw outputs change shape between tool versions, language analysers, and
runtime modes. Coupling the prompt to that surface area would make the
AI layer brittle and unauditable.

The EvidenceGraph is the contract between the deterministic engine and
the AI layer:

  * versioned (``EVIDENCE_GRAPH_VERSION``) so cache keys and prompt
    upgrades stay coherent;
  * deterministic — same inputs produce the same graph, so the
    ``evidence_hash`` can drive cache lookups;
  * narrow — only the fields the prompt actually consumes.

Finding identity:

    finding_id := "<scan_id>:<cve_id>"

(optionally ``"<scan_id>:<cve_id>:<package>"`` to disambiguate when one
CVE appears under multiple packages in the same scan).
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

EVIDENCE_GRAPH_VERSION = "1.0.0"

_FRAMEWORK_HINTS = {
    "django", "flask", "fastapi", "starlette", "tornado",
    "aiohttp", "bottle", "sanic", "quart", "falcon",
    "spring", "springboot", "express", "koa", "hapi",
}


class EvidenceGraphBuilder:
    """Build a normalised EvidenceGraph for a deterministic finding.

    Parameters
    ----------
    storage:
        A ``StorageRepository`` implementation. Only ``get_scan(scan_id)``
        is used.
    """

    def __init__(self, storage: Any) -> None:
        self._storage = storage

    def build(self, finding_id: str) -> Dict[str, Any]:
        """Build the EvidenceGraph for ``finding_id``.

        Raises:
            LookupError: when the scan or finding cannot be resolved.
        """
        scan_id, cve_id, package_hint = parse_finding_id(finding_id)
        scan = self._storage.get_scan(scan_id)
        if not scan:
            raise LookupError(f"scan {scan_id!r} not found")

        return build_evidence_graph(
            finding_id=finding_id,
            scan_id=scan_id,
            cve_id=cve_id,
            package_hint=package_hint,
            scan=scan,
        )


def parse_finding_id(finding_id: str) -> Tuple[str, str, Optional[str]]:
    """Split a composite finding id into ``(scan_id, cve_id, package?)``.

    Raises:
        ValueError: when the id is malformed.
    """
    if not finding_id or ":" not in finding_id:
        raise ValueError(
            "finding_id must be of the form '<scan_id>:<cve_id>' "
            "(optionally '<scan_id>:<cve_id>:<package>')"
        )
    parts = finding_id.split(":", 2)
    if len(parts) == 2:
        scan_id, cve_id = parts
        return scan_id, cve_id, None
    scan_id, cve_id, package = parts
    return scan_id, cve_id, package or None


def build_evidence_graph(
    *,
    finding_id: str,
    scan_id: str,
    cve_id: str,
    package_hint: Optional[str],
    scan: Dict[str, Any],
) -> Dict[str, Any]:
    """Compose the EvidenceGraph dict from a fully-loaded scan record."""
    correlation_row = _select_correlation(scan, cve_id, package_hint)
    reachability_row = _select_reachability(scan, cve_id, package_hint)
    vuln_row = _select_vulnerability(scan, cve_id, package_hint)

    package = (
        (correlation_row or {}).get("package")
        or (reachability_row or {}).get("package")
        or (vuln_row or {}).get("package")
        or package_hint
    )

    raw = scan.get("raw") or {}
    routes = _normalise_routes(scan.get("routes") or _routes_from_raw(raw))
    imports = _imports_from_raw(raw, package)
    call_paths = _call_paths_from_raw(raw, package)
    taint_paths = _taint_paths_from_raw(raw, package)
    runtime_events = _runtime_events_from_raw(raw, package)
    snippets = _snippets_from_correlation(correlation_row, reachability_row)

    framework = _detect_framework(scan, routes)
    evidence_strength = _evidence_strength(correlation_row, reachability_row, runtime_events)

    graph = {
        "evidence_graph_version": EVIDENCE_GRAPH_VERSION,
        "finding": {
            "id": finding_id,
            "verdict": (correlation_row or {}).get("verdict"),
            "confidence": (correlation_row or {}).get("confidence"),
            "severity": (correlation_row or {}).get("severity") or (vuln_row or {}).get("severity"),
            "evidence_type": (
                (correlation_row or {}).get("evidence_type")
                or (reachability_row or {}).get("evidence_type")
            ),
            "reachability_class": (correlation_row or {}).get("reachability_class"),
        },
        "cve": {
            "id": cve_id,
            "description": (vuln_row or {}).get("description"),
            "vulnerability_type": (vuln_row or {}).get("vulnerability_type"),
            "attack_vector": (vuln_row or {}).get("attack_vector"),
            "affected_apis": (vuln_row or {}).get("affected_apis") or [],
            "preconditions": (vuln_row or {}).get("preconditions") or [],
        },
        "dependency": {
            "name": package,
            "version": (vuln_row or {}).get("version"),
            "fix_version": (vuln_row or {}).get("fix_version"),
        },
        "framework": {"name": framework} if framework else {},
        "evidence_strength": evidence_strength,
        "routes": routes,
        "imports": imports,
        "call_paths": call_paths,
        "taint_paths": taint_paths,
        "runtime_events": runtime_events,
        "snippets": snippets,
    }
    return graph


def evidence_hash(graph: Dict[str, Any]) -> str:
    """Stable sha256 over the EvidenceGraph (without the version field).

    The version is excluded so a graph-format bump alone does not invalidate
    every cache entry — the cache key composes hash + ``EVIDENCE_GRAPH_VERSION``
    + ``PROMPT_VERSION`` explicitly.
    """
    payload = {k: v for k, v in graph.items() if k != "evidence_graph_version"}
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ── selectors over the scan record ─────────────────────────────────────


def _matches_cve(row: Dict[str, Any], cve_id: str) -> bool:
    row_cve = row.get("cve_id")
    if isinstance(row_cve, list):
        return cve_id in row_cve
    return row_cve == cve_id


def _select_correlation(
    scan: Dict[str, Any],
    cve_id: str,
    package_hint: Optional[str],
) -> Optional[Dict[str, Any]]:
    rows = scan.get("correlation") or []
    candidates = [r for r in rows if _matches_cve(r, cve_id)]
    if package_hint:
        narrowed = [r for r in candidates if r.get("package") == package_hint]
        if narrowed:
            return narrowed[0]
    return candidates[0] if candidates else None


def _select_reachability(
    scan: Dict[str, Any],
    cve_id: str,
    package_hint: Optional[str],
) -> Optional[Dict[str, Any]]:
    rows = scan.get("reachability") or []
    candidates = [r for r in rows if r.get("cve_id") == cve_id]
    if package_hint:
        narrowed = [r for r in candidates if r.get("package") == package_hint]
        if narrowed:
            return narrowed[0]
    return candidates[0] if candidates else None


def _select_vulnerability(
    scan: Dict[str, Any],
    cve_id: str,
    package_hint: Optional[str],
) -> Optional[Dict[str, Any]]:
    rows = scan.get("vulnerabilities") or []
    candidates = [r for r in rows if _matches_cve(r, cve_id)]
    if package_hint:
        narrowed = [r for r in candidates if r.get("package") == package_hint]
        if narrowed:
            return narrowed[0]
    return candidates[0] if candidates else None


# ── normalisers ────────────────────────────────────────────────────────


def _normalise_routes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows or []:
        out.append({
            "method": r.get("method"),
            "path": r.get("path"),
            "handler": r.get("handler"),
            "framework": r.get("framework"),
        })
    return out


def _routes_from_raw(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    payload = raw.get("route_extractor") or {}
    return payload.get("routes") or payload.get("findings") or []


def _imports_from_raw(raw: Dict[str, Any], package: Optional[str]) -> List[str]:
    if not package:
        return []
    mapping = (raw.get("metadata") or {}).get("findings") or []
    out: List[str] = []
    for row in mapping:
        if row.get("distribution") == package and row.get("import_name"):
            out.append(row["import_name"])
    return out


def _call_paths_from_raw(raw: Dict[str, Any], package: Optional[str]) -> List[List[str]]:
    if not package:
        return []
    paths: List[List[str]] = []
    for tool_name in ("python_reachability", "java_reachability", "multi_language_reachability"):
        payload = raw.get(tool_name) or {}
        analyses = payload.get("vulnerabilities") or payload.get("analyses") or []
        for analysis in analyses:
            if analysis.get("package_name") != package:
                continue
            for path in analysis.get("call_paths") or []:
                if isinstance(path, list):
                    paths.append([str(n) for n in path])
    return paths


def _taint_paths_from_raw(raw: Dict[str, Any], package: Optional[str]) -> List[List[str]]:
    payload = raw.get("tainter") or {}
    flows = payload.get("flows") or payload.get("taint_paths") or []
    out: List[List[str]] = []
    for flow in flows:
        if package and flow.get("package") and flow["package"] != package:
            continue
        steps = flow.get("steps") or flow.get("path") or []
        if steps:
            out.append([str(s) for s in steps])
    return out


def _runtime_events_from_raw(raw: Dict[str, Any], package: Optional[str]) -> List[Dict[str, Any]]:
    payload = raw.get("dynamic_reachability") or {}
    events: List[Dict[str, Any]] = []
    for ev in payload.get("events") or []:
        if package and ev.get("package") and ev["package"] != package:
            continue
        events.append({
            "type": ev.get("type"),
            "module": ev.get("module"),
            "api": ev.get("api"),
        })
    if not events:
        modules = payload.get("modules_loaded") or []
        for mod in modules:
            if package and not str(mod).startswith(package):
                continue
            events.append({"type": "module_loaded", "module": mod})
    return events


def _snippets_from_correlation(
    correlation_row: Optional[Dict[str, Any]],
    reachability_row: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    snippets: List[Dict[str, Any]] = []
    files = (reachability_row or {}).get("files") or []
    for f in files[:3]:
        if isinstance(f, dict) and f.get("path"):
            snippets.append({"file": f["path"], "code": f.get("snippet")})
        elif isinstance(f, str):
            snippets.append({"file": f, "code": None})
    return snippets


def _detect_framework(scan: Dict[str, Any], routes: List[Dict[str, Any]]) -> Optional[str]:
    for r in routes:
        fw = (r.get("framework") or "").lower()
        if fw in _FRAMEWORK_HINTS:
            return fw
    for dep in scan.get("vulnerabilities") or []:
        pkg = (dep.get("package") or "").lower()
        if pkg in _FRAMEWORK_HINTS:
            return pkg
    return None


def _evidence_strength(
    correlation_row: Optional[Dict[str, Any]],
    reachability_row: Optional[Dict[str, Any]],
    runtime_events: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Derive per-evidence-tier strength estimates without re-deriving verdict."""
    confidence = float((correlation_row or {}).get("confidence") or 0.0)
    has_call_chain = bool((reachability_row or {}).get("call_chain_exists"))
    has_import = bool((reachability_row or {}).get("import_detected"))
    has_runtime = bool(runtime_events)

    return {
        "runtime": confidence if has_runtime else 0.0,
        "taint": confidence if has_call_chain else 0.0,
        "static": confidence * 0.5 if has_import else 0.0,
    }


__all__ = [
    "EVIDENCE_GRAPH_VERSION",
    "EvidenceGraphBuilder",
    "build_evidence_graph",
    "evidence_hash",
    "parse_finding_id",
]
