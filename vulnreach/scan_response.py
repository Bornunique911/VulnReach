from __future__ import annotations

from typing import Any, Dict, List

_TAINT_TOOLS = {"tainter"}
_AST_TOOLS = {"python_reachability", "java_reachability", "multi_language_reachability"}
_RUNTIME_TOOLS = {"dynamic_reachability", "pytest_coverage"}
_ROUTE_TOOLS = {"route_extractor"}
_SCA_TOOLS = {"trivy"}

_REACHABILITY_CLASSES = {
    "DYNAMICALLY_REACHABLE",
    "STATICALLY_REACHABLE",
    "UNCERTAIN",
    "NOT_REACHABLE",
}


def reachability_class_from_correlation(item: Dict[str, Any]) -> str:
    """Resolve reachability class from top-level fields or evidence fallback."""
    top = str(item.get("reachability_class") or "").strip().upper()
    if top in _REACHABILITY_CLASSES:
        return top

    evidence = item.get("evidence") or {}
    ev = str(evidence.get("reachability_class") or "").strip().upper()
    if ev in _REACHABILITY_CLASSES:
        return ev

    # Legacy fallback when older rows only have verdict.
    verdict = str(item.get("verdict") or "").strip().upper()
    if verdict == "CONFIRMED":
        return "DYNAMICALLY_REACHABLE"
    if verdict == "LIKELY":
        return "STATICALLY_REACHABLE"
    if verdict == "POSSIBLE":
        return "UNCERTAIN"
    return "NOT_REACHABLE"


def _build_analysis_coverage(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Derive which analysis layers ran, were skipped, or errored from raw tool outputs."""
    tools_ran: List[str] = []
    tools_skipped: Dict[str, str] = {}
    tools_errored: Dict[str, str] = {}

    for tool_name, payload in (raw or {}).items():
        if isinstance(payload, dict):
            if payload.get("status") == "skipped":
                tools_skipped[tool_name] = str(payload.get("reason", ""))
            elif "error" in payload:
                tools_errored[tool_name] = str(payload["error"])
            else:
                tools_ran.append(tool_name)
        else:
            tools_ran.append(tool_name)

    ran_set = set(tools_ran)
    evidence_layers = {
        "sca": bool(ran_set & _SCA_TOOLS),
        "taint": bool(ran_set & _TAINT_TOOLS),
        "ast": bool(ran_set & _AST_TOOLS),
        "route": bool(ran_set & _ROUTE_TOOLS),
        "runtime": bool(ran_set & _RUNTIME_TOOLS),
    }

    return {
        "tools_ran": sorted(tools_ran),
        "tools_skipped": tools_skipped,
        "tools_errored": tools_errored,
        "evidence_layers": evidence_layers,
    }


def augment_scan_response(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add API/package contract fields expected by clients:
    - summary
    - dynamically_reachable / statically_reachable / uncertain / not_reachable
    - pipeline_status
    """
    enriched = dict(scan)
    correlation = list(enriched.get("correlation") or [])

    dynamically_reachable: List[Dict[str, Any]] = []
    statically_reachable: List[Dict[str, Any]] = []
    uncertain: List[Dict[str, Any]] = []
    not_reachable: List[Dict[str, Any]] = []

    for item in correlation:
        cls = reachability_class_from_correlation(item)
        if cls == "DYNAMICALLY_REACHABLE":
            dynamically_reachable.append(item)
        elif cls == "STATICALLY_REACHABLE":
            statically_reachable.append(item)
        elif cls == "UNCERTAIN":
            uncertain.append(item)
        else:
            not_reachable.append(item)

    enriched["dynamically_reachable"] = dynamically_reachable
    enriched["statically_reachable"] = statically_reachable
    enriched["uncertain"] = uncertain
    enriched["not_reachable"] = not_reachable
    enriched["summary"] = {
        "total": len(correlation),
        "dynamically_reachable": len(dynamically_reachable),
        "statically_reachable": len(statically_reachable),
        "uncertain": len(uncertain),
        "not_reachable": len(not_reachable),
    }
    enriched["pipeline_status"] = (
        "BLOCK" if str(enriched.get("status", "")).lower() == "blocked" else "PASS"
    )
    enriched["analysis_coverage"] = _build_analysis_coverage(enriched.get("raw") or {})
    return enriched

