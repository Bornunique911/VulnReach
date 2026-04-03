from __future__ import annotations

from typing import Any, Dict, List

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
    return enriched

