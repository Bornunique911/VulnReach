"""
build_fix_plan — pure computation over an existing scan result dict.

Returns a list of package upgrade recommendations sorted by the number
of reachable CVEs removed (highest first).
"""

from typing import Any, Dict, List

_REACHABLE_CLASSES = {"DYNAMICALLY_REACHABLE", "STATICALLY_REACHABLE"}


def build_fix_plan(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a fix plan from a scan result dict (as returned by storage.get_scan()).

    Each entry describes one package upgrade and which reachable CVEs it removes.
    """
    vulns = scan.get("vulnerabilities") or []
    correlation = scan.get("correlation") or []

    # Map cve_id → reachability info from correlation
    cve_reach: Dict[str, Dict[str, Any]] = {}
    for finding in correlation:
        cve_id = finding.get("cve_id")
        if not cve_id:
            continue
        reach_class = finding.get("reachability_class") or (
            (finding.get("evidence") or {}).get("reachability_class")
        )
        cve_reach[cve_id] = {
            "reachability_class": reach_class,
            "verdict": finding.get("verdict"),
            "risk_score": finding.get("risk_score") or 0.0,
        }

    # Group vulnerabilities by package, collect CVEs + fix version
    pkg_map: Dict[str, Dict[str, Any]] = {}
    for vuln in vulns:
        pkg = vuln.get("package")
        if not pkg:
            continue
        entry = pkg_map.setdefault(pkg, {
            "package": pkg,
            "current_version": vuln.get("version") or "unknown",
            "upgrade_to": vuln.get("fix_version"),
            "all_cves": [],
        })
        cve_ids = vuln.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        for cve in cve_ids:
            if cve and cve not in entry["all_cves"]:
                entry["all_cves"].append(cve)
        # Keep the highest fix_version seen (take the first non-null)
        if not entry["upgrade_to"] and vuln.get("fix_version"):
            entry["upgrade_to"] = vuln.get("fix_version")

    # Build plan entries — only packages that have reachable CVEs
    plan: List[Dict[str, Any]] = []
    for pkg, entry in pkg_map.items():
        reachable_cves = [
            cve for cve in entry["all_cves"]
            if cve_reach.get(cve, {}).get("reachability_class") in _REACHABLE_CLASSES
        ]
        unreachable_cves = [
            cve for cve in entry["all_cves"] if cve not in reachable_cves
        ]
        if not reachable_cves:
            continue

        # Aggregate risk score as max across reachable CVEs
        risk_score = max(
            (float(cve_reach[c].get("risk_score") or 0) for c in reachable_cves if c in cve_reach),
            default=0.0,
        )
        reachability_class = next(
            (cve_reach[c].get("reachability_class") for c in reachable_cves if c in cve_reach),
            None,
        )

        plan.append({
            "package": pkg,
            "current_version": entry["current_version"],
            "upgrade_to": entry["upgrade_to"],
            "reachable_cves_removed": reachable_cves,
            "unreachable_cves_also_fixed": unreachable_cves,
            "reachability_class": reachability_class,
            "risk_score": risk_score,
        })

    plan.sort(key=lambda x: (len(x["reachable_cves_removed"]), x["risk_score"]), reverse=True)
    return plan
