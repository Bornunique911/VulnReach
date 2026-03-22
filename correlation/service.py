from typing import Any, Dict, List, Optional

from correlation.engine import (
    apply_policy,
    classify_reachability,
    confidence_from_verdict,
    priority_from_score,
    risk_score,
)


class CorrelationService:
    def correlate(
        self,
        vulnerabilities: List[Dict[str, Any]],
        static_reachability: Dict[str, Dict[str, Any]],
        dynamic_reachability: Dict[str, Dict[str, Any]],
        exposure: str,
        policy_rules: Optional[List[Dict[str, Any]]] = None,
        semgrep_findings: Optional[List[Dict[str, Any]]] = None,
        dast_findings: Optional[List[Dict[str, Any]]] = None,
        # Legacy compatibility: single merged map still accepted
        reachability: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Correlate vulnerability + reachability data into prioritised findings.

        Classification tiers (coverage.json = ground truth):
          1. DYNAMICALLY_REACHABLE  — coverage hit + call chain / function
          2. STATICALLY_REACHABLE   — import / file / function, no coverage
             Sub-types: FUNCTION | FILE | IMPORT | TRANSITIVE
          3. NOT_REACHABLE          — no evidence at all
          4. UNCERTAIN              — taint-only, no call chain, no coverage

        The ``correlation`` list contains all findings tagged with
        ``reachability_class`` and ``finding_type`` for backward compatibility
        with the dashboard. The four categorised lists (``dynamically_reachable``,
        ``statically_reachable``, ``not_reachable``, ``uncertain``) provide the
        structured security-focused view.
        """
        # Back-compat shim: if caller passes the old single ``reachability``
        # map, treat it as static only.
        if reachability is not None and not static_reachability and not dynamic_reachability:
            static_reachability = reachability

        correlation_results: List[Dict[str, Any]] = []
        dynamically_reachable: List[Dict[str, Any]] = []
        statically_reachable: List[Dict[str, Any]] = []
        not_reachable: List[Dict[str, Any]] = []
        uncertain: List[Dict[str, Any]] = []

        rules = policy_rules or []
        pipeline_status = "PASS"

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "MEDIUM")
            package = vuln.get("package", "")
            cves = vuln.get("cve_id") or []
            if not isinstance(cves, list):
                cves = [cves]
            if not cves:
                cves = [None]

            for cve in cves:
                dyn = dynamic_reachability.get(cve) if cve else None
                sta = static_reachability.get(cve) if cve else None

                # ── Assemble evidence signals ─────────────────────────────────
                # Dynamic map: always has has_coverage_hit=True when present
                coverage_hit: bool = bool(dyn and dyn.get("has_coverage_hit", False))
                has_taint_flow: bool = bool(dyn and dyn.get("has_taint_flow", False))

                # Prefer dynamic-sourced function/file (runtime-confirmed);
                # fall back to static evidence.
                function: str | None = (dyn or {}).get("function") or (sta or {}).get("function")
                file: str | None = (dyn or {}).get("file") or (sta or {}).get("file")
                call_chain_exists: bool = bool(
                    (dyn and dyn.get("call_chain_exists"))
                    or (sta and sta.get("call_chain_exists"))
                )
                import_detected: bool = bool(
                    (dyn and dyn.get("import_detected"))
                    or (sta and sta.get("import_detected"))
                )
                evidence_type: str = (
                    (dyn or {}).get("evidence_type")
                    or (sta or {}).get("evidence_type")
                    or "static"
                )
                files: list = list(
                    set((dyn or {}).get("files", []) + (sta or {}).get("files", []))
                )[:10]

                # ── Classify ─────────────────────────────────────────────────
                reachability_class, static_subtype = classify_reachability(
                    coverage_hit=coverage_hit,
                    call_chain_exists=call_chain_exists,
                    import_detected=import_detected,
                    function=function,
                    file=file,
                    evidence_type=evidence_type,
                    package=package,
                )

                # ── Map to verdict + confidence ───────────────────────────────
                if reachability_class == "DYNAMICALLY_REACHABLE":
                    verdict = "CONFIRMED" if has_taint_flow else "LIKELY"
                    confidence = dyn.get("confidence", 0.95 if has_taint_flow else 0.75)
                    finding_type = "dynamic"
                elif reachability_class == "STATICALLY_REACHABLE":
                    if call_chain_exists and import_detected:
                        verdict = "LIKELY"
                    elif import_detected or call_chain_exists:
                        verdict = "POSSIBLE"
                    else:
                        verdict = "POSSIBLE"
                    confidence = (sta or {}).get("confidence") or confidence_from_verdict(verdict)
                    finding_type = "static"
                elif reachability_class == "UNCERTAIN":
                    verdict = "POSSIBLE"
                    confidence = 0.3
                    finding_type = "uncertain"
                else:  # NOT_REACHABLE
                    verdict = "NOT_OBSERVED"
                    confidence = 0.1
                    finding_type = "not_reachable"

                score = risk_score(severity, verdict, exposure)
                priority = priority_from_score(score)

                evidence_blob: Dict[str, Any] = {
                    "coverage_hit": coverage_hit,
                    "has_taint_flow": has_taint_flow,
                    "call_chain_exists": call_chain_exists,
                    "import_detected": import_detected,
                    "function": function,
                    "file": file,
                    "files": files,
                    "evidence_type": evidence_type,
                    # Dashboard compat fields
                    "has_coverage_hit": coverage_hit,
                    "has_static_evidence": bool(sta),
                    # Classification — stored inside evidence so they survive DB round-trip
                    "reachability_class": reachability_class,
                }
                if static_subtype:
                    evidence_blob["static_subtype"] = static_subtype

                finding: Dict[str, Any] = {
                    "cve_id": cve,
                    "package": package,
                    "severity": severity,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": confidence,
                    "reachability_class": reachability_class,
                    "finding_type": finding_type,
                    "evidence": evidence_blob,
                }

                if static_subtype:
                    finding["static_subtype"] = static_subtype

                correlation_results.append(finding)

                # ── Populate categorised lists ────────────────────────────────
                summary = {
                    "cve_id": cve,
                    "package": package,
                    "severity": severity,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": confidence,
                }

                if reachability_class == "DYNAMICALLY_REACHABLE":
                    dynamically_reachable.append({
                        **summary,
                        "functions_executed": [f for f in [function] if f],
                        "files": files,
                        "reasoning": _dynamic_reasoning(has_taint_flow, call_chain_exists, function),
                    })
                elif reachability_class == "STATICALLY_REACHABLE":
                    statically_reachable.append({
                        **summary,
                        "classification": static_subtype,
                        "reasoning": _static_reasoning(static_subtype, import_detected, call_chain_exists, function, file),
                    })
                elif reachability_class == "UNCERTAIN":
                    uncertain.append({
                        **summary,
                        "reason": "taint-flow evidence only — no call chain and no runtime coverage confirm execution",
                    })
                else:
                    not_reachable.append({"cve_id": cve, "package": package, "severity": severity})

                if apply_policy(severity, verdict, rules) == "BLOCK":
                    pipeline_status = "BLOCK"

        # ── Semgrep static findings ───────────────────────────────────────────
        for finding in semgrep_findings or []:
            severity = finding.get("severity", "MEDIUM")
            check_id = finding.get("check_id")
            verdict = "POSSIBLE"
            score = risk_score(severity, verdict, exposure)
            priority = priority_from_score(score)
            correlation_results.append(
                {
                    "check_id": check_id,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "reachability_class": "STATICALLY_REACHABLE",
                    "finding_type": "semgrep",
                    "source": "semgrep",
                }
            )
            if apply_policy(severity, verdict, rules) == "BLOCK":
                pipeline_status = "BLOCK"

        # ── DAST findings — Claude-steered payload confirmation ───────────────
        for finding in dast_findings or []:
            cve_id = finding.get("cve_id")
            sev = finding.get("dast_severity", "HIGH").upper()
            verdict = finding.get("verdict", "CONFIRMED")
            score = risk_score(sev, verdict, exposure)
            priority = priority_from_score(score)
            correlation_results.append(
                {
                    "cve_id": cve_id,
                    "verdict": verdict,
                    "risk_score": score,
                    "priority": priority,
                    "confidence": finding.get("confidence", 1.0),
                    "reachability_class": "DYNAMICALLY_REACHABLE",
                    "finding_type": "dast",
                    "evidence": {
                        "vuln_class": finding.get("dast_vuln_class", "sql_injection"),
                        "severity": sev,
                        "endpoint": finding.get("function", ""),
                        "parameter": finding.get("sink", ""),
                        "payload": finding.get("dast_payload"),
                        "confirmation_method": finding.get("dast_method"),
                        "reasoning": finding.get("dast_reasoning"),
                        "files": finding.get("files", []),
                    },
                }
            )
            if apply_policy(sev, verdict, rules) == "BLOCK":
                pipeline_status = "BLOCK"

        return {
            "correlation": correlation_results,
            "dynamically_reachable": dynamically_reachable,
            "statically_reachable": statically_reachable,
            "not_reachable": not_reachable,
            "uncertain": uncertain,
            "pipeline_status": pipeline_status,
            "summary": {
                "total": len(correlation_results),
                "dynamically_reachable": len(dynamically_reachable),
                "statically_reachable": len(statically_reachable),
                "not_reachable": len(not_reachable),
                "uncertain": len(uncertain),
            },
        }


def _dynamic_reasoning(has_taint_flow: bool, call_chain_exists: bool, function: str | None) -> str:
    parts = ["Runtime coverage confirmed execution"]
    if has_taint_flow:
        parts.append("taint flow traces user-controlled input to this package")
    if call_chain_exists:
        parts.append("call chain exists from application code")
    if function:
        parts.append(f"function '{function}' was executed")
    return "; ".join(parts) + "."


def _static_reasoning(
    subtype: str | None,
    import_detected: bool,
    call_chain_exists: bool,
    function: str | None,
    file: str | None,
) -> str:
    if subtype == "FUNCTION":
        return f"Function '{function}' is present in source but was not executed at runtime."
    if subtype == "FILE":
        return f"File '{file}' references this package but was not observed in runtime coverage."
    if subtype == "TRANSITIVE":
        return "Package is loaded via framework bootstrap (e.g. routing/middleware); not directly called by application code."
    if subtype == "IMPORT":
        return "Package import was detected but no function-level usage or runtime execution was observed."
    return "Static evidence present; no runtime execution confirmed."
