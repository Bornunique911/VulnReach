from typing import Any, Dict, List, Optional

from correlation.engine import apply_policy, confidence_from_verdict, priority_from_score, risk_score


class CorrelationService:
    def correlate(
        self,
        vulnerabilities: List[Dict[str, Any]],
        static_reachability: Dict[str, Dict[str, Any]],
        dynamic_reachability: Dict[str, Dict[str, Any]],
        exposure: str,
        policy_rules: Optional[List[Dict[str, Any]]] = None,
        semgrep_findings: Optional[List[Dict[str, Any]]] = None,
        # Legacy compatibility: single merged map still accepted
        reachability: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Correlate vulnerability + reachability data into prioritised findings.

        Two separate finding lists are produced:
          - dynamic: verdict derived from taint-flow + runtime coverage (only
            packages confirmed to be used at runtime are included)
          - static: verdict derived from import / call-chain evidence only
            (all packages with ANY static evidence are included)

        The combined ``correlation`` list contains both, each tagged with a
        ``finding_type`` field ("dynamic" | "static" | "semgrep").
        """
        # Back-compat shim: if caller passes the old single ``reachability``
        # map, treat it as static only.
        if reachability is not None and not static_reachability and not dynamic_reachability:
            static_reachability = reachability

        correlation_results: List[Dict[str, Any]] = []
        rules = policy_rules or []
        pipeline_status = "PASS"

        for vuln in vulnerabilities:
            severity = vuln.get("severity")
            cves = vuln.get("cve_id") or []
            if not isinstance(cves, list):
                cves = [cves]
            if not cves:
                cves = [None]

            for cve in cves:
                # ----------------------------------------------------------------
                # Dynamic finding — only emit if dynamic evidence exists for this
                # package (taint flow confirmed AND/OR runtime coverage hit).
                # ----------------------------------------------------------------
                dyn = dynamic_reachability.get(cve) if cve else None
                if dyn:
                    dyn_verdict = dyn.get("verdict", "NOT_OBSERVED")
                    dyn_confidence = dyn.get("confidence") or confidence_from_verdict(dyn_verdict)
                    dyn_score = risk_score(severity, dyn_verdict, exposure)
                    dyn_priority = priority_from_score(dyn_score)
                    correlation_results.append(
                        {
                            "cve_id": cve,
                            "verdict": dyn_verdict,
                            "risk_score": dyn_score,
                            "priority": dyn_priority,
                            "confidence": dyn_confidence,
                            "finding_type": "dynamic",
                            "evidence": {
                                "has_taint_flow": dyn.get("has_taint_flow", False),
                                "has_coverage_hit": dyn.get("has_coverage_hit", False),
                                "files": dyn.get("files", []),
                            },
                        }
                    )
                    if apply_policy(severity, dyn_verdict, rules) == "BLOCK":
                        pipeline_status = "BLOCK"

                # ----------------------------------------------------------------
                # Static finding — emit for every CVE that has any static
                # evidence (import detected, call-chain, return, attribute call).
                # Packages with NO static evidence at all are skipped.
                # ----------------------------------------------------------------
                sta = static_reachability.get(cve) if cve else None
                sta_verdict = sta.get("verdict", "NOT_OBSERVED") if sta else "NOT_OBSERVED"

                # Only include static findings where we have at least an import
                has_static_evidence = sta and (
                    sta.get("import_detected")
                    or sta.get("call_chain_exists")
                    or sta.get("sink_reachable")
                )
                if has_static_evidence:
                    sta_confidence = sta.get("confidence") or confidence_from_verdict(sta_verdict)
                    sta_score = risk_score(severity, sta_verdict, exposure)
                    sta_priority = priority_from_score(sta_score)
                    correlation_results.append(
                        {
                            "cve_id": cve,
                            "verdict": sta_verdict,
                            "risk_score": sta_score,
                            "priority": sta_priority,
                            "confidence": sta_confidence,
                            "finding_type": "static",
                            "evidence": {
                                "import_detected": sta.get("import_detected", False),
                                "call_chain_exists": sta.get("call_chain_exists", False),
                                "sink_reachable": sta.get("sink_reachable", False),
                                "files": sta.get("files", []),
                                "function": sta.get("function"),
                            },
                        }
                    )
                    if apply_policy(severity, sta_verdict, rules) == "BLOCK":
                        pipeline_status = "BLOCK"

        # ----------------------------------------------------------------
        # Semgrep static findings (unchanged logic, tagged as "semgrep")
        # ----------------------------------------------------------------
        for finding in semgrep_findings or []:
            severity = finding.get("severity")
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
                    "finding_type": "semgrep",
                    "source": "semgrep",
                }
            )
            if apply_policy(severity, verdict, rules) == "BLOCK":
                pipeline_status = "BLOCK"

        return {"correlation": correlation_results, "pipeline_status": pipeline_status}
