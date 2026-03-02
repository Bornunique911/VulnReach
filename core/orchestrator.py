import logging
from typing import Any, Dict, Set

from core.models import AgentResult, ScanContext
from agents.runner import AgentRunner
from correlation.engine import confidence_from_verdict, dynamic_reachability_verdict, reachability_verdict
from correlation.service import CorrelationService
from storage.repository import StorageRepository

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        storage: StorageRepository,
        runner: AgentRunner,
        correlation_service: CorrelationService,
    ) -> None:
        self.storage = storage
        self.runner = runner
        self.correlation_service = correlation_service

    async def execute_scan(
        self,
        scan_id: str,
        repo_path: str,
        config_path: str,
        config: Any,
        repo_url: str | None,
    ) -> None:
        context = ScanContext(
            repo_path=repo_path,
            repo_url=repo_url,
            config_path=config_path,
            config=config,
            scan_id=scan_id,
        )

        logger.info("scan_start", extra={"scan_id": scan_id, "repo_url": repo_url, "repo_path": repo_path})
        results = await self.runner.run_all(context)

        # Identify tools that failed — warn and continue with partial data
        failed_tools = [r.tool_name for r in results if r.metadata.get("error")]
        if failed_tools:
            logger.warning(
                "scan_partial_tools_skipped",
                extra={"scan_id": scan_id, "failed_tools": failed_tools},
            )

        # ------------------------------------------------------------------
        # Build STATIC reach map
        # Source: tainter + python_reachability (import / call-chain evidence)
        # Verdict logic: import_detected / call_chain_exists only — no dynamic
        # ------------------------------------------------------------------
        static_reach_map: Dict[str, Dict[str, Any]] = {}

        for result in results:
            if result.tool_name in {"tainter", "python_reachability"}:
                for item in result.findings:
                    cve = item.get("cve_id")
                    if not cve:
                        continue
                    verdict = reachability_verdict(
                        import_detected=item.get("import_detected", False),
                        call_chain_exists=item.get("call_chain_exists", False),
                        sink_reachable=False,  # static path never sets sink_reachable
                    )
                    static_reach_map[cve] = {
                        **item,
                        "verdict": verdict,
                        "evidence_type": "static",
                        "confidence": item.get("confidence") or confidence_from_verdict(verdict),
                    }

        # ------------------------------------------------------------------
        # Build DYNAMIC reach map
        # Source: tainter taint flows (findings.json) ∩ dynamic coverage hits
        #
        # A CVE earns a dynamic finding ONLY when the vulnerable package is:
        #   (a) present in tainter taint flows  → has_taint_flow
        #   (b) hit in runtime coverage         → has_coverage_hit
        #
        # Both pieces of evidence are needed for CONFIRMED; either alone
        # produces LIKELY/POSSIBLE (see dynamic_reachability_verdict).
        # ------------------------------------------------------------------

        # Step 1 — collect CVEs that have a taint-flow trace (from tainter)
        taint_cves: Set[str] = set()
        for result in results:
            if result.tool_name == "tainter":
                for item in result.findings:
                    cve = item.get("cve_id")
                    # Tainter findings that have any flow evidence
                    if cve and (item.get("call_chain_exists") or item.get("sink_reachable")):
                        taint_cves.add(cve)

        # Step 2 — collect CVEs confirmed by runtime coverage (dynamic agent)
        coverage_evidence: Dict[str, Dict[str, Any]] = {}
        for result in results:
            if result.tool_name == "dynamic_reachability":
                for item in result.findings:
                    cve = item.get("cve_id")
                    if cve:
                        coverage_evidence[cve] = item

        # Step 3 — combine: emit a dynamic entry for each CVE that is present
        # in EITHER taint flows or coverage (union), but tag which are present.
        # Only packages with runtime usage (coverage_evidence) are included in
        # the dynamic map — taint-only CVEs without coverage are not dynamic.
        dynamic_reach_map: Dict[str, Dict[str, Any]] = {}

        # We only populate the dynamic map for CVEs that appear in coverage_evidence
        # (runtime-used packages). Taint evidence enriches the verdict.
        for cve, dyn_item in coverage_evidence.items():
            has_taint = cve in taint_cves
            has_coverage = dyn_item.get("sink_reachable", False)

            verdict = dynamic_reachability_verdict(
                has_taint_flow=has_taint,
                has_coverage_hit=has_coverage,
            )
            confidence = (
                0.95 if (has_taint and has_coverage)
                else 0.75 if has_coverage
                else 0.55
            )
            dynamic_reach_map[cve] = {
                **dyn_item,
                "verdict": verdict,
                "evidence_type": "dynamic",
                "has_taint_flow": has_taint,
                "has_coverage_hit": has_coverage,
                "confidence": confidence,
            }

        semgrep_result = next((res for res in results if res.tool_name == "semgrep"), AgentResult(tool_name="semgrep"))
        self.storage.store_semgrep_findings(scan_id, semgrep_result.findings)

        correlation_output = self.correlation_service.correlate(
            vulnerabilities=context.vulnerabilities,
            static_reachability=static_reach_map,
            dynamic_reachability=dynamic_reach_map,
            exposure=config.risk.exposure,
            policy_rules=[rule.model_dump() for rule in config.policy.block_if],
            semgrep_findings=semgrep_result.findings,
        )
        self.storage.store_correlation(scan_id, correlation_output["correlation"])

        if correlation_output["pipeline_status"] == "BLOCK":
            status = "blocked"
        elif failed_tools:
            status = "partial"
        else:
            status = "completed"
        self.storage.update_scan_status(scan_id, status)
        logger.info(
            "scan_complete",
            extra={
                "scan_id": scan_id,
                "status": status,
                "pipeline_status": correlation_output["pipeline_status"],
                "failed_tools": failed_tools,
            },
        )