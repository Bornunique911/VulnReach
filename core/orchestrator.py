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
        #
        # A CVE earns dynamic reachability ONLY through the FULL evidence chain:
        #   1. SCA vulnerable (already filtered — only vulns from Trivy)
        #   2. Has taint flow (from tainter agent)
        #   3. Has route exposure (from route_extractor)
        #   4. Has static reachability (from static_reach_map above)
        #   5. Coverage confirms execution (from dynamic_reachability/pytest_coverage)
        #
        # Without all five, the package is NOT dynamically reachable.
        # The only exception: direct library code in coverage (sink_reachable=True)
        # with taint evidence — this is strong enough to skip the route gate.
        # ------------------------------------------------------------------

        # Step 1 — collect CVEs that have a taint-flow trace (from tainter)
        taint_cves: Set[str] = set()
        for result in results:
            if result.tool_name == "tainter":
                for item in result.findings:
                    cve = item.get("cve_id")
                    if cve and (item.get("call_chain_exists") or item.get("sink_reachable")):
                        taint_cves.add(cve)

        # Step 1b — check if routes exist at all (route_extractor ran and found routes)
        # Note: taint evidence already proves route→package flow, so we don't
        # need to match package names against route handler names. We only check
        # whether any routes were found (i.e. the app has HTTP endpoints).
        has_routes = False
        for result in results:
            if result.tool_name == "route_extractor" and result.findings:
                has_routes = True
                break

        # Step 2 — collect CVEs confirmed by runtime coverage
        coverage_evidence: Dict[str, Dict[str, Any]] = {}
        for result in results:
            if result.tool_name in ("dynamic_reachability", "pytest_coverage"):
                for item in result.findings:
                    cve = item.get("cve_id")
                    if not cve:
                        continue
                    existing = coverage_evidence.get(cve)
                    if existing:
                        existing["sink_reachable"] = existing.get("sink_reachable", False) or item.get("sink_reachable", False)
                        existing["confidence"] = max(existing.get("confidence", 0), item.get("confidence", 0))
                        existing_files = set(existing.get("files", []))
                        existing_files.update(item.get("files", []))
                        existing["files"] = list(existing_files)[:10]
                        existing_fn = existing.get("function") or ""
                        new_fn = item.get("function") or ""
                        if new_fn and new_fn not in existing_fn:
                            existing["function"] = f"{existing_fn}, {new_fn}".strip(", ")
                        existing["import_time_hit"] = existing.get("import_time_hit", False) or item.get("import_time_hit", False)
                    else:
                        coverage_evidence[cve] = dict(item)

        # Step 3 — gate dynamic findings on the full evidence chain
        #
        # Full chain: SCA (already filtered) → taint → routes → static → coverage
        #
        # Taint evidence already proves route→package flow (the tainter traces
        # user input through HTTP routes to the package). So has_taint implies
        # route exposure — no need to separately match package names against
        # route handler names.
        #
        # Import-time-only (Strategy 2) is weak evidence — the app code that
        # imports the library ran, but the library's own code isn't in coverage.
        # Promoted to CONFIRMED only when the full chain is present.
        dynamic_reach_map: Dict[str, Dict[str, Any]] = {}

        for cve, dyn_item in coverage_evidence.items():
            has_taint = cve in taint_cves
            has_coverage = dyn_item.get("sink_reachable", False)
            has_static = cve in static_reach_map
            import_time_only = dyn_item.get("import_time_hit", False) and not has_coverage

            if import_time_only:
                # Strategy 2 (import-in-executed-file): weak signal.
                # Only promote if FULL evidence chain is satisfied:
                #   taint (implies route exposure) + static reachability
                if not (has_taint and has_static):
                    continue
                # Full chain: SCA + taint + routes (via taint) + static + coverage (import-time)
                verdict = "CONFIRMED"
                confidence = 0.95
            elif has_coverage and has_taint:
                # Direct library coverage + taint → CONFIRMED
                verdict = "CONFIRMED"
                confidence = 0.95
            elif has_coverage and has_static:
                # Direct coverage + static (no taint) → LIKELY
                verdict = "LIKELY"
                confidence = 0.75
            elif has_coverage:
                # Coverage hit but no taint or static → weak
                verdict = "POSSIBLE"
                confidence = 0.55
            else:
                # No coverage evidence at all — skip
                continue

            dynamic_reach_map[cve] = {
                **dyn_item,
                "verdict": verdict,
                "evidence_type": "dynamic",
                "has_taint_flow": has_taint,
                "has_coverage_hit": True,  # all paths above have some coverage evidence
                "has_static_evidence": has_static,
                "confidence": confidence,
            }

        # ------------------------------------------------------------------
        # Build DAST evidence map
        # Source: intelligent_dast agent — Claude-steered SQLi confirmation
        # These are already verdict=CONFIRMED with confidence=1.0
        # ------------------------------------------------------------------
        dast_findings: list[dict[str, Any]] = []
        for result in results:
            if result.tool_name == "intelligent_dast":
                dast_findings.extend(result.findings)
                # Also store the full DAST metadata (iterations, payloads, etc.)
                if result.metadata.get("findings"):
                    self.storage.store_raw_output(
                        scan_id, "intelligent_dast_detail",
                        result.metadata["findings"],
                    )

        semgrep_result = next((res for res in results if res.tool_name == "semgrep"), AgentResult(tool_name="semgrep"))

        correlation_output = self.correlation_service.correlate(
            vulnerabilities=context.vulnerabilities,
            static_reachability=static_reach_map,
            dynamic_reachability=dynamic_reach_map,
            exposure=config.risk.exposure,
            policy_rules=[rule.model_dump() for rule in config.policy.block_if],
            semgrep_findings=semgrep_result.findings,
            dast_findings=dast_findings,
        )
        self.storage.store_correlation(scan_id, correlation_output["correlation"])

        # Store structured reachability classification for API consumers
        summary = correlation_output.get("summary", {})
        logger.info(
            "correlation_summary",
            extra={
                "scan_id": scan_id,
                "dynamically_reachable": summary.get("dynamically_reachable", 0),
                "statically_reachable": summary.get("statically_reachable", 0),
                "not_reachable": summary.get("not_reachable", 0),
                "uncertain": summary.get("uncertain", 0),
            },
        )

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