"""Intelligent DAST Agent — Claude-steered SQL injection confirmation (v1).

Flow:
  Step 1 — Pre-flight: verify config, API key, and taint paths exist
  Step 2 — Assemble DastScanContext from pipeline context (Phase 1)
  Step 3 — Run the steering loop (Phase 2 + 3): Claude picks payloads,
            httpx executes them, confirmation signals are checked
  Step 4 — Return structured DastFinding results (Phase 4)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from dotenv import load_dotenv

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext
from agents.dast.context_assembler import assemble
from agents.dast.steering_loop import SteeringLoop

logger = logging.getLogger(__name__)

# Fallback if config does not specify a base URL
_FALLBACK_PORT = 3000


class IntelligentDastAgent(BaseAgent):
    tool_name = "intelligent_dast"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:
        # ------------------------------------------------------------------
        # Step 1 — Pre-flight
        # ------------------------------------------------------------------
        if not context.config:
            return self._skipped("no_config")

        idast_cfg = context.config.scan.intelligent_dast
        if not idast_cfg.enabled:
            return self._skipped("disabled_in_config")

        # Resolve API key — only required for the Anthropic provider.
        # Reload dotenv files so env vars set after server startup are picked up.
        load_dotenv(dotenv_path=".env.local", override=False)
        load_dotenv(override=False)  # also checks .env
        api_key = os.environ.get(idast_cfg.api_key_env, "")
        if idast_cfg.provider == "anthropic" and not api_key:
            return self._skipped(f"missing_api_key: {idast_cfg.api_key_env} not set")

        # Need at least some taint flows to probe
        if not context.taint_flows:
            return AgentResult(
                tool_name=self.tool_name,
                status="skipped",
                findings=[],
                metadata={
                    "status": "skipped",
                    "reason": "no_taint_flows",
                    "hint": "Run the tainter agent before intelligent_dast",
                },
            )

        # Determine base URL: config override → runtime container port → fallback
        base_url = idast_cfg.base_url or ""
        if not base_url:
            port = (
                context.config.scan.runtime.container_port
                if context.config.scan.runtime
                else _FALLBACK_PORT
            )
            base_url = f"http://localhost:{port}"

        logger.info(
            f"[intelligent_dast] Starting: base_url={base_url} "
            f"taint_flows={len(context.taint_flows)} max_iter={idast_cfg.max_iter}"
        )

        # ------------------------------------------------------------------
        # Step 2 — Assemble DastScanContext (Phase 1)
        # ------------------------------------------------------------------
        try:
            dast_context = assemble(context, base_url)
        except Exception as exc:
            logger.error(f"[intelligent_dast] Context assembly failed: {exc}")
            return AgentResult(
                tool_name=self.tool_name,
                status="error",
                findings=[],
                metadata={"error": "context_assembly_failed", "details": str(exc)},
            )

        if not dast_context.taint_paths:
            return AgentResult(
                tool_name=self.tool_name,
                status="skipped",
                findings=[],
                metadata={
                    "status": "skipped",
                    "reason": "no_sql_taint_paths",
                    "hint": "No SQL-related taint flows found — v1 supports SQLi only",
                    "flows_in_context": len(context.taint_flows),
                },
            )

        logger.info(
            f"[intelligent_dast] Assembled {len(dast_context.taint_paths)} SQL taint paths"
        )

        # ------------------------------------------------------------------
        # Step 3 — Steering loop (Phase 2 + 3)
        # ------------------------------------------------------------------
        try:
            loop = SteeringLoop(
                provider=idast_cfg.provider,
                base_url=base_url,
                model=idast_cfg.model,
                api_key=api_key,
                ollama_base_url=idast_cfg.ollama_base_url,
                max_iter=idast_cfg.max_iter,
                auth_credentials=idast_cfg.auth_credentials,
            )
            dast_findings = await loop.run(dast_context)
        except RuntimeError as exc:
            # Missing optional dependency (anthropic / httpx)
            return AgentResult(
                tool_name=self.tool_name,
                status="error",
                findings=[],
                metadata={"error": "missing_dependency", "details": str(exc)},
            )
        except Exception as exc:
            logger.exception("[intelligent_dast] Steering loop failed")
            return AgentResult(
                tool_name=self.tool_name,
                status="error",
                findings=[],
                metadata={"error": "steering_loop_failed", "details": str(exc)},
            )

        # ------------------------------------------------------------------
        # Step 4 — Format output (Phase 4)
        # ------------------------------------------------------------------
        confirmed = [f for f in dast_findings if f.status == "confirmed"]

        # Convert DastFindings to reachability_evidence schema so store_reachability works.
        # Only persist confirmed findings — exhausted/skipped/give_up add noise.
        findings_for_storage = []
        for f in confirmed:
            coverage_files = f.evidence.get("coverage_delta", [])
            findings_for_storage.append({
                "cve_id": f.cve_reference,
                "package": "Django",           # SQLi is in the app framework layer
                "import_detected": True,
                "call_chain_exists": True,
                "sink_reachable": True,
                "verdict": "CONFIRMED",
                "file": coverage_files[0] if coverage_files else None,
                "function": f.endpoint,
                "sink": f"{f.endpoint}?{f.parameter}",
                "confidence": 1.0,
                "evidence_type": "dast",
                "files": coverage_files,
                # Extra DAST-specific fields stored in the findings list
                "dast_payload": f.confirmed_payload,
                "dast_method": f.confirmation_method,
                "dast_reasoning": f.reasoning,
                "dast_vuln_class": f.vuln_class,
                "dast_severity": f.severity,
            })

        logger.info(
            f"[intelligent_dast] Complete: "
            f"{len(confirmed)} confirmed / {len(dast_findings)} total paths probed"
        )

        return AgentResult(
            tool_name=self.tool_name,
            status="ok",
            findings=findings_for_storage,
            metadata={
                "status": "ok",
                "paths_probed": len(dast_findings),
                "confirmed_count": len(confirmed),
                "exhausted_count": sum(1 for f in dast_findings if f.status == "exhausted"),
                "skipped_count": sum(1 for f in dast_findings if f.status == "skipped"),
                "base_url": base_url,
                "model": idast_cfg.model,
                "findings": [f.model_dump() for f in dast_findings],
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _skipped(self, reason: str) -> AgentResult:
        logger.info(f"[intelligent_dast] Skipped — {reason}")
        return AgentResult(
            tool_name=self.tool_name,
            status="skipped",
            findings=[],
            metadata={"status": "skipped", "reason": reason},
        )
