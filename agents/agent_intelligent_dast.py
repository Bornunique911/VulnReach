"""Intelligent DAST Agent — delegates to `intelligent_dast.runner.run_dast()`.

Flow:
  Step 1 — Pre-flight: check config, taint flows, base URL
  Step 2 — Write taint flows to a temp file (run_dast reads from disk)
  Step 3 — Find openapi.json/yaml in the repo path (if present)
  Step 4 — Call run_dast() in a thread executor (it is synchronous)
  Step 5 — Convert FlowResult list to reachability-evidence storage format
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext

logger = logging.getLogger(__name__)

_FALLBACK_PORT = 3000
_OPENAPI_NAMES = ("openapi.json", "openapi.yaml", "openapi.yml")


class IntelligentDastAgent(BaseAgent):
    tool_name = "intelligent_dast"

    async def run(self, context: ScanContext) -> AgentResult:
        # ------------------------------------------------------------------
        # Step 1 — Pre-flight
        # ------------------------------------------------------------------
        if not context.config:
            return self._skipped("no_config")

        idast_cfg = context.config.scan.intelligent_dast
        if not idast_cfg.enabled:
            return self._skipped("disabled_in_config")

        if not context.taint_flows:
            return self._skipped("no_taint_flows")

        # Resolve API key — only required for the Anthropic provider
        load_dotenv(dotenv_path=".env.local", override=False)
        load_dotenv(override=False)
        api_key = os.environ.get(idast_cfg.api_key_env, "")
        if idast_cfg.provider == "anthropic" and not api_key:
            return self._skipped(f"missing_api_key:{idast_cfg.api_key_env}")

        # Base URL: config override → runtime container_port → fallback
        base_url = idast_cfg.base_url or ""
        if not base_url:
            port = context.config.scan.runtime.container_port if context.config.scan.runtime else _FALLBACK_PORT
            base_url = f"http://localhost:{port}"

        # ------------------------------------------------------------------
        # Step 2 — Write taint flows to a temp file
        # ------------------------------------------------------------------
        taint_tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            json.dump({"flows": context.taint_flows}, taint_tmp, indent=2)
            taint_tmp.flush()
            taint_file = taint_tmp.name
        finally:
            taint_tmp.close()

        # ------------------------------------------------------------------
        # Step 3 — Find openapi spec in the repo
        # ------------------------------------------------------------------
        openapi_spec: Optional[str] = None
        if context.repo_path:
            repo = Path(context.repo_path)
            for name in _OPENAPI_NAMES:
                candidate = repo / name
                if candidate.exists():
                    openapi_spec = str(candidate)
                    logger.info(f"[intelligent_dast] OpenAPI spec: {openapi_spec}")
                    break

        logger.info(
            f"[intelligent_dast] Starting: url={base_url} "
            f"flows={len(context.taint_flows)} provider={idast_cfg.provider} "
            f"model={idast_cfg.model} openapi={openapi_spec}"
        )

        # ------------------------------------------------------------------
        # Step 4 — Run synchronous run_dast() in executor
        # ------------------------------------------------------------------
        try:
            from intelligent_dast.runner import run_dast

            fn = partial(
                run_dast,
                taint_file=taint_file,
                base_url=base_url,
                openapi_spec=openapi_spec,
                llm_provider=idast_cfg.provider,
                llm_model=idast_cfg.model or None,
                max_iterations=idast_cfg.max_iter,
                ollama_base_url=idast_cfg.ollama_base_url or "http://localhost:11434",
            )
            loop = asyncio.get_event_loop()
            flow_results = await loop.run_in_executor(None, fn)
        except Exception as exc:
            logger.exception("[intelligent_dast] run_dast failed")
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "run_dast_failed", "details": str(exc)},
            )
        finally:
            # Clean up temp file
            try:
                Path(taint_file).unlink(missing_ok=True)
            except Exception:
                pass

        # ------------------------------------------------------------------
        # Step 5 — Convert FlowResult list to storage format
        # ------------------------------------------------------------------
        confirmed = [fr for fr in flow_results if fr.finding]
        skipped = [fr for fr in flow_results if fr.skipped]

        findings_for_storage: List[Dict[str, Any]] = []
        for fr in confirmed:
            f = fr.finding
            findings_for_storage.append({
                "cve_id": None,
                "package": None,
                "import_detected": True,
                "call_chain_exists": True,
                "sink_reachable": True,
                "verdict": "CONFIRMED",
                "confidence": 1.0,
                "evidence_type": "dast",
                "finding_type": "dast",
                "function": fr.endpoint,
                "files": [],
                # DAST-specific details
                "dast_flow_id": fr.flow_id,
                "dast_vuln_class": fr.vulnerability_class,
                "dast_payload": f.payload,
                "dast_evidence": f.evidence,
                "dast_confirmed_at_iteration": f.confirmed_at_iteration,
                "dast_endpoint": fr.endpoint,
            })

        logger.info(
            f"[intelligent_dast] Complete: "
            f"{len(confirmed)} confirmed / {len(flow_results)} flows tested / "
            f"{len(skipped)} skipped"
        )

        return AgentResult(
            tool_name=self.tool_name,
            findings=findings_for_storage,
            metadata={
                "status": "ok",
                "flows_tested": len(flow_results),
                "confirmed_count": len(confirmed),
                "skipped_count": len(skipped),
                "no_finding_count": len(flow_results) - len(confirmed) - len(skipped),
                "base_url": base_url,
                "provider": idast_cfg.provider,
                "model": idast_cfg.model,
                "openapi_spec": openapi_spec,
                "findings": [
                    {
                        "flow_id": fr.flow_id,
                        "vulnerability_class": fr.vulnerability_class,
                        "endpoint": fr.endpoint,
                        "confirmed": bool(fr.finding),
                        "skipped": fr.skipped,
                        "skip_reason": fr.skip_reason,
                        "finding": fr.finding.to_dict() if fr.finding else None,
                    }
                    for fr in flow_results
                ],
            },
        )

    def _skipped(self, reason: str) -> AgentResult:
        logger.info(f"[intelligent_dast] Skipped — {reason}")
        return AgentResult(
            tool_name=self.tool_name,
            findings=[],
            metadata={"status": "skipped", "reason": reason},
        )
