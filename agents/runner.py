from typing import List
import logging

from core.models import AgentResult, ScanContext
from pydantic import ValidationError

from storage.repository import StorageRepository

from .agent_git import GitAgent
from .agent_trivy import TrivyAgent
from .agent_tainter import TainterAgent
from .agent_semgrep import SemgrepAgent
from .agent_python_reachability import PythonReachabilityAgent
from .agent_dynamic_reachability import DynamicReachabilityAgent
from .agent_routextractor import RouteExtractorAgent
from .agent_metadata import MetadataAgent

logger = logging.getLogger(__name__)


class AgentRunner:
    def __init__(self, storage: StorageRepository) -> None:
        self.storage = storage
        self.git = GitAgent()
        self.trivy = TrivyAgent()
        self.tainter = TainterAgent()
        self.semgrep = SemgrepAgent()
        self.python_reachability = PythonReachabilityAgent()
        self.dynamic_reachability = DynamicReachabilityAgent()
        self.route_extractor = RouteExtractorAgent()
        self.metadata_agent = MetadataAgent()

    async def run_all(self, context: ScanContext) -> List[AgentResult]:
        results: List[AgentResult] = []

        cfg_tools = context.config.scan.tools if context.config else ["trivy", "tainter"]
        tools = [tool.lower() for tool in cfg_tools]
        if context.repo_url and "git" not in tools:
            tools.insert(0, "git")
        # Always keep semgrep entry lowercased for gating

        if "git" in tools and context.repo_url:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "git"})
            git_result = await self._run_agent(self.git, context)
            results.append(git_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.git.tool_name,
                git_result.metadata.get("raw", git_result.metadata or {}),
            )
            if git_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "git", "error": git_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "git"})

        if "trivy" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "trivy"})
            trivy_result = await self._run_agent(self.trivy, context)
            results.append(trivy_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.trivy.tool_name,
                trivy_result.metadata.get("raw", trivy_result.metadata or {}),
             )
            self.storage.store_vulnerabilities(context.scan_id or "", trivy_result.findings)
            context.vulnerabilities = trivy_result.findings
            logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "trivy"})

        if "tainter" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "tainter"})
            tainter_result = await self._run_agent(self.tainter, context)
            results.append(tainter_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.tainter.tool_name,
                tainter_result.metadata.get("raw", tainter_result.metadata or {}),
             )
            self.storage.store_reachability(context.scan_id or "", tainter_result.findings)
            logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "tainter"})

        if "python_reachability" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "python_reachability"})
            py_result = await self._run_agent(self.python_reachability, context)
            results.append(py_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.python_reachability.tool_name,
                py_result.metadata.get("raw", py_result.metadata or {}),
             )
            self.storage.store_reachability(context.scan_id or "", py_result.findings)
            if py_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "python_reachability", "error": py_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "python_reachability"})

        # Dynamic reachability runs if runtime.enabled in config (not gated by tools list)
        if context.config and context.config.scan.runtime.enabled:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability"})
            dyn_result = await self._run_agent(self.dynamic_reachability, context)
            results.append(dyn_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.dynamic_reachability.tool_name,
                dyn_result.metadata.get("raw", dyn_result.metadata or {}),
            )
            # Store dynamic findings as reachability evidence
            if dyn_result.findings:
                self.storage.store_reachability(context.scan_id or "", dyn_result.findings)
            if dyn_result.metadata.get("error"):
                # Dynamic failure should not crash scan - log and continue
                logger.warning("agent_error", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability", "error": dyn_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability"})

        if "route_extractor" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "route_extractor"})
            route_result = await self._run_agent(self.route_extractor, context)
            results.append(route_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.route_extractor.tool_name,
                route_result.metadata.get("raw", route_result.metadata or {}),
             )
            self.storage.store_routes(context.scan_id or "", route_result.findings)
            if route_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "route_extractor", "error": route_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "route_extractor"})

        if "metadata" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "metadata"})
            meta_result = await self._run_agent(self.metadata_agent, context)
            results.append(meta_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.metadata_agent.tool_name,
                meta_result.metadata.get("raw", meta_result.metadata or {}),
             )
            if meta_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "metadata", "error": meta_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "metadata"})

        return results

    async def _run_agent(self, agent, context: ScanContext) -> AgentResult:
        try:
            result = await agent.run(context)
            return AgentResult.model_validate(result)
        except ValidationError as ve:
            return AgentResult(tool_name=getattr(agent, "tool_name", "unknown"), findings=[], metadata={"error": "schema_validation_failed", "details": ve.errors()})
        except Exception as exc:  # pragma: no cover
            logger.exception("agent_exception", extra={"scan_id": context.scan_id, "agent": getattr(agent, "tool_name", "unknown")})
            return AgentResult(tool_name=getattr(agent, "tool_name", "unknown"), findings=[], metadata={"error": "agent_exception", "details": str(exc)})
