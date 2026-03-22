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
from .agent_openapi_generator import OpenAPIGeneratorAgent
from .agent_intelligent_dast import IntelligentDastAgent
from .agent_pytest_coverage import PytestCoverageAgent
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
        self.openapi_generator = OpenAPIGeneratorAgent()
        self.dynamic_reachability = DynamicReachabilityAgent()
        self.intelligent_dast = IntelligentDastAgent()
        self.pytest_coverage = PytestCoverageAgent()
        self.route_extractor = RouteExtractorAgent()
        self.metadata_agent = MetadataAgent()

    async def run_all(self, context: ScanContext) -> List[AgentResult]:
        """Execute all agents in the correct pipeline order.

        Order:
          1. git          — clone repo if repo_url provided
          2. trivy        — SCA scan → context.vulnerabilities
          3. metadata     — import_map → context.import_map (needed by tainter/dynamic)
          4. tainter      — static taint flows → context.taint_flows
          5. python_reachability — AST call-chain analysis
          6. semgrep      — static analysis rules
          7. route_extractor — extract HTTP routes
          8. openapi_generator — LLM-generate openapi.json if missing (before dynamic)
          9. dynamic_reachability — Docker + schemathesis + coverage
         10. pytest_coverage — run test suite with coverage.py
         11. intelligent_dast — Claude-steered DAST (needs taint_flows)
        """
        results: List[AgentResult] = []

        cfg_tools = context.config.scan.tools if context.config else ["trivy", "tainter"]
        tools = [tool.lower() for tool in cfg_tools]
        if context.repo_url and "git" not in tools:
            tools.insert(0, "git")

        # ── 1. Git clone ─────────────────────────────────────────────────
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

        # ── 2. Trivy (SCA) ───────────────────────────────────────────────
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

        # ── 3. Metadata (import_map) — MUST run before tainter/dynamic ──
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

        # ── 4. Tainter (static taint flows) ──────────────────────────────
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
            # Populate taint_flows on context for downstream agents (e.g. intelligent_dast)
            context.taint_flows = tainter_result.metadata.get("flows", [])
            logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "tainter"})

        # ── 5. Python Reachability (AST call-chain) ──────────────────────
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

        # ── 6. Semgrep (static analysis rules) ───────────────────────────
        if "semgrep" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "semgrep"})
            semgrep_result = await self._run_agent(self.semgrep, context)
            results.append(semgrep_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.semgrep.tool_name,
                semgrep_result.metadata.get("raw", semgrep_result.metadata or {}),
            )
            self.storage.store_semgrep_findings(context.scan_id or "", semgrep_result.findings)
            if semgrep_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "semgrep", "error": semgrep_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "semgrep"})

        # ── 7. Route Extractor ────────────────────────────────────────────
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
            # Populate context.routes for downstream agents (dynamic, dast)
            context.routes = route_result.findings
            if route_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "route_extractor", "error": route_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "route_extractor"})

        # ── 8. OpenAPI Generator (LLM) — runs before dynamic if enabled ──
        # Generates openapi.json so dynamic_reachability can use it.
        # Gated by runtime.enabled AND openapi_generator.enabled in config.
        if context.config and context.config.scan.runtime.enabled and context.config.scan.openapi_generator.enabled:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "openapi_generator"})
            oas_result = await self._run_agent(self.openapi_generator, context)
            results.append(oas_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.openapi_generator.tool_name,
                oas_result.metadata.get("raw", oas_result.metadata or {}),
            )
            if oas_result.metadata.get("error"):
                logger.warning("agent_error", extra={"scan_id": context.scan_id, "agent": "openapi_generator", "error": oas_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "openapi_generator"})

        # ── 9. Dynamic Reachability (Docker + schemathesis + coverage) ───
        # Requires: Dockerfile + openapi.json (may have been generated above)
        if context.config and context.config.scan.runtime.enabled:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability"})
            dyn_result = await self._run_agent(self.dynamic_reachability, context)
            results.append(dyn_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.dynamic_reachability.tool_name,
                dyn_result.metadata.get("raw", dyn_result.metadata or {}),
            )
            if dyn_result.findings:
                self.storage.store_reachability(context.scan_id or "", dyn_result.findings)
            if dyn_result.metadata.get("error"):
                logger.warning("agent_error", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability", "error": dyn_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "dynamic_reachability"})

        # ── 10. Pytest Coverage (test suite with coverage.py) ─────────────
        if "pytest_coverage" in tools:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "pytest_coverage"})
            pytest_result = await self._run_agent(self.pytest_coverage, context)
            results.append(pytest_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.pytest_coverage.tool_name,
                pytest_result.metadata.get("raw", pytest_result.metadata or {}),
            )
            if pytest_result.findings:
                self.storage.store_reachability(context.scan_id or "", pytest_result.findings)
            if pytest_result.metadata.get("error"):
                logger.warning("agent_skipped", extra={"scan_id": context.scan_id, "agent": "pytest_coverage", "error": pytest_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "pytest_coverage"})

        # ── 11. Intelligent DAST (Claude-steered, needs taint_flows) ──────
        if context.config and context.config.scan.intelligent_dast.enabled:
            logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": "intelligent_dast"})
            dast_result = await self._run_agent(self.intelligent_dast, context)
            results.append(dast_result)
            self.storage.store_raw_output(
                context.scan_id or "",
                self.intelligent_dast.tool_name,
                dast_result.metadata.get("raw", dast_result.metadata or {}),
            )
            if dast_result.findings:
                self.storage.store_reachability(context.scan_id or "", dast_result.findings)
            if dast_result.metadata.get("error"):
                logger.warning("agent_error", extra={"scan_id": context.scan_id, "agent": "intelligent_dast", "error": dast_result.metadata})
            else:
                logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": "intelligent_dast"})

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
