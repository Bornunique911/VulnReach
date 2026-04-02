import io
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List

from correlation.engine import confidence_from_verdict, reachability_verdict
from core.agent import BaseTool
from core.models import AgentResult, ReachabilityFinding, ScanContext
from agents.reachability.common import build_report_dict
from agents.reachability.java_reachability_analyzer import JavaReachabilityAnalyzer


class JavaReachabilityAgent(BaseTool):
    tool_name = "java_reachability"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.repo_path:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "missing_repo_path"})

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": str(repo_path)},
            )

        vuln_inputs = self._build_vuln_inputs(context.vulnerabilities)
        if not vuln_inputs:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"status": "no_vulns"})

        stdout_buf = io.StringIO()
        try:
            with redirect_stdout(stdout_buf):
                analyzer = JavaReachabilityAnalyzer(str(repo_path))
                analyses = [analyzer.analyze_vulnerability(vuln) for vuln in vuln_inputs]
                report = build_report_dict(analyses, str(repo_path), "java")
        except Exception as exc:  # pragma: no cover
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "java_reachability_failed", "details": str(exc)},
            )

        findings = [
            ReachabilityFinding.model_validate(f).model_dump()
            for f in self._map_findings(analyses, vuln_inputs)
        ]
        metadata = {
            "status": "ok",
            "finding_count": len(findings),
            "raw": report,
            "logs": stdout_buf.getvalue(),
        }
        return AgentResult.model_validate(
            {"tool_name": self.tool_name, "findings": findings, "metadata": metadata}
        )

    def _build_vuln_inputs(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        inputs: List[Dict[str, Any]] = []
        for vuln in vulns:
            package = vuln.get("package")
            if not package:
                continue
            cves = vuln.get("cve_id")
            cve_list = cves if isinstance(cves, list) else [cves] if cves else []
            inputs.append(
                {
                    "package_name": package,
                    "installed_version": vuln.get("version"),
                    "fixed_version": vuln.get("fix_version"),
                    "severity": vuln.get("severity"),
                    "cve_ids": cve_list,
                }
            )
        return inputs

    def _map_findings(self, analyses: List[Any], vuln_inputs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        pkg_cves: Dict[str, List[str]] = {}
        for inp in vuln_inputs:
            pkg = inp.get("package_name")
            if not pkg:
                continue
            pkg_cves.setdefault(pkg, []).extend(inp.get("cve_ids", []))

        mapped: List[Dict[str, Any]] = []
        for analysis in analyses:
            cves = pkg_cves.get(analysis.package_name, [None]) or [None]
            call_chain_exists = bool(analysis.call_chain_graph)
            sink_reachable = call_chain_exists
            verdict = reachability_verdict(analysis.is_used, call_chain_exists, sink_reachable)
            confidence = confidence_from_verdict(verdict)
            files = list(dict.fromkeys(ctx.file_path for ctx in analysis.usage_contexts))
            functions = list(
                dict.fromkeys(
                    ctx.enclosing_scope for ctx in analysis.usage_contexts if ctx.enclosing_scope
                )
            )
            line = min(
                (ctx.line_number for ctx in analysis.usage_contexts if getattr(ctx, "line_number", 0)),
                default=None,
            )

            for cve in cves:
                mapped.append(
                    {
                        "cve_id": cve,
                        "package": analysis.package_name,
                        "import_detected": analysis.is_used,
                        "call_chain_exists": call_chain_exists,
                        "sink_reachable": sink_reachable,
                        "verdict": verdict,
                        "confidence": confidence,
                        "evidence_type": "static",
                        "function": ", ".join(functions) if functions else None,
                        "files": files,
                        "line": line,
                    }
                )

        return mapped
