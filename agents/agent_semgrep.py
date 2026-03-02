import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext, SemgrepFinding


class SemgrepAgent(BaseAgent):
    tool_name = "semgrep"

    def __init__(self, timeout_seconds: int = 300, config: str = "auto") -> None:
        self.timeout_seconds = timeout_seconds
        self.config = config

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

        raw, stderr, returncode = await self._run_semgrep(repo_path)
        if raw is None or returncode != 0:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "error": "semgrep_execution_failed",
                    "stderr": stderr,
                    "returncode": returncode,
                },
            )

        findings = [SemgrepFinding.model_validate(f).model_dump() for f in self._normalize(raw)]
        return AgentResult.model_validate(
            {
                "tool_name": self.tool_name,
                "findings": findings,
                "metadata": {"status": "ok", "raw": raw, "finding_count": len(findings)},
            }
        )

    async def _run_semgrep(self, repo_path: Path) -> tuple[Optional[Dict[str, Any]], str, int]:
        cmd = [
            "semgrep",
            "--config",
            self.config,
            "--json",
            str(repo_path),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            return None, "timeout", 1

        stderr_text = stderr.decode() if stderr else ""
        if proc.returncode != 0:
            return None, stderr_text, proc.returncode

        try:
            return json.loads(stdout.decode()), stderr_text, proc.returncode
        except json.JSONDecodeError:
            return None, stderr_text, proc.returncode

    def _normalize(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        results = raw.get("results", []) if isinstance(raw, dict) else []
        for item in results:
            severity = (
                item.get("extra", {}).get("severity")
                or item.get("extra", {}).get("metadata", {}).get("severity")
                or "MEDIUM"
            )
            findings.append(
                {
                    "check_id": item.get("check_id"),
                    "path": item.get("path"),
                    "start": item.get("start"),
                    "end": item.get("end"),
                    "extra": item.get("extra"),
                    "severity": severity,
                }
            )
        return findings

