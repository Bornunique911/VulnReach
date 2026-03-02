import asyncio
import json
import re
import shutil
from pathlib import Path
from typing import Optional
from uuid import uuid4

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext


class GitAgent(BaseAgent):
    tool_name = "git"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.repo_url:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "missing_repo_url"})

        repo_name = self._safe_repo_name(self._repo_name(context.repo_url, context.repo_path))
        clone_root = Path(context.clone_root).resolve()
        findings_root = Path(context.findings_root).resolve()
        clone_root.mkdir(parents=True, exist_ok=True)
        findings_root.mkdir(parents=True, exist_ok=True)

        scan_dir = context.scan_id or uuid4().hex
        target_dir = clone_root / repo_name / scan_dir
        if target_dir.exists():
            shutil.rmtree(target_dir)

        clone_result = await self._run_cmd(["git", "clone", context.repo_url, str(target_dir)])
        if clone_result[0] != 0:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "clone_failed", "stderr": clone_result[2]},
            )

        commit = await self._current_commit(target_dir)
        context.repo_path = str(target_dir)
        context.repo_name = repo_name

        findings_dir = findings_root / repo_name
        findings_dir.mkdir(parents=True, exist_ok=True)
        scan_file = self._next_scan_file(findings_dir)
        clone_metadata = {
            "repo_url": context.repo_url,
            "repo_name": repo_name,
            "clone_path": str(target_dir),
            "commit": commit,
            "scan_id": context.scan_id,
            "scan_file": str(scan_file),
        }
        scan_file.write_text(json.dumps(clone_metadata, indent=2), encoding="utf-8")

        return AgentResult(tool_name=self.tool_name, findings=[clone_metadata], metadata={"raw": clone_metadata})

    async def _current_commit(self, repo_path: Path) -> Optional[str]:
        code, stdout, _ = await self._run_cmd(["git", "-C", str(repo_path), "rev-parse", "HEAD"])
        return stdout.strip() if code == 0 else None

    def _repo_name(self, repo_url: str, repo_path: Optional[str]) -> str:
        if repo_url:
            name = repo_url.rstrip("/").split("/")[-1]
            return name[:-4] if name.endswith(".git") else name
        if repo_path:
            return Path(repo_path).name
        return "unknown"

    def _safe_repo_name(self, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "-", name or "repo")
        return safe or "repo"

    def _next_scan_file(self, findings_dir: Path) -> Path:
        max_idx = 0
        for path in findings_dir.glob("scan*.json"):
            suffix = path.stem[4:]
            if suffix.isdigit():
                max_idx = max(max_idx, int(suffix))
        return findings_dir / f"scan{max_idx + 1}.json"

    async def _run_cmd(self, cmd: list[str]) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            return 1, "", "timeout"
        return proc.returncode, stdout.decode(), stderr.decode()
