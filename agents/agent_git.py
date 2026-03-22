import asyncio
import logging
import re
import tempfile
from pathlib import Path
from typing import Optional

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext

logger = logging.getLogger(__name__)

# Config filenames to look for inside the cloned repo, in priority order
_CONFIG_CANDIDATES = ["vulnreach.yaml", "vulnreach.yml", "scan.yml", "scan.yaml"]


class GitAgent(BaseAgent):
    tool_name = "git"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.repo_url:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "missing_repo_url"})

        repo_name = self._safe_repo_name(self._repo_name(context.repo_url))

        # Clone into a fresh temp directory — each scan (including rescans) gets its own isolated copy
        tmp_dir = tempfile.mkdtemp(prefix=f"vulnreach-{repo_name}-")
        target_dir = Path(tmp_dir)
        logger.info(f"[git] Cloning {context.repo_url} → {target_dir}")

        clone_result = await self._run_cmd(["git", "clone", "--depth", "1", context.repo_url, str(target_dir)])
        if clone_result[0] != 0:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "clone_failed", "stderr": clone_result[2]},
            )

        commit = await self._current_commit(target_dir)
        context.repo_path = str(target_dir)
        context.repo_name = repo_name

        # Auto-discover a vulnreach config inside the cloned repo.
        # Overrides the default config set by the API when no config_path was given.
        for candidate in _CONFIG_CANDIDATES:
            candidate_path = target_dir / candidate
            if candidate_path.exists():
                try:
                    from config.schema import load_config
                    context.config = load_config(str(candidate_path))
                    context.config_path = str(candidate_path)
                    logger.info(f"[git] Auto-discovered config: {candidate_path}")
                    break
                except Exception as exc:
                    logger.warning(f"[git] Found {candidate_path} but failed to load: {exc}")

        clone_metadata = {
            "repo_url": context.repo_url,
            "repo_name": repo_name,
            "clone_path": str(target_dir),
            "commit": commit,
            "scan_id": context.scan_id,
        }

        return AgentResult(tool_name=self.tool_name, findings=[clone_metadata], metadata={"raw": clone_metadata})

    async def _current_commit(self, repo_path: Path) -> Optional[str]:
        code, stdout, _ = await self._run_cmd(["git", "-C", str(repo_path), "rev-parse", "HEAD"])
        return stdout.strip() if code == 0 else None

    def _repo_name(self, repo_url: str) -> str:
        name = repo_url.rstrip("/").split("/")[-1]
        return name[:-4] if name.endswith(".git") else name

    def _safe_repo_name(self, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "-", name or "repo")
        return safe or "repo"

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
