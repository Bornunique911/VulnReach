"""Pytest Coverage Agent — run the target app's test suite with coverage.

Flow:
  Step 1 — Pre-flight: find target Python, verify pytest + pytest-cov available,
            locate test directories.
  Step 2 — Run pytest with --cov and --cov-report=json to produce coverage.json.
  Step 3 — Parse coverage.json.
  Step 4 — Correlate coverage with known CVE vulnerabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext
from agents.utils.coverage_correlator import correlate_coverage

logger = logging.getLogger(__name__)

# Test directories to look for, in priority order.
_TEST_DIRS = ("tests", "test", "testing")

# Maximum seconds to wait for the test suite to finish.
_PYTEST_TIMEOUT = 300

# Maximum size of coverage.json we're willing to parse (50 MB).
_MAX_COVERAGE_BYTES = 50 * 1024 * 1024


def _find_target_python(repo_path: Path) -> Optional[str]:
    """Find the target app's virtualenv Python, same logic as MetadataAgent."""
    for venv in (".venv", "venv", "env", ".env"):
        candidate = repo_path / venv / "bin" / "python"
        if candidate.is_file():
            return str(candidate)
    return None


def _find_test_dirs(repo_path: Path) -> List[str]:
    """Return test directories that exist under repo_path."""
    found = []
    for name in _TEST_DIRS:
        candidate = repo_path / name
        if candidate.is_dir():
            found.append(str(candidate))
    return found or [str(repo_path)]  # fallback: let pytest discover from root


class PytestCoverageAgent(BaseAgent):
    tool_name = "pytest_coverage"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        # ------------------------------------------------------------------
        # Step 1 — Pre-flight
        # ------------------------------------------------------------------
        if not context.repo_path:
            return self._skipped("missing_repo_path")

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return self._skipped("repo_path_not_found")

        python_bin = _find_target_python(repo_path)
        if not python_bin:
            logger.warning("[pytest_cov] No virtualenv found in repo — skipping")
            return self._skipped("no_virtualenv_found")

        # Verify pytest and pytest-cov are installed in the target env.
        if not await self._check_deps(python_bin):
            return self._skipped("pytest_or_pytest_cov_not_installed")

        test_dirs = _find_test_dirs(repo_path)
        logger.info(f"[pytest_cov] Test dirs: {test_dirs}")

        # ------------------------------------------------------------------
        # Step 2 — Run pytest
        # ------------------------------------------------------------------
        coverage_data, run_meta = await self._run_pytest(
            python_bin, repo_path, test_dirs
        )

        if coverage_data is None:
            return AgentResult(
                tool_name=self.tool_name,
                status="failed",
                findings=[],
                metadata=run_meta,
            )

        # ------------------------------------------------------------------
        # Step 3 + 4 — Correlate
        # ------------------------------------------------------------------
        findings = correlate_coverage(
            coverage_data,
            context.vulnerabilities,
            context.import_map,
            evidence_type="pytest",
            static_findings=context.taint_flows,
        )

        return AgentResult(
            tool_name=self.tool_name,
            findings=[f.model_dump() for f in findings],
            metadata={
                "status": "ok",
                "finding_count": len(findings),
                "coverage_files": coverage_data.get("meta", {}).get("covered_lines"),
                "run": run_meta,
            },
        )

    # ------------------------------------------------------------------
    # Step 1 helpers
    # ------------------------------------------------------------------

    async def _check_deps(self, python_bin: str) -> bool:
        """Return True if both pytest and pytest-cov are importable."""
        check_script = (
            "import pytest, pytest_cov; print('ok')"
        )
        proc = await asyncio.create_subprocess_exec(
            python_bin, "-c", check_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False
        return proc.returncode == 0 and stdout.decode().strip() == "ok"

    # ------------------------------------------------------------------
    # Step 2 — Run pytest with coverage
    # ------------------------------------------------------------------

    async def _run_pytest(
        self,
        python_bin: str,
        repo_path: Path,
        test_dirs: List[str],
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Run pytest --cov and return (coverage_data, meta)."""
        with tempfile.TemporaryDirectory(prefix="vulnreach_pytest_") as tmp_dir:
            cov_json_path = Path(tmp_dir) / "coverage.json"

            cmd = [
                python_bin, "-m", "pytest",
                *test_dirs,
                f"--cov={repo_path}",
                f"--cov-report=json:{cov_json_path}",
                "--tb=no",
                "-q",
                "--no-header",
                "-p", "no:cacheprovider",
            ]

            logger.info(f"[pytest_cov] Running: {' '.join(cmd)}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_PYTEST_TIMEOUT
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.error(f"[pytest_cov] Timed out after {_PYTEST_TIMEOUT}s")
                return None, {
                    "error": "pytest_timeout",
                    "timeout": _PYTEST_TIMEOUT,
                    "cmd": " ".join(cmd),
                }

            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            meta: Dict[str, Any] = {
                "cmd": " ".join(cmd),
                "returncode": proc.returncode,
                "stdout": stdout_text[-2000:],
            }
            if stderr_text.strip():
                meta["stderr"] = stderr_text[-500:]

            # rc=0 — all tests passed; rc=1 — some tests failed (still have coverage)
            # rc=2 — interrupted; rc=3 — internal error; rc=4 — bad usage; rc=5 — no tests
            if proc.returncode not in (0, 1):
                logger.warning(
                    f"[pytest_cov] Unexpected exit code {proc.returncode} — "
                    f"checking for coverage.json anyway"
                )

            if not cov_json_path.exists():
                return None, {**meta, "error": "coverage_json_not_produced"}

            file_size = cov_json_path.stat().st_size
            if file_size > _MAX_COVERAGE_BYTES:
                logger.warning(
                    f"[pytest_cov] coverage.json is {file_size // (1024*1024)} MB — skipping"
                )
                return None, {
                    **meta,
                    "error": "coverage_json_too_large",
                    "size_bytes": file_size,
                }

            try:
                with open(cov_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as exc:
                return None, {**meta, "error": "coverage_json_parse_failed", "details": str(exc)}

            if not data.get("files"):
                return None, {**meta, "error": "coverage_empty"}

            logger.info(f"[pytest_cov] Coverage collected — {len(data['files'])} files")
            meta["files_count"] = len(data["files"])
            return data, meta

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _skipped(self, reason: str) -> AgentResult:
        logger.info(f"[pytest_cov] Skipped — {reason}")
        return AgentResult(
            tool_name=self.tool_name,
            status="skipped",
            findings=[],
            metadata={"reason": reason},
        )
