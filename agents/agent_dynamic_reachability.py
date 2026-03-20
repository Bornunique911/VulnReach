"""Dynamic Reachability Agent — Docker-based coverage approach.

Flow (per DYNAMIC_ANALYSIS.MD):
  Step 1 — Pre-flight checks (Dockerfile + openapi spec exist)
  Step 2 — Patch Dockerfile, build instrumented image, start container
  Step 3 — Run Schemathesis (triggers traffic with custom headers)
  Step 4 — Collect coverage.json from container
  Step 5 — Correlate static findings with dynamic hit set
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None

from core.agent import BaseTool
from core.models import AgentResult, ReachabilityFinding, ScanContext

logger = logging.getLogger(__name__)

# Known PyPI name → importable package name mappings for correlation
_PYPI_TO_IMPORT: Dict[str, str] = {
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "mysqlclient": "MySQLdb",
}

# Minimum package name length to use as a substring match (avoids 're', 'os', etc.)
_MIN_PKG_MATCH_LEN = 4


class DynamicReachabilityAgent(BaseTool):
    tool_name = "dynamic_reachability"

    def __init__(self, default_timeout: int = 60) -> None:
        self.default_timeout = default_timeout

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.config or not context.config.scan.runtime.enabled:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"status": "disabled", "reason": "runtime.enabled is false"},
            )

        if not context.repo_path:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "missing_repo_path"},
            )

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": str(repo_path)},
            )

        runtime = context.config.scan.runtime
        timeout = runtime.timeout or self.default_timeout
        coverage_wait = runtime.coverage_wait
        container_port = runtime.container_port

        # ------------------------------------------------------------------
        # Step 1 — Pre-flight checks
        # ------------------------------------------------------------------
        preflight = self._preflight(repo_path)
        if not preflight["passed"]:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "skipped",
                    "container_started": {"status": "no", "id": "na"},
                    **preflight,
                },
            )

        # Dispatch to eBPF mode when enabled and the tracer is available.
        # Falls back to coverage mode silently when unavailable.
        ebpf_cfg = runtime.ebpf
        if ebpf_cfg.enabled:
            if self._ebpf_available(ebpf_cfg.tracer):
                logger.info(
                    f"[dynamic] eBPF mode active (tracer={ebpf_cfg.tracer}, mode={ebpf_cfg.mode})"
                )
                return await self._run_ebpf_mode(context, repo_path, runtime, preflight)
            logger.warning(
                f"[dynamic] eBPF requested but {ebpf_cfg.tracer} unavailable — "
                "falling back to Dockerfile-patch coverage mode"
            )

        dockerfile_path = Path(preflight["dockerfile_path"])
        openapi_path = preflight["openapi_path"]

        # ------------------------------------------------------------------
        # Step 2 — Patch Dockerfile, build image, start container
        # ------------------------------------------------------------------
        image_tag, workdir, patch_meta = await self._build_instrumented_image(
            dockerfile_path, repo_path
        )
        if not image_tag:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "dockerfile_patch",
                    "container_started": {"status": "no", "id": "na"},
                    **patch_meta,
                },
            )

        # _start_container now returns (container_id, coverage_host_dir)
        # so there are no hidden side-effects on instance state.
        start_result = await self._start_container(image_tag, container_port, timeout)
        if start_result is None:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "container_start",
                    "container_started": {"status": "no", "id": "na"},
                    "image": image_tag,
                },
            )

        container_id, coverage_host_dir = start_result
        container_started: Dict[str, str] = {"status": "no", "id": "na"}
        coverage_data: Optional[Dict[str, Any]] = None
        coverage_meta: Dict[str, Any] = {}
        schemathesis_meta: Dict[str, Any] = {}

        try:
            # Wait for container to become healthy
            base_url = f"http://localhost:{container_port}"
            healthy = await self._wait_for_healthy(base_url, timeout=30)
            if not healthy:
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "health_check",
                        "container_started": {"status": "no", "id": container_id[:12]},
                        "url": base_url,
                    },
                )

            container_started = {"status": "yes-running", "id": container_id[:12]}

            # ------------------------------------------------------------------
            # Step 3 — Schemathesis
            # ------------------------------------------------------------------
            schemathesis_meta = await self._run_schemathesis(
                base_url, openapi_path, container_port, workdir
            )

            # Wait for coverage data to flush
            logger.info(f"[dynamic] Waiting {coverage_wait}s for coverage to flush...")
            await asyncio.sleep(coverage_wait)

        finally:
            # Always stop the running container before extraction or cleanup.
            await self._stop_container(container_id)
            if workdir and Path(workdir).exists():
                shutil.rmtree(workdir, ignore_errors=True)

        # ------------------------------------------------------------------
        # Step 4 — Extract coverage from the shared volume using a fresh
        #           short-lived container (no running container needed here).
        # ------------------------------------------------------------------
        taint_events: List[Dict[str, Any]] = []
        try:
            coverage_data, coverage_meta, taint_events = (
                await self._extract_coverage_from_volume(image_tag, coverage_host_dir)
            )
            # Persist coverage.json next to the repo so it survives cleanup.
            src = Path(coverage_host_dir) / "coverage.json"
            if src.exists():
                dest = repo_path / "coverage.json"
                shutil.copy2(src, dest)
                logger.info(f"[dynamic][coverage] Saved coverage.json to {dest}")
                coverage_meta["saved_to"] = str(dest)
        finally:
            # Always clean up the coverage host directory.
            if coverage_host_dir and Path(coverage_host_dir).exists():
                shutil.rmtree(coverage_host_dir, ignore_errors=True)

        if not coverage_data:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "skipped",
                    "step": "coverage_collection",
                    "container_started": container_started,
                    "reason": coverage_meta.get("error", "empty coverage"),
                    "schemathesis": schemathesis_meta,
                },
            )

        # ------------------------------------------------------------------
        # Step 5 — Correlate static + dynamic (coverage + taint events)
        # ------------------------------------------------------------------
        findings = self._correlate(coverage_data, context.vulnerabilities, taint_events)

        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "finding_count": len(findings),
                "container_started": container_started,
                "image_tag": image_tag,
                "schemathesis": schemathesis_meta,
                "coverage": coverage_meta,
            },
        })

    # ------------------------------------------------------------------
    # Step 1 — Pre-flight
    # ------------------------------------------------------------------

    def _preflight(self, repo_path: Path) -> Dict[str, Any]:
        """Check that Dockerfile and an OpenAPI spec exist."""
        dockerfile = repo_path / "Dockerfile"
        if not dockerfile.exists():
            reason = f"Dockerfile not found in {repo_path}"
            logger.warning(f"[dynamic][preflight] SKIP — {reason}")
            return {"passed": False, "reason": reason}

        openapi_path: Optional[str] = None
        for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
            candidate = repo_path / name
            if candidate.exists():
                openapi_path = str(candidate)
                break

        if not openapi_path:
            reason = f"No openapi.json / openapi.yaml found in {repo_path}"
            logger.warning(f"[dynamic][preflight] SKIP — {reason}")
            return {
                "passed": False,
                "reason": reason,
                "dockerfile_path": str(dockerfile),
            }

        logger.info(
            f"[dynamic][preflight] PASS — Dockerfile: {dockerfile}, OpenAPI: {openapi_path}"
        )
        return {
            "passed": True,
            "dockerfile_path": str(dockerfile),
            "openapi_path": openapi_path,
        }

    # ------------------------------------------------------------------
    # Step 2 — Patch Dockerfile + build + start
    # ------------------------------------------------------------------

    def _patch_dockerfile(
        self, original: Path, inject_hooks: bool = False
    ) -> Tuple[Optional[str], str]:
        """
        Ensure the Dockerfile is instrumented for coverage collection.

        - If COVERAGE_PROCESS_START already present → pass-through (no-op).
        - If CMD is gunicorn/uvicorn → inject sitecustomize + env block.
        - Otherwise → return (None, reason) so the caller can abort cleanly.

        When inject_hooks=True, the sitecustomize.py also installs runtime_hooks
        (audit, imports, sinks) and registers an atexit handler to flush taint
        events to /coverage/runtime_events.<pid>.json on container shutdown.
        Requires .vulnreach_hooks/ to be present in the Docker build context.
        """
        content = original.read_text(encoding="utf-8")

        if "COVERAGE_PROCESS_START" in content:
            logger.info("[dynamic][patch] COVERAGE_PROCESS_START found — pass-through")
            return content, "already_patched"

        lines = content.splitlines()
        patched_lines: List[str] = []
        found_target_cmd = False

        for line in lines:
            stripped = line.strip()
            if not stripped.upper().startswith("CMD"):
                patched_lines.append(line)
                continue

            cmd_args = self._parse_cmd_line(stripped)
            if not cmd_args:
                patched_lines.append(line)
                continue

            first = cmd_args[0].lower()
            if first in ("gunicorn", "uvicorn"):
                found_target_cmd = True
                logger.info(f"[dynamic][patch] Found {first} CMD — injecting coverage env")

            patched_lines.append(line)

        if not found_target_cmd:
            return None, "CMD not gunicorn/uvicorn — cannot auto-patch"

        # sitecustomize.py content written via printf \n sequences.
        # Single-quoted printf args pass double quotes through literally, so
        # "/runtime_hooks" and the atexit path string are safe.
        if inject_hooks:
            # Extended: coverage.py + runtime_hooks (audit/imports/sinks)
            # Each worker gets its own events file keyed by PID.
            sitecustomize_printf = (
                "import coverage\\ncoverage.process_startup()\\n"
                "import sys\\nsys.path.insert(0, \"/runtime_hooks\")\\n"
                "try:\\n"
                "    from hooks import audit, imports, sinks\\n"
                "    from hooks.events import flush_to_file\\n"
                "    import atexit, os\\n"
                "    audit.install()\\n"
                "    imports.install()\\n"
                "    sinks.install()\\n"
                "    atexit.register(flush_to_file,"
                " \"/coverage/runtime_events.\" + str(os.getpid()) + \".json\")\\n"
                "except Exception:\\n    pass\\n"
            )
            copy_hooks_line = "COPY .vulnreach_hooks/ /runtime_hooks/\n"
            logger.info("[dynamic][patch] Injecting runtime_hooks alongside coverage.py")
        else:
            sitecustomize_printf = "import coverage\\ncoverage.process_startup()\\n"
            copy_hooks_line = ""

        coverage_block = (
            "\n# Injected by VulnReach dynamic agent\n"
            + copy_hooks_line
            + "RUN printf '[run]\\nsource = .\\ndata_file = /tmp/.coverage\\n"
            "parallel = true\\nsigterm = true\\nconcurrency = multiprocessing\\n'"
            " > /app/.coveragerc\n"
            "RUN python -c \"import sysconfig; print(sysconfig.get_path('purelib'))\""
            " > /tmp/sp.txt \\\n"
            f" && printf '{sitecustomize_printf}'"
            " > \"$(cat /tmp/sp.txt)/sitecustomize.py\"\n"
            "ENV COVERAGE_PROCESS_START=/app/.coveragerc\n"
        )

        full = "\n".join(patched_lines)
        last_cmd_idx = full.rfind("\nCMD ")
        if last_cmd_idx != -1:
            full = full[:last_cmd_idx] + coverage_block + full[last_cmd_idx:]
        else:
            full += coverage_block

        return full, ""

    def _parse_cmd_line(self, line: str) -> List[str]:
        """Parse a Dockerfile CMD line — handles JSON array and shell form."""
        rest = re.sub(r"^CMD\s+", "", line, flags=re.IGNORECASE).strip()

        # JSON array form: CMD ["gunicorn", ...]
        if rest.startswith("["):
            try:
                return json.loads(rest)
            except json.JSONDecodeError:
                pass

        # Shell form: CMD gunicorn ...
        import shlex
        try:
            return shlex.split(rest)
        except ValueError:
            return []

    async def _build_instrumented_image(
        self, dockerfile_path: Path, repo_path: Path
    ) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        """Patch Dockerfile, build image. Returns (image_tag, workdir, meta).

        Attempts to copy runtime_hooks/ into the Docker build context as
        .vulnreach_hooks/ so the patched Dockerfile can COPY it into the image.
        Falls back to coverage-only instrumentation if the directory is missing
        or the copy fails.
        """
        # Locate runtime_hooks relative to this agent file.
        hooks_src = Path(__file__).parent.parent / "runtime_hooks"
        hooks_dst = repo_path / ".vulnreach_hooks"
        inject_hooks = False

        if hooks_src.exists() and hooks_src.is_dir():
            try:
                if hooks_dst.exists():
                    shutil.rmtree(hooks_dst)
                shutil.copytree(hooks_src, hooks_dst)
                inject_hooks = True
                logger.info("[dynamic][build] Copied runtime_hooks into build context")
            except Exception as exc:
                logger.warning(f"[dynamic][build] Failed to copy runtime_hooks: {exc}")

        try:
            patched_content, skip_reason = self._patch_dockerfile(
                dockerfile_path, inject_hooks=inject_hooks
            )
            if patched_content is None:
                return None, None, {"error": skip_reason}

            # Write patched Dockerfile to a temp dir — NEVER overwrite the original.
            workdir = tempfile.mkdtemp(prefix="vulnreach_dynamic_")
            patched_path = Path(workdir) / "Dockerfile"
            patched_path.write_text(patched_content, encoding="utf-8")

            repo_name = repo_path.name.lower().replace(" ", "_")
            image_tag = f"{repo_name}:instrumented"

            logger.info(f"[dynamic][build] Building image {image_tag} from {workdir}")

            proc = await asyncio.create_subprocess_exec(
                "docker", "build",
                "-t", image_tag,
                "-f", str(patched_path),
                str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return None, workdir, {"error": "docker_build_timeout"}

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[-2000:]
                return None, workdir, {"error": "docker_build_failed", "stderr": err}

            logger.info(f"[dynamic][build] Image built: {image_tag}")
            return image_tag, workdir, {
                "image_tag": image_tag,
                "skip_reason": skip_reason,
                "hooks_injected": inject_hooks,
            }

        finally:
            # Remove the temporary .vulnreach_hooks from the repo build context.
            if inject_hooks and hooks_dst.exists():
                shutil.rmtree(hooks_dst, ignore_errors=True)

    async def _start_container(
        self, image_tag: str, container_port: int, timeout: int
    ) -> Optional[Tuple[str, str]]:
        """
        Start the instrumented container with a coverage volume mount.

        Returns (container_id, coverage_host_dir) so callers manage the
        coverage directory explicitly — no hidden instance-variable side effects.
        Returns None on failure.
        """
        # Kill any orphaned containers from previous runs on the same port.
        await self._cleanup_port_conflicts(container_port)

        coverage_dir = tempfile.mkdtemp(prefix="vulnreach_cov_")

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "-p", f"{container_port}:{container_port}",
            "-v", f"{coverage_dir}:/coverage",
            "-e", "COVERAGE_FILE=/coverage/.coverage",
            image_tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            shutil.rmtree(coverage_dir, ignore_errors=True)
            logger.error("[dynamic][container] Timed out starting container")
            return None

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            logger.error(f"[dynamic][container] Failed to start: {err}")
            shutil.rmtree(coverage_dir, ignore_errors=True)
            return None

        container_id = stdout.decode("utf-8").strip()
        logger.info(f"[dynamic][container] Started: {container_id[:12]}")
        return container_id, coverage_dir

    async def _wait_for_healthy(self, base_url: str, timeout: int = 30) -> bool:
        """Poll /health then base URL until a sub-500 response or timeout."""
        if aiohttp is None:
            logger.warning(
                "[dynamic][health] aiohttp not available — waiting 5s and assuming healthy"
            )
            await asyncio.sleep(5)
            return True

        deadline = time.monotonic() + timeout
        for endpoint in (f"{base_url}/health", base_url):
            while time.monotonic() < deadline:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            endpoint, timeout=aiohttp.ClientTimeout(total=3)
                        ) as resp:
                            if resp.status < 500:
                                logger.info(
                                    f"[dynamic][health] Healthy at {endpoint} ({resp.status})"
                                )
                                return True
                except Exception:
                    pass
                await asyncio.sleep(2)

        logger.warning(f"[dynamic][health] Container not healthy after {timeout}s")
        return False

    # ------------------------------------------------------------------
    # Step 3 — Schemathesis
    # ------------------------------------------------------------------

    async def _run_schemathesis(
        self,
        base_url: str,
        openapi_path: str,
        port: int,
        workdir: Optional[str],
    ) -> Dict[str, Any]:
        """Run Schemathesis against the live container to generate coverage."""
        # Ensure the OpenAPI spec is accessible from workdir
        schema_path = openapi_path
        if workdir:
            try:
                dest = Path(workdir) / "openapi.json"
                shutil.copy(openapi_path, dest)
                schema_path = str(dest)
            except Exception as e:
                logger.warning(f"[dynamic][schemathesis] Failed to copy OpenAPI to workdir: {e}")

        cmd = [
            "schemathesis", "run",
            schema_path,
            f"--url={base_url}",
            "--max-examples=10",
            "--header=AGENT: VulnReach",
            "--workers=1",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {"status": "timeout", "note": "schemathesis timed out", "cmd": " ".join(cmd)}

            if proc.returncode == 0:
                logger.info("[dynamic][schemathesis] Tests completed successfully")
                return {
                    "status": "completed",
                    "stdout": stdout.decode("utf-8", errors="replace")[-1000:],
                    "cmd": " ".join(cmd),
                }

            logger.warning(f"[dynamic][schemathesis] Tests failed (rc={proc.returncode})")
            return {
                "status": "failed",
                "returncode": proc.returncode,
                "stderr": stderr.decode("utf-8", errors="replace")[-1000:],
                "cmd": " ".join(cmd),
            }

        except FileNotFoundError:
            # schemathesis binary not on PATH — fall back to manual requests
            logger.warning("[dynamic][schemathesis] schemathesis not found — using manual requests")
            await self._make_manual_requests(base_url)
            return {
                "status": "fallback_used",
                "note": "schemathesis not available, used manual requests",
                "would_run": " ".join(cmd),
            }
        except Exception as e:
            logger.error(f"[dynamic][schemathesis] Unexpected error: {e}")
            return {"status": "error", "error": str(e), "would_run": " ".join(cmd)}

    async def _make_manual_requests(self, base_url: str) -> None:
        """Fallback: hit common endpoints to exercise code paths."""
        if aiohttp is None:
            logger.warning("[dynamic][manual] aiohttp not available for manual requests")
            return

        endpoints = ["/", "/health", "/yaml-test", "/request-test"]
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()
                        logger.info(
                            f"[dynamic][manual] {endpoint} → {resp.status} ({len(content)} bytes)"
                        )
                except Exception as e:
                    logger.warning(f"[dynamic][manual] Request to {endpoint} failed: {e}")

    # ------------------------------------------------------------------
    # Step 4 — Extract coverage from volume
    # ------------------------------------------------------------------

    async def _extract_coverage_from_volume(
        self, image_tag: str, coverage_dir: str
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
        """
        Spin up a short-lived container to combine coverage files and export
        coverage.json to the shared host volume.  Also collects runtime_events
        written by the taint/sink hooks (runtime_events.<pid>.json files).

        The running container must already be stopped before calling this so
        all worker processes have had a chance to flush their .coverage files
        and trigger their atexit handlers.

        Returns (coverage_data, metadata, taint_events).
        """
        if not coverage_dir or not Path(coverage_dir).exists():
            return None, {"error": "coverage_dir_missing"}, []

        coverage_files = list(Path(coverage_dir).glob(".coverage*"))
        if not coverage_files:
            return None, {
                "error": "no_coverage_files_found",
                "files_in_dir": os.listdir(coverage_dir),
            }, []

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "--rm",
            "-v", f"{coverage_dir}:/coverage",
            image_tag,
            "/bin/sh", "-c",
            "coverage combine /coverage/.coverage* && coverage json -o /coverage/coverage.json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None, {"error": "coverage_combine_timeout"}, []

        if proc.returncode != 0:
            return None, {
                "error": "coverage_combine_failed",
                "stderr": stderr.decode("utf-8", errors="replace")[-1000:],
            }, []

        json_path = Path(coverage_dir) / "coverage.json"
        if not json_path.exists():
            return None, {"error": "coverage_json_not_created"}, []

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return None, {"error": "coverage_json_parse_failed", "details": str(e)}, []

        if not data.get("files"):
            return None, {"error": "coverage_empty"}, []

        # Collect taint/sink events written by runtime_hooks atexit handlers.
        # Each worker process writes its own file (keyed by PID) to avoid races.
        taint_events: List[Dict[str, Any]] = []
        for events_file in sorted(Path(coverage_dir).glob("runtime_events.*.json")):
            try:
                with open(events_file, "r", encoding="utf-8") as f:
                    batch = json.load(f)
                if isinstance(batch, list):
                    taint_events.extend(batch)
            except Exception as exc:
                logger.warning(
                    f"[dynamic][coverage] Failed to parse {events_file.name}: {exc}"
                )

        if taint_events:
            logger.info(
                f"[dynamic][coverage] Collected {len(taint_events)} runtime hook events"
            )

        logger.info(f"[dynamic][coverage] Collected {len(data['files'])} files")
        return data, {
            "files_count": len(data["files"]),
            "raw_files_count": len(coverage_files),
            "taint_events_count": len(taint_events),
        }, taint_events

    async def _stop_container(self, container_id: str) -> None:
        """Stop and force-remove a container, waiting for completion."""
        # docker stop first (graceful SIGTERM → SIGKILL after 10s)
        stop_proc = await asyncio.create_subprocess_exec(
            "docker", "stop", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(stop_proc.wait(), timeout=30)
        except asyncio.TimeoutError:
            stop_proc.kill()
            await stop_proc.wait()
            logger.warning(f"[dynamic][container] docker stop timed out for {container_id[:12]}")

        # docker rm -f ensures removal even if stop didn't fully work
        rm_proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(rm_proc.wait(), timeout=15)
        except asyncio.TimeoutError:
            rm_proc.kill()
            await rm_proc.wait()
            logger.warning(f"[dynamic][container] docker rm timed out for {container_id[:12]}")

    async def _cleanup_port_conflicts(self, container_port: int) -> None:
        """
        Kill any containers already bound to container_port from previous
        crashed or orphaned runs. Called before starting a new container.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "-q", "--filter", f"publish={container_port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("[dynamic][cleanup] Timed out listing containers for port cleanup")
            return

        ids = stdout.decode("utf-8").split()
        if not ids:
            return

        logger.warning(
            f"[dynamic][cleanup] Found {len(ids)} orphaned container(s) on port "
            f"{container_port} — stopping: {', '.join(c[:12] for c in ids)}"
        )
        await asyncio.gather(*[self._stop_container(cid) for cid in ids])

    # ------------------------------------------------------------------
    # Step 5 — Correlate static + dynamic
    # ------------------------------------------------------------------

    def _correlate(
        self,
        coverage_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        taint_events: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ReachabilityFinding]:
        """
        Cross-reference dynamically executed (file, function) pairs from
        coverage.json with static vulnerability findings.  Taint sink events
        from runtime_hooks are used as a second evidence stream.

        Verdicts:
          CONFIRMED 0.95 — package import path was dynamically hit (coverage)
          CONFIRMED 0.90 — package name found in a taint sink event stack frame
                           (sink reached but coverage didn't capture the path)
          LIKELY    0.70 — package not seen in either evidence stream
        """
        # Build hit sets from coverage data
        hit_functions: set[str] = set()
        hit_files: set[str] = set()

        for file_path, file_data in coverage_data.get("files", {}).items():
            rel = Path(file_path).name
            hit_files.add(rel)

            for func_name, func_data in file_data.get("functions", {}).items():
                if func_data.get("executed_lines"):
                    hit_functions.add(func_name)
                    hit_functions.add(f"{rel}:{func_name}")

        # Build a flat lowercased corpus of all stack frame text from taint sink
        # events so we can do a single substring scan per package later.
        taint_stack_corpus: List[str] = []
        if taint_events:
            for event in taint_events:
                if event.get("event_type") == "taint_sink_reached":
                    stack = event.get("data", {}).get("stack", [])
                    for frame in stack:
                        taint_stack_corpus.append(frame.lower())

        findings: List[ReachabilityFinding] = []

        for vuln in vulnerabilities:
            pypi_name = (vuln.get("package") or "").lower()
            if not pypi_name:
                continue

            # Resolve PyPI name → importable name (e.g. pillow → PIL)
            import_name = _PYPI_TO_IMPORT.get(pypi_name, pypi_name).lower()

            cves = vuln.get("cve_id", [])
            if isinstance(cves, str):
                cves = [cves]
            if not cves:
                cves = [None]

            # Only do substring matching for names long enough to be unambiguous
            dynamically_hit = False
            taint_confirmed = False
            if len(import_name) >= _MIN_PKG_MATCH_LEN:
                dynamically_hit = any(
                    import_name in f.lower() for f in hit_files
                ) or any(
                    import_name in f.lower() for f in hit_functions
                )
                # Check if the package name appears in any taint sink stack frame.
                # This catches cases where a vulnerable package reached a sink but
                # coverage.py didn't instrument that specific path.
                taint_confirmed = any(
                    import_name in frame for frame in taint_stack_corpus
                )

            if dynamically_hit:
                verdict, confidence = "CONFIRMED", 0.95
            elif taint_confirmed:
                # Taint evidence without coverage: still strong signal since we
                # directly observed tainted data flowing through the package.
                verdict, confidence = "CONFIRMED", 0.90
            else:
                verdict, confidence = "LIKELY", 0.70

            sink_reachable = dynamically_hit or taint_confirmed

            for cve in cves:
                findings.append(
                    ReachabilityFinding(
                        cve_id=cve,
                        package=vuln.get("package"),
                        import_detected=True,
                        call_chain_exists=True,
                        sink_reachable=sink_reachable,
                        verdict=verdict,
                        confidence=confidence,
                        evidence_type="dynamic",
                        function=None,
                        files=list(hit_files)[:5],
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # eBPF non-invasive tracing (alternative to Dockerfile patching)
    # ------------------------------------------------------------------

    def _ebpf_available(self, tracer: str = "bpftrace") -> bool:
        """Return True if eBPF tracing can be attempted on this host.

        Requires Linux and the specified tracer binary in PATH.
        bpftrace needs kernel ≥ 4.9 with BPF enabled; we rely on the binary
        being present as a proxy for a working eBPF environment.
        """
        import platform
        if platform.system() != "Linux":
            logger.info("[dynamic][ebpf] Not Linux — eBPF unavailable")
            return False
        available = shutil.which(tracer) is not None
        if not available:
            logger.info(f"[dynamic][ebpf] {tracer} not found in PATH")
        return available

    async def _get_container_pid(self, container_id: str) -> Optional[int]:
        """Return the host-namespace PID of the container's init process."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format", "{{.State.Pid}}", container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None
        pid_str = stdout.decode("utf-8").strip()
        return int(pid_str) if pid_str.isdigit() and int(pid_str) > 0 else None

    def _build_bpftrace_script(
        self, pid: int, mode: str
    ) -> str:
        """Generate a bpftrace script scoped to the container's PID.

        openat mode (default, portable):
            Traces every file-open syscall in the container process tree.
            We filter matching lines in Python after collection.

        usdt mode (higher fidelity, requires CPython built with --with-dtrace):
            Intercepts Python's function__entry USDT probe, emitting the
            filename and function name for every Python call.
        """
        if mode == "usdt":
            return (
                f"usdt:/proc/{pid}/exe:python:function__entry\n"
                "{{\n"
                '  printf("func:%s:%s\\n", str(arg0), str(arg1));\n'
                "}}\n"
            )
        # openat — trace openat syscalls in the container's PID namespace
        return (
            "tracepoint:syscalls:sys_enter_openat\n"
            f"/pid == {pid}/\n"
            "{{\n"
            '  printf("open:%s\\n", str(args->filename));\n'
            "}}\n"
        )

    async def _start_ebpf_tracer(
        self, pid: int, mode: str, tracer: str
    ) -> Optional[asyncio.subprocess.Process]:
        """Write a bpftrace script to a temp file and start the tracer."""
        script = self._build_bpftrace_script(pid, mode)
        script_path = Path(tempfile.mktemp(suffix=".bt"))
        script_path.write_text(script, encoding="utf-8")

        try:
            proc = await asyncio.create_subprocess_exec(
                tracer, str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            logger.info(
                f"[dynamic][ebpf] Tracer started (pid={pid}, mode={mode}, tracer={tracer})"
            )
            return proc
        except Exception as exc:
            logger.warning(f"[dynamic][ebpf] Failed to start {tracer}: {exc}")
            script_path.unlink(missing_ok=True)
            return None

    async def _collect_ebpf_hits(
        self,
        tracer_proc: asyncio.subprocess.Process,
        vuln_packages: List[str],
    ) -> set[str]:
        """Stop the tracer and return the set of vulnerable package names hit."""
        try:
            tracer_proc.terminate()
            stdout, _ = await asyncio.wait_for(tracer_proc.communicate(), timeout=10)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                tracer_proc.kill()
            except ProcessLookupError:
                pass
            stdout = b""

        output = stdout.decode("utf-8", errors="replace")
        hit_packages: set[str] = set()

        for line in output.splitlines():
            line_lower = line.lower()
            for pkg in vuln_packages:
                import_name = _PYPI_TO_IMPORT.get(pkg.lower(), pkg.lower())
                if len(import_name) >= _MIN_PKG_MATCH_LEN and import_name in line_lower:
                    hit_packages.add(pkg.lower())

        logger.info(f"[dynamic][ebpf] Packages hit: {hit_packages or 'none'}")
        return hit_packages

    async def _build_plain_image(
        self, dockerfile_path: Path, repo_path: Path
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Build the original image without instrumentation (for eBPF mode)."""
        repo_name = repo_path.name.lower().replace(" ", "_")
        image_tag = f"{repo_name}:plain"

        logger.info(f"[dynamic][ebpf] Building plain image {image_tag}")

        proc = await asyncio.create_subprocess_exec(
            "docker", "build",
            "-t", image_tag,
            "-f", str(dockerfile_path),
            str(repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None, {"error": "docker_build_timeout"}

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")[-2000:]
            return None, {"error": "docker_build_failed", "stderr": err}

        return image_tag, {"image_tag": image_tag}

    async def _start_container_plain(
        self, image_tag: str, container_port: int, timeout: int
    ) -> Optional[str]:
        """Start the container without any coverage volume (eBPF mode)."""
        await self._cleanup_port_conflicts(container_port)

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "-p", f"{container_port}:{container_port}",
            image_tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error("[dynamic][ebpf] Timed out starting plain container")
            return None

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            logger.error(f"[dynamic][ebpf] Failed to start container: {err}")
            return None

        container_id = stdout.decode("utf-8").strip()
        logger.info(f"[dynamic][ebpf] Started plain container: {container_id[:12]}")
        return container_id

    async def _run_ebpf_mode(
        self,
        context: "ScanContext",
        repo_path: Path,
        runtime: Any,
        preflight: Dict[str, Any],
    ) -> "AgentResult":
        """Full eBPF tracing flow: no Dockerfile patching, host-side tracing.

        The container is started from the original image.  A bpftrace script
        (scoped to the container's host PID) runs in parallel with Schemathesis
        traffic.  Package hits from the tracer output feed _correlate() directly.
        """
        ebpf_cfg = runtime.ebpf
        dockerfile_path = Path(preflight["dockerfile_path"])
        openapi_path = preflight["openapi_path"]
        container_port = runtime.container_port
        timeout = runtime.timeout

        image_tag, build_meta = await self._build_plain_image(dockerfile_path, repo_path)
        if not image_tag:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "ebpf_image_build",
                    "container_started": {"status": "no", "id": "na"},
                    **build_meta,
                },
            )

        container_id = await self._start_container_plain(image_tag, container_port, timeout)
        if not container_id:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "ebpf_container_start",
                    "container_started": {"status": "no", "id": "na"},
                    "image": image_tag,
                },
            )

        tracer_proc: Optional[asyncio.subprocess.Process] = None
        schemathesis_meta: Dict[str, Any] = {}

        try:
            base_url = f"http://localhost:{container_port}"
            healthy = await self._wait_for_healthy(base_url, timeout=30)
            if not healthy:
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "ebpf_health_check",
                        "container_started": {"status": "no", "id": container_id[:12]},
                    },
                )

            container_pid = await self._get_container_pid(container_id)
            if container_pid:
                tracer_proc = await self._start_ebpf_tracer(
                    container_pid, ebpf_cfg.mode, ebpf_cfg.tracer
                )
            else:
                logger.warning(
                    "[dynamic][ebpf] Could not get container PID — tracing skipped"
                )

            schemathesis_meta = await self._run_schemathesis(
                base_url, openapi_path, container_port, workdir=None
            )

        finally:
            # Collect hits before the container disappears.
            ebpf_hits: set[str] = set()
            if tracer_proc is not None:
                vuln_packages = [
                    (v.get("package") or "").lower()
                    for v in context.vulnerabilities
                    if v.get("package")
                ]
                ebpf_hits = await self._collect_ebpf_hits(tracer_proc, vuln_packages)

            await self._stop_container(container_id)

        findings = self._correlate_from_ebpf(ebpf_hits, context.vulnerabilities)

        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "mode": "ebpf",
                "finding_count": len(findings),
                "container_started": {"status": "yes-running", "id": container_id[:12]},
                "image_tag": image_tag,
                "schemathesis": schemathesis_meta,
                "ebpf": {
                    "tracer": ebpf_cfg.tracer,
                    "mode": ebpf_cfg.mode,
                    "packages_hit": sorted(ebpf_hits),
                },
            },
        })

    def _correlate_from_ebpf(
        self,
        ebpf_hits: "set[str]",
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[ReachabilityFinding]:
        """Build ReachabilityFindings from eBPF hit set.

        Verdicts:
          CONFIRMED 0.85 — package path observed in eBPF tracer output
          LIKELY    0.60 — package not observed (eBPF ran but no hit)
        """
        findings: List[ReachabilityFinding] = []

        for vuln in vulnerabilities:
            pypi_name = (vuln.get("package") or "").lower()
            if not pypi_name:
                continue

            hit = pypi_name in ebpf_hits
            verdict = "CONFIRMED" if hit else "LIKELY"
            confidence = 0.85 if hit else 0.60

            cves = vuln.get("cve_id", [])
            if isinstance(cves, str):
                cves = [cves]
            if not cves:
                cves = [None]

            for cve in cves:
                findings.append(
                    ReachabilityFinding(
                        cve_id=cve,
                        package=vuln.get("package"),
                        import_detected=hit,
                        call_chain_exists=hit,
                        sink_reachable=False,  # eBPF tracks file loads, not sink calls
                        verdict=verdict,
                        confidence=confidence,
                        evidence_type="dynamic",
                        function=None,
                        files=[],
                    )
                )

        return findings