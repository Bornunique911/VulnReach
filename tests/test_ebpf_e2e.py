"""
eBPF end-to-end pipeline test.

Validates the full path:
  vulnerable target app
    → eBPF sidecar (non-invasive, no Dockerfile patching)
      → coverage_normaliser (NormalisedCoverage → coverage.py format)
        → correlator (_correlate)
          → DYNAMICALLY_REACHABLE verdict for exercised packages
          → lower verdict for installed-but-never-called packages

Skip conditions (checked at collection time):
  - Not Linux
  - bpftrace not in PATH
  - docker / docker compose not available
  - eBPF dry-run probe fails (kernel too old or Docker Desktop / LinuxKit)

Run manually:
  cd labs/ebpf-e2e && docker compose up -d --build --wait
  VULNREACH_ALLOW_DOCKER_DAEMON=true pytest tests/test_ebpf_e2e.py -v
  cd labs/ebpf-e2e && docker compose down
"""

import asyncio
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ── Skip guards ──────────────────────────────────────────────────────────────

def _bpftrace_dry_run() -> bool:
    """Return True if bpftrace can attach a tracepoint on this kernel."""
    try:
        result = subprocess.run(
            ["bpftrace", "-e", "tracepoint:syscalls:sys_enter_openat { exit(); }"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _ebpf_available() -> bool:
    if platform.system() != "Linux":
        return False
    if shutil.which("bpftrace") is None:
        return False
    if shutil.which("docker") is None:
        return False
    if not os.environ.get("VULNREACH_ALLOW_DOCKER_DAEMON"):
        return False
    return _bpftrace_dry_run()


requires_ebpf = pytest.mark.skipif(
    not _ebpf_available(),
    reason=(
        "eBPF E2E requires: Linux, bpftrace in PATH, docker available, "
        "VULNREACH_ALLOW_DOCKER_DAEMON=true, and kernel ≥4.9 with tracepoint support"
    ),
)

# ── Fixtures ─────────────────────────────────────────────────────────────────

LAB_DIR = Path(__file__).parent.parent / "labs" / "ebpf-e2e"
TARGET_PORT = 5001
TARGET_URL = f"http://localhost:{TARGET_PORT}"


def _wait_for_target(timeout: int = 30) -> bool:
    """Poll until the target app responds on /health."""
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{TARGET_URL}/health", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


@pytest.fixture(scope="module")
def ebpf_target():
    """Start the ebpf-e2e target via docker compose and tear it down after."""
    subprocess.run(
        ["docker", "compose", "up", "-d", "--build"],
        cwd=LAB_DIR,
        check=True,
        capture_output=True,
    )
    ready = _wait_for_target(timeout=60)
    if not ready:
        subprocess.run(["docker", "compose", "down", "--remove-orphans"], cwd=LAB_DIR)
        pytest.fail("Target app did not become healthy within 60s")

    yield TARGET_URL

    subprocess.run(
        ["docker", "compose", "down", "--remove-orphans"],
        cwd=LAB_DIR,
        capture_output=True,
    )


# ── Known vulnerabilities injected into the scan context ─────────────────────

_VULNS: List[Dict[str, Any]] = [
    {
        # pyyaml IS called at runtime via /parse
        "package": "PyYAML",
        "cve_id": ["CVE-2020-14343"],
        "severity": "CRITICAL",
        "version": "5.3.1",
        "fix_version": "6.0",
    },
    {
        # werkzeug is imported by Flask but not directly called in our app code
        "package": "Werkzeug",
        "cve_id": ["CVE-2023-46136"],
        "severity": "HIGH",
        "version": "2.3.7",
        "fix_version": "3.0.1",
    },
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_scan_config(compose_path: str, target_service: str = "target") -> Any:
    """Build a minimal ScanConfig with eBPF sidecar mode enabled."""
    from config.schema import (
        EbpfSettings,
        IntelligentDastSettings,
        OpenAPIGeneratorSettings,
        PolicySettings,
        RiskSettings,
        RuntimeSettings,
        ScanConfig,
        ScanSettings,
    )

    return ScanConfig(
        scan=ScanSettings(
            tools=["dynamic_reachability"],
            runtime=RuntimeSettings(
                enabled=True,
                timeout=120,
                coverage_wait=20,
                container_port=TARGET_PORT,
                ebpf=EbpfSettings(
                    enabled=True,
                    mode="usdt",
                    sidecar_mode=True,
                    language="python",
                ),
            ),
            openapi_generator=OpenAPIGeneratorSettings(enabled=False),
            intelligent_dast=IntelligentDastSettings(enabled=False),
        ),
        risk=RiskSettings(exposure="public", data_sensitivity="high"),
        policy=PolicySettings(block_if=[]),
    )


def _get_reachability_class(findings: list, cve_id: str) -> str | None:
    for f in findings:
        ids = f.get("cve_id") if isinstance(f.get("cve_id"), list) else [f.get("cve_id")]
        if cve_id in (ids or []):
            return f.get("reachability_class")
    return None


# ── Tests ─────────────────────────────────────────────────────────────────────

@requires_ebpf
class TestEbpfSidecarE2E:
    """Full pipeline tests using the eBPF sidecar (non-invasive, no Dockerfile patching)."""

    def test_target_is_healthy(self, ebpf_target):
        """Sanity check — target app responds before we start tracing."""
        import urllib.request
        resp = urllib.request.urlopen(f"{ebpf_target}/health", timeout=5)
        assert resp.status == 200

    def test_pyyaml_is_dynamically_reachable(self, ebpf_target):
        """pyyaml is called on every /parse request — must be DYNAMICALLY_REACHABLE."""
        from agents.agent_dynamic_reachability import DynamicReachabilityAgent
        from core.models import ScanContext
        from correlation.service import CorrelationService

        compose_path = str(LAB_DIR / "docker-compose.yml")
        config = _build_scan_config(compose_path, target_service="target")

        context = ScanContext(
            repo_path=str(LAB_DIR / "target"),
            scan_id="ebpf-e2e-pyyaml",
            config=config,
            vulnerabilities=_VULNS,
        )

        agent = DynamicReachabilityAgent()
        result = asyncio.get_event_loop().run_until_complete(agent.run(context))

        assert result is not None, "Agent returned no result"
        assert result.metadata.get("mode") in ("ebpf_sidecar", "ebpf"), (
            f"Expected eBPF mode, got: {result.metadata.get('mode')}"
        )

        svc = CorrelationService()
        corr = svc.correlate(
            vulnerabilities=_VULNS,
            static_reachability={},
            dynamic_reachability={
                (f["package"].lower(), cve): f
                for f in result.findings
                for cve in (
                    [f["cve_id"]] if isinstance(f.get("cve_id"), str) else (f.get("cve_id") or [])
                )
            },
            exposure="public",
        )

        pyyaml_class = _get_reachability_class(corr["correlation"], "CVE-2020-14343")
        assert pyyaml_class == "DYNAMICALLY_REACHABLE", (
            f"pyyaml CVE-2020-14343 expected DYNAMICALLY_REACHABLE, got {pyyaml_class}. "
            f"eBPF metadata: {result.metadata.get('ebpf', {})}"
        )

    def test_unused_package_not_dynamically_reachable(self, ebpf_target):
        """Werkzeug is imported by Flask but not directly called — must not be DYNAMICALLY_REACHABLE."""
        from agents.agent_dynamic_reachability import DynamicReachabilityAgent
        from core.models import ScanContext
        from correlation.service import CorrelationService

        compose_path = str(LAB_DIR / "docker-compose.yml")
        config = _build_scan_config(compose_path, target_service="target")

        context = ScanContext(
            repo_path=str(LAB_DIR / "target"),
            scan_id="ebpf-e2e-werkzeug",
            config=config,
            vulnerabilities=_VULNS,
        )

        agent = DynamicReachabilityAgent()
        result = asyncio.get_event_loop().run_until_complete(agent.run(context))

        svc = CorrelationService()
        corr = svc.correlate(
            vulnerabilities=_VULNS,
            static_reachability={},
            dynamic_reachability={
                (f["package"].lower(), cve): f
                for f in result.findings
                for cve in (
                    [f["cve_id"]] if isinstance(f.get("cve_id"), str) else (f.get("cve_id") or [])
                )
            },
            exposure="public",
        )

        werkzeug_class = _get_reachability_class(corr["correlation"], "CVE-2023-46136")
        assert werkzeug_class != "DYNAMICALLY_REACHABLE", (
            f"Werkzeug CVE-2023-46136 should not be DYNAMICALLY_REACHABLE — "
            f"got {werkzeug_class}"
        )

    def test_ebpf_metadata_present(self, ebpf_target):
        """Agent result must include eBPF metadata with runtime and file_count."""
        from agents.agent_dynamic_reachability import DynamicReachabilityAgent
        from core.models import ScanContext

        compose_path = str(LAB_DIR / "docker-compose.yml")
        config = _build_scan_config(compose_path, target_service="target")

        context = ScanContext(
            repo_path=str(LAB_DIR / "target"),
            scan_id="ebpf-e2e-meta",
            config=config,
            vulnerabilities=_VULNS,
        )

        agent = DynamicReachabilityAgent()
        result = asyncio.get_event_loop().run_until_complete(agent.run(context))

        ebpf_meta = result.metadata.get("ebpf", {})
        assert ebpf_meta.get("runtime") == "python", (
            f"Expected runtime=python, got: {ebpf_meta}"
        )
        assert ebpf_meta.get("file_count", 0) > 0, (
            f"Expected at least one file traced, got file_count=0. "
            f"Full metadata: {result.metadata}"
        )


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="probe_router uses /proc — Linux only",
)
class TestEbpfProbeSelection:
    """Unit-level tests for probe selection logic — no bpftrace or kernel required."""

    def test_python_probe_selected(self):
        """probe_router must select a viable probe for Python (USDT if available, else uprobe)."""
        from agents.ebpf.probe_router import select_probe
        # PID 1 is always present; use it as a stand-in (we test selection, not attachment)
        probe = select_probe(runtime="python", pid=1)
        assert not probe.skip, f"No viable Python probe found: {probe.skip_reason}"
        # Accept any mechanism — USDT on real Linux, uprobe/openat on older kernels
        assert probe.bpftrace_script, "Probe config must include a bpftrace script"

    def test_openat_fallback_always_available(self):
        """openat mode must always produce a valid probe config on Linux."""
        from agents.ebpf.probe_router import select_probe
        probe = select_probe(runtime="generic", pid=1)
        assert not probe.skip, f"openat fallback skipped: {probe.skip_reason}"
        assert "openat" in probe.bpftrace_script
