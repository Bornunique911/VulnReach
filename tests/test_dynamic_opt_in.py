import asyncio
from pathlib import Path

from agents.agent_dynamic_reachability import DynamicReachabilityAgent, _safe_compose_project_name
from config.schema import default_config
from core.models import ScanContext


def test_compose_project_name_is_safe_for_temp_clone_suffix():
    name = _safe_compose_project_name(Path("/tmp/vulnreach-multi-tier-dvpa-803zldc_"))

    assert name == "vulnreach-multi-tier-dvpa-803zldc"
    assert name[-1].isalnum()
    assert "_" not in name


def test_dynamic_scan_requires_docker_daemon_opt_in(tmp_path, monkeypatch):
    config = default_config()
    config.scan.runtime.enabled = True

    monkeypatch.delenv("VULNREACH_ALLOW_DOCKER_DAEMON", raising=False)

    context = ScanContext(repo_path=str(tmp_path), config=config)
    result = asyncio.run(DynamicReachabilityAgent().run(context))

    assert result.metadata.get("status") == "skipped"
    assert "VULNREACH_ALLOW_DOCKER_DAEMON" in str(result.metadata.get("reason", ""))


def test_dynamic_scan_continues_past_opt_in_gate_when_enabled(tmp_path, monkeypatch):
    config = default_config()
    config.scan.runtime.enabled = True

    monkeypatch.setenv("VULNREACH_ALLOW_DOCKER_DAEMON", "true")

    context = ScanContext(repo_path=str(tmp_path), config=config)
    result = asyncio.run(DynamicReachabilityAgent().run(context))

    # No Dockerfile/OpenAPI in tmp repo, so this should skip in preflight
    # rather than at the daemon opt-in gate.
    assert result.metadata.get("status") == "skipped"
    assert "VULNREACH_ALLOW_DOCKER_DAEMON" not in str(result.metadata.get("reason", ""))
