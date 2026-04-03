import asyncio

from agents.agent_dynamic_reachability import DynamicReachabilityAgent
from config.schema import default_config
from core.models import ScanContext


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
