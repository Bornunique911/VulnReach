from pathlib import Path

import yaml


def test_runtime_profile_uses_socket_proxy() -> None:
    path = Path(__file__).resolve().parents[1] / "dev-images" / "docker-compose.runtime.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = data.get("services") or {}

    assert "docker-socket-proxy" in services
    assert "vulnreach" in services

    vulnreach = services["vulnreach"]
    env = set(vulnreach.get("environment") or [])
    assert "VULNREACH_ALLOW_DOCKER_DAEMON=true" in env
    assert "DOCKER_HOST=tcp://docker-socket-proxy:2375" in env

    proxy = services["docker-socket-proxy"]
    proxy_env = set(proxy.get("environment") or [])
    assert "POST=1" in proxy_env
    assert "CONTAINERS=1" in proxy_env
    assert "BUILD=1" in proxy_env
