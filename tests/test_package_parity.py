import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

import requests

from core.orchestrator import Orchestrator
from vulnreach.client import VulnReachClient
from vulnreach.local import run_local_scan


@dataclass
class _Repo:
    scans: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    raw: Dict[tuple[str, str], Dict[str, Any]] = field(default_factory=dict)

    def create_scan(self, status: str = "started", metadata: Optional[Dict[str, Any]] = None) -> str:
        scan_id = str(uuid.uuid4())
        self.scans[scan_id] = {
            "scan_id": scan_id,
            "status": status,
            "metadata": metadata or {},
            "vulnerabilities": [],
            "reachability": [],
            "correlation": [],
            "raw": {},
            "semgrep_findings": [],
            "routes": [],
        }
        return scan_id

    def update_scan_status(self, scan_id: str, status: str) -> None:
        self.scans[scan_id]["status"] = status

    def store_vulnerabilities(self, scan_id: str, vulns: List[Dict[str, Any]]) -> None:
        self.scans[scan_id]["vulnerabilities"] = list(vulns)

    def store_reachability(self, scan_id: str, evidence: List[Dict[str, Any]]) -> None:
        self.scans[scan_id]["reachability"] = list(evidence)

    def store_correlation(self, scan_id: str, results: List[Dict[str, Any]]) -> None:
        self.scans[scan_id]["correlation"] = list(results)

    def store_raw_output(self, scan_id: str, tool_name: str, payload: Dict[str, Any]) -> None:
        self.raw[(scan_id, tool_name)] = dict(payload)
        self.scans[scan_id]["raw"][tool_name] = dict(payload)

    def store_semgrep_findings(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        self.scans[scan_id]["semgrep_findings"] = list(findings)

    def store_routes(self, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        self.scans[scan_id]["routes"] = list(findings)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self.scans.get(scan_id)

    # auth helpers used by api.auth path
    def get_user_by_username(self, username: str):
        if username == "admin":
            from api.auth import hash_password
            return {
                "id": "user-1",
                "username": "admin",
                "password_hash": hash_password("changeme"),
                "role": "admin",
            }
        return None

    def get_user_for_api_key(self, key_hash: str):
        return None

    def touch_api_key_last_used(self, key_id: str):
        return None


async def _fake_execute_scan(self, scan_id: str, repo_path: str, config_path: str, config: Any, repo_url: str | None):
    _populate_scan(self.storage, scan_id)


def _populate_scan(storage: _Repo, scan_id: str) -> None:
    storage.store_vulnerabilities(
        scan_id,
        [{"package": "demo-lib", "cve_id": ["CVE-2024-0001"], "severity": "HIGH", "version": "1.0.0", "fix_version": "1.0.1"}],
    )
    storage.store_correlation(
        scan_id,
        [
            {
                "cve_id": "CVE-2024-0001",
                "package": "demo-lib",
                "verdict": "CONFIRMED",
                "reachability_class": "DYNAMICALLY_REACHABLE",
                "evidence": {"reachability_class": "DYNAMICALLY_REACHABLE"},
            },
            {
                "cve_id": "CVE-2024-0002",
                "package": "demo-lib-2",
                "verdict": "NOT_OBSERVED",
                "reachability_class": "NOT_REACHABLE",
                "evidence": {"reachability_class": "NOT_REACHABLE"},
            },
        ],
    )
    storage.update_scan_status(scan_id, "completed")


class _Resp:
    def __init__(self, status_code: int, payload: Dict[str, Any]):
        self.status_code = status_code
        self._payload = payload
        self.ok = 200 <= status_code < 300
        self.text = str(payload)

    def json(self):
        return self._payload


def test_package_local_and_client_modes_return_parity(monkeypatch):
    repo = _Repo()

    import storage
    monkeypatch.setattr(storage, "get_repository", lambda: repo)
    monkeypatch.setattr(Orchestrator, "execute_scan", _fake_execute_scan)

    local_scan = run_local_scan(repo_path=".", config_path=None, tools=["trivy"])
    assert local_scan["summary"]["total"] == 2
    assert local_scan["summary"]["dynamically_reachable"] == 1
    assert local_scan["summary"]["not_reachable"] == 1

    app = FastAPI()

    @app.post("/login")
    def _login(payload: Dict[str, Any]):
        if payload.get("username") == "admin" and payload.get("password") == "changeme":
            return {"access_token": "test-token", "token_type": "bearer"}
        return {"detail": "Invalid credentials"}

    @app.post("/scan")
    def _start_scan(payload: Dict[str, Any]):
        scan_id = repo.create_scan(status="started", metadata=payload)
        _populate_scan(repo, scan_id)
        return {"scan_id": scan_id, "status": "started"}

    @app.get("/scan/{scan_id}")
    def _get_scan(scan_id: str):
        from vulnreach.scan_response import augment_scan_response
        scan = repo.get_scan(scan_id) or {}
        return {"scan_id": scan_id, **augment_scan_response(scan)}

    tc = TestClient(app)

    def _request(method: str, url: str, **kwargs):
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        resp = tc.request(
            method=method,
            url=path,
            headers=kwargs.get("headers"),
            json=kwargs.get("json"),
            params=kwargs.get("params"),
            data=kwargs.get("data"),
        )
        payload = resp.json() if resp.content else {}
        return _Resp(resp.status_code, payload)

    monkeypatch.setattr(requests, "request", _request)

    client = VulnReachClient("http://test")
    client.login("admin", "changeme")
    started = client.start_scan(repo_url="https://example.invalid/repo")
    client_scan = client.poll_scan(started["scan_id"], interval=0)

    assert client_scan["summary"] == local_scan["summary"]
    assert len(client_scan["dynamically_reachable"]) == len(local_scan["dynamically_reachable"])
    assert len(client_scan["not_reachable"]) == len(local_scan["not_reachable"])
