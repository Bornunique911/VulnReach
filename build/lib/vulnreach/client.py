"""
VulnReachClient — thin synchronous HTTP client for the VulnReach API.
Used by CLI commands when --url / VULNREACH_URL is set (client mode).
"""

import os
import time
from typing import Any, Dict, List, Optional

import click
import requests


class VulnReachClient:
    def __init__(self, url: str, token: Optional[str] = None) -> None:
        self.url = url.rstrip("/")
        self.token = token

    def _headers(self) -> Dict[str, str]:
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _raise(self, resp: requests.Response) -> None:
        if not resp.ok:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise click.ClickException(f"API error {resp.status_code}: {detail}")

    def login(self, username: str, password: str) -> str:
        resp = requests.post(
            f"{self.url}/login",
            json={"username": username, "password": password},
            timeout=15,
        )
        self._raise(resp)
        token = resp.json().get("access_token") or resp.json().get("token")
        if not token:
            raise click.ClickException("Login succeeded but no token returned")
        self.token = token
        return token

    def ensure_auth(self) -> None:
        """Auto-login from env vars if no token present."""
        if self.token:
            return
        username = os.getenv("VULNREACH_USERNAME")
        password = os.getenv("VULNREACH_PASSWORD")
        if username and password:
            self.login(username, password)
            return
        raise click.ClickException(
            "No auth token. Set VULNREACH_TOKEN or VULNREACH_USERNAME + VULNREACH_PASSWORD."
        )

    def start_scan(
        self,
        repo_path: Optional[str] = None,
        repo_url: Optional[str] = None,
        config_path: Optional[str] = None,
        tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        self.ensure_auth()
        payload: Dict[str, Any] = {}
        if repo_path:
            payload["repo_path"] = repo_path
        if repo_url:
            payload["repo_url"] = repo_url
        if config_path:
            payload["config_path"] = config_path
        if tools:
            payload["tools"] = tools
        resp = requests.post(
            f"{self.url}/scan",
            json=payload,
            headers=self._headers(),
            timeout=30,
        )
        self._raise(resp)
        return resp.json()

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        self.ensure_auth()
        resp = requests.get(
            f"{self.url}/scan/{scan_id}",
            headers=self._headers(),
            timeout=30,
        )
        self._raise(resp)
        return resp.json()

    def poll_scan(self, scan_id: str, interval: int = 10) -> Dict[str, Any]:
        """Block until the scan reaches a terminal status, then return its data."""
        terminal = {"completed", "blocked", "partial", "failed"}
        while True:
            data = self.get_scan(scan_id)
            if data.get("status") in terminal:
                return data
            time.sleep(interval)

    def get_fix_plan(self, scan_id: str) -> Dict[str, Any]:
        self.ensure_auth()
        resp = requests.get(
            f"{self.url}/scan/{scan_id}/fix-plan",
            headers=self._headers(),
            timeout=30,
        )
        self._raise(resp)
        return resp.json()

    def get_graph(self, scan_id: str, cve: str) -> Dict[str, Any]:
        self.ensure_auth()
        resp = requests.get(
            f"{self.url}/scan/{scan_id}/graph/{cve}",
            headers=self._headers(),
            timeout=30,
        )
        self._raise(resp)
        return resp.json()

    def get_explanation(self, scan_id: str, cve: str, provider: str = "none") -> Dict[str, Any]:
        self.ensure_auth()
        resp = requests.get(
            f"{self.url}/scan/{scan_id}/explain/{cve}",
            params={"provider": provider},
            headers=self._headers(),
            timeout=60,
        )
        self._raise(resp)
        return resp.json()
