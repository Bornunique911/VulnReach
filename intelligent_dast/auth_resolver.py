"""Resolve authentication headers and cookies for DAST probing.

Supports two credential sources (merged, script wins on conflict):
  1. Static — hardcoded headers/cookies from YAML config
  2. Script — subprocess command whose stdout provides credentials

No external dependencies beyond PyYAML (already a project dep).
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# Script output is cached for this many seconds to avoid repeated subprocess calls
_CACHE_TTL_SECONDS = 300  # 5 minutes


class AuthResolutionError(Exception):
    """Raised when credential resolution fails."""


class AuthResolver:
    """Resolve auth headers and cookies from a YAML config file."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._config: Dict[str, Any] = {}
        if config_path:
            self._config = self._load_config(config_path)

        # Script result cache: (headers, cookies, timestamp)
        self._script_cache: Optional[Tuple[Dict[str, str], Dict[str, str], float]] = None

    def resolve(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Return merged (headers, cookies) from static + script sources.

        Script values take precedence over static on key conflicts.
        Returns ({}, {}) if no config was provided.
        """
        if not self._config:
            return {}, {}

        static_headers, static_cookies = self._load_static()
        script_headers, script_cookies = self._run_script()

        # Merge: script wins on conflict
        headers = {**static_headers, **script_headers}
        cookies = {**static_cookies, **script_cookies}

        return headers, cookies

    # ------------------------------------------------------------------
    # Static credentials
    # ------------------------------------------------------------------

    def _load_static(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Extract static headers and cookies from config."""
        static = self._config.get("static") or {}
        headers = static.get("headers") or {}
        cookies = static.get("cookies") or {}
        return dict(headers), dict(cookies)

    # ------------------------------------------------------------------
    # Script-based credentials
    # ------------------------------------------------------------------

    def _run_script(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Run the configured script command and parse its output.

        Returns cached result if within TTL. Returns ({}, {}) if no
        script is configured.

        Raises:
            AuthResolutionError: If the script fails or output is unparseable.
        """
        script_cfg = self._config.get("script")
        if not script_cfg:
            return {}, {}

        # Check cache
        if self._script_cache is not None:
            _, _, cached_at = self._script_cache
            if time.monotonic() - cached_at < _CACHE_TTL_SECONDS:
                return self._script_cache[0], self._script_cache[1]

        command = script_cfg.get("command")
        if not command:
            return {}, {}

        timeout = script_cfg.get("timeout_seconds", 10)
        output_format = (script_cfg.get("output_format") or "json").lower()

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise AuthResolutionError(
                f"Auth script timed out after {timeout}s: {command}"
            )
        except OSError as exc:
            raise AuthResolutionError(
                f"Auth script failed to execute: {command} — {exc}"
            )

        if result.returncode != 0:
            raise AuthResolutionError(
                f"Auth script exited with code {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )

        stdout = result.stdout.strip()
        if not stdout:
            raise AuthResolutionError("Auth script produced empty output")

        if output_format == "json":
            headers, cookies = self._parse_json_output(stdout)
        elif output_format == "env":
            headers, cookies = self._parse_env_output(stdout)
        else:
            raise AuthResolutionError(
                f"Unknown output_format '{output_format}' — expected 'json' or 'env'"
            )

        # Cache the result
        self._script_cache = (headers, cookies, time.monotonic())
        logger.info(f"[auth_resolver] Script credentials cached ({len(headers)} headers, {len(cookies)} cookies)")
        return headers, cookies

    # ------------------------------------------------------------------
    # Output parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json_output(stdout: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Parse JSON output: {"headers": {...}, "cookies": {...}}"""
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AuthResolutionError(
                f"Auth script JSON parse failed: {exc} — output: {stdout[:200]}"
            )

        if not isinstance(data, dict):
            raise AuthResolutionError(
                f"Auth script JSON must be an object, got {type(data).__name__}"
            )

        headers = data.get("headers") or {}
        cookies = data.get("cookies") or {}

        if not isinstance(headers, dict) or not isinstance(cookies, dict):
            raise AuthResolutionError(
                "Auth script JSON 'headers' and 'cookies' must be objects"
            )

        return {str(k): str(v) for k, v in headers.items()}, {str(k): str(v) for k, v in cookies.items()}

    @staticmethod
    def _parse_env_output(stdout: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Parse env-style output.

        Lines starting with HEADER_ become headers:
            HEADER_AUTHORIZATION=Bearer xyz  →  Authorization: Bearer xyz
        Lines starting with COOKIE_ become cookies:
            COOKIE_SESSIONID=abc123  →  sessionid: abc123
        """
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

        for line in stdout.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if key.startswith("HEADER_"):
                # HEADER_AUTHORIZATION → Authorization
                header_name = key[7:].replace("_", "-").title()
                headers[header_name] = value
            elif key.startswith("COOKIE_"):
                # COOKIE_SESSIONID → sessionid
                cookie_name = key[7:].lower()
                cookies[cookie_name] = value

        return headers, cookies

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_config(config_path: str) -> Dict[str, Any]:
        """Load and validate the YAML auth config file."""
        path = Path(config_path)
        if not path.exists():
            raise AuthResolutionError(f"Auth config file not found: {config_path}")

        try:
            text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(text)
        except Exception as exc:
            raise AuthResolutionError(
                f"Failed to parse auth config {config_path}: {exc}"
            )

        if not isinstance(data, dict):
            raise AuthResolutionError(
                f"Auth config must be a YAML mapping, got {type(data).__name__}"
            )

        return data
