"""Resolve authentication headers and cookies for DAST probing.

Supports two credential sources (merged, script wins on conflict):
  1. Static — hardcoded headers/cookies from YAML config
  2. Script — subprocess command whose stdout provides credentials

No external dependencies beyond PyYAML (already a project dep).
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

        timeout = self._parse_timeout(script_cfg.get("timeout_seconds", 10))
        output_format = (script_cfg.get("output_format") or "json").lower()
        argv = self._parse_command(command)

        try:
            result = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise AuthResolutionError(
                f"Auth script timed out after {timeout}s: {argv[0]}"
            )
        except OSError as exc:
            raise AuthResolutionError(
                f"Auth script failed to execute: {argv[0]} — {exc}"
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

    @staticmethod
    def _parse_timeout(value: Any) -> int:
        """Parse and validate timeout_seconds from config."""
        try:
            timeout = int(value)
        except (TypeError, ValueError):
            raise AuthResolutionError(f"Invalid timeout_seconds value: {value!r}")
        if timeout < 1 or timeout > 300:
            raise AuthResolutionError("timeout_seconds must be between 1 and 300")
        return timeout

    @staticmethod
    def _parse_command(command: Any) -> List[str]:
        """Parse and validate script command as argv (no shell interpolation)."""
        argv: List[str]
        if isinstance(command, str):
            cmd = command.strip()
            if not cmd:
                return []
            try:
                argv = shlex.split(cmd, posix=True)
            except ValueError as exc:
                raise AuthResolutionError(f"Auth script command parse failed: {exc}")
        elif isinstance(command, list):
            argv = []
            for idx, item in enumerate(command):
                if not isinstance(item, str):
                    raise AuthResolutionError(
                        f"Auth script command item at index {idx} must be a string"
                    )
                part = item.strip()
                if not part:
                    raise AuthResolutionError(
                        f"Auth script command item at index {idx} is empty"
                    )
                argv.append(part)
        else:
            raise AuthResolutionError(
                "Auth script command must be a string or list of strings"
            )

        if not argv:
            raise AuthResolutionError("Auth script command is empty")

        executable = argv[0]
        has_path_sep = (os.path.sep and os.path.sep in executable) or (
            os.path.altsep and os.path.altsep in executable
        )
        if has_path_sep:
            exe_path = Path(executable).expanduser()
            if not exe_path.is_absolute():
                exe_path = (Path.cwd() / exe_path).resolve()
            if not exe_path.exists() or not exe_path.is_file():
                raise AuthResolutionError(f"Auth script executable not found: {executable}")
            if not os.access(exe_path, os.X_OK):
                raise AuthResolutionError(f"Auth script executable is not runnable: {executable}")
            argv[0] = str(exe_path)
        else:
            resolved = shutil.which(executable)
            if not resolved:
                raise AuthResolutionError(f"Auth script executable not found on PATH: {executable}")
            argv[0] = resolved

        return argv

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
