import sys
from pathlib import Path

import pytest

from intelligent_dast.auth_resolver import AuthResolutionError, AuthResolver


def test_auth_script_command_list_executes_without_shell(tmp_path: Path) -> None:
    cfg_path = tmp_path / "auth.yml"
    cfg_path.write_text(
        "\n".join(
            [
                "script:",
                "  command:",
                f"    - {sys.executable}",
                '    - -c',
                '    - import json; print(json.dumps({"headers":{"Authorization":"Bearer test-token"}}))',
                "  output_format: json",
                "  timeout_seconds: 5",
            ]
        ),
        encoding="utf-8",
    )

    resolver = AuthResolver(str(cfg_path))
    headers, cookies = resolver.resolve()

    assert headers == {"Authorization": "Bearer test-token"}
    assert cookies == {}


def test_auth_script_command_must_be_string_or_list(tmp_path: Path) -> None:
    cfg_path = tmp_path / "auth.yml"
    cfg_path.write_text(
        "\n".join(
            [
                "script:",
                "  command:",
                "    key: value",
                "  output_format: json",
            ]
        ),
        encoding="utf-8",
    )

    resolver = AuthResolver(str(cfg_path))
    with pytest.raises(AuthResolutionError):
        resolver.resolve()


def test_auth_script_timeout_bounds(tmp_path: Path) -> None:
    cfg_path = tmp_path / "auth.yml"
    cfg_path.write_text(
        "\n".join(
            [
                "script:",
                "  command:",
                f"    - {sys.executable}",
                "    - -c",
                "    - print('{}')",
                "  output_format: json",
                "  timeout_seconds: 0",
            ]
        ),
        encoding="utf-8",
    )

    resolver = AuthResolver(str(cfg_path))
    with pytest.raises(AuthResolutionError):
        resolver.resolve()
