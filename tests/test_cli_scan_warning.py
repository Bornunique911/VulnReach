from unittest.mock import patch
from click.testing import CliRunner
from vulnreach.cli.scan import scan


def _make_scan_data(tools_skipped: dict, tools_errored: dict | None = None) -> dict:
    return {
        "scan_id": "test-123",
        "status": "completed",
        "correlation": [],
        "metadata": {},
        "analysis_coverage": {
            "tools_ran": ["trivy"],
            "tools_skipped": tools_skipped,
            "tools_errored": tools_errored or {},
            "evidence_layers": {
                "sca": True,
                "taint": "tainter" not in tools_skipped,
                "ast": "python_reachability" not in tools_skipped,
                "route": False,
                "runtime": False,
            },
        },
    }


def _run_scan(scan_data: dict) -> str:
    runner = CliRunner()
    with patch("vulnreach.local.run_local_scan", return_value=scan_data):
        result = runner.invoke(scan, ["--repo-path", "/tmp/fake"], obj={"mode": "local"})
    return result.output


def test_partial_analysis_warning_shown_when_tools_skipped():
    """Warning block must appear when tools were skipped."""
    data = _make_scan_data({"tainter": "not installed", "dynamic_reachability": "runtime disabled"})
    output = _run_scan(data)
    assert "Partial analysis" in output
    assert "tainter" in output
    assert "dynamic_reachability" in output


def test_no_warning_when_all_tools_ran():
    """No warning block when tools_skipped and tools_errored are both empty."""
    data = _make_scan_data({})
    output = _run_scan(data)
    assert "Partial analysis" not in output


def test_errored_tools_shown_in_warning():
    """Errored tools must appear in the warning block."""
    data = _make_scan_data({}, tools_errored={"semgrep": "timeout"})
    output = _run_scan(data)
    assert "Partial analysis" in output
    assert "semgrep" in output


def test_missing_layers_shown_in_warning():
    """Missing evidence layers must be listed in the warning."""
    data = _make_scan_data({"tainter": "not installed"})
    output = _run_scan(data)
    assert "taint" in output or "Missing layers" in output


def test_no_analysis_coverage_key_no_crash():
    """When analysis_coverage is absent (old scan format), no warning and no crash."""
    data = {
        "scan_id": "old-scan-456",
        "status": "completed",
        "correlation": [],
        "metadata": {},
    }
    output = _run_scan(data)
    assert "Partial analysis" not in output
