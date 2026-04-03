import json
import os
from pathlib import Path
from typing import Dict

import pytest

from agents.reachability.agent_bridge import MultiLanguageReachabilityBridge
from agents.reachability.multi_language_analyzer import ProjectLanguageDetector
import agents.reachability.agent_bridge as bridge_module


FIXTURES = Path(__file__).parent / "fixtures" / "languages"
_CASES = [
    ("java", "java", "org.apache.logging.log4j:log4j-core", "CVE-2021-44228"),
    ("javascript", "javascript", "lodash", "CVE-2021-23337"),
    ("go", "go", "gopkg.in/yaml.v2", "CVE-2019-11254"),
]
_FILTER = (os.getenv("VULNREACH_FIXTURE_LANGUAGE") or "").strip().lower()
if _FILTER:
    _CASES = [c for c in _CASES if c[0] == _FILTER]


@pytest.mark.parametrize("fixture_name, expected_language, _pkg, _cve", _CASES)
def test_fixture_language_detection(
    fixture_name: str,
    expected_language: str,
    _pkg: str,
    _cve: str,
) -> None:
    repo = FIXTURES / fixture_name
    detected = ProjectLanguageDetector(str(repo)).detect_languages()
    assert expected_language in detected


@pytest.mark.parametrize("fixture_name, expected_language, package, cve_id", _CASES)
def test_bridge_maps_language_fixtures(
    fixture_name: str,
    expected_language: str,
    package: str,
    cve_id: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = FIXTURES / fixture_name

    def _fake_multi_language_analysis(
        project_root: str,
        consolidated_path: str,
        output_dir: str = None,
        languages=None,
    ):
        assert Path(project_root).resolve() == repo.resolve()
        assert Path(consolidated_path).exists()
        out = Path(output_dir or "security_findings")
        out.mkdir(parents=True, exist_ok=True)
        report = {
            "language": expected_language,
            "analyses": [
                {
                    "package_name": package,
                    "is_used": True,
                    "call_chain_graph": "graph TD; A-->B;",
                    "usage_contexts": [
                        {
                            "file_path": f"{fixture_name}/entry.file",
                            "line_number": 7,
                            "enclosing_scope": "entry",
                        }
                    ],
                }
            ],
        }
        report_path = out / f"{expected_language}_vulnerability_reachability_report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return [expected_language]

    monkeypatch.setattr(
        bridge_module,
        "run_multi_language_analysis",
        _fake_multi_language_analysis,
    )

    bridge = MultiLanguageReachabilityBridge()
    result: Dict[str, object] = bridge.run_sync(
        project_root=str(repo),
        consolidated_path=None,
        output_dir=str(tmp_path),
        vulnerabilities=[
            {
                "package": package,
                "cve_id": [cve_id],
                "severity": "HIGH",
            }
        ],
    )

    assert result.get("tool_name") == "multi_language_reachability"
    findings = result.get("findings") or []
    metadata = result.get("metadata") or {}
    assert metadata.get("status") == "ok"
    assert expected_language in (metadata.get("languages") or [])
    assert len(findings) >= 1
    assert any(
        f.get("cve_id") == cve_id and f.get("package") == package
        for f in findings
        if isinstance(f, dict)
    )
