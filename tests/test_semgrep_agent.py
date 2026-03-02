from agents.agent_semgrep import SemgrepAgent

def test_semgrep_normalize_includes_severity_and_ids():
    agent = SemgrepAgent()
    raw = {
        "results": [
            {
                "check_id": "python.lang.best-practice",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 2},
                "extra": {"severity": "HIGH"},
            },
            {
                "check_id": "js.injection.test",
                "path": "web.js",
                "start": {"line": 10},
                "end": {"line": 12},
                "extra": {"metadata": {"severity": "MEDIUM"}},
            },
        ]
    }

    findings = agent._normalize(raw)
    assert len(findings) == 2
    assert findings[0]["check_id"] == "python.lang.best-practice"
    assert findings[0]["severity"] == "HIGH"
    assert findings[1]["severity"] == "MEDIUM"

