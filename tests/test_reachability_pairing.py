from correlation.service import CorrelationService


def test_correlation_uses_package_and_cve_pair() -> None:
    service = CorrelationService()

    vulnerabilities = [
        {"package": "pkg-one", "cve_id": ["CVE-2026-0001"], "severity": "HIGH"},
        {"package": "pkg-two", "cve_id": ["CVE-2026-0001"], "severity": "HIGH"},
    ]

    static_reachability = {
        ("pkg-one", "CVE-2026-0001"): {
            "import_detected": True,
            "call_chain_exists": True,
            "sink_reachable": False,
            "evidence_type": "static",
            "confidence": 0.7,
            "function": "doWork",
            "files": ["app.py"],
        }
    }

    result = service.correlate(
        vulnerabilities=vulnerabilities,
        static_reachability=static_reachability,
        dynamic_reachability={},
        exposure="public",
        policy_rules=[],
        semgrep_findings=[],
        dast_findings=[],
    )

    findings = {
        (f.get("package"), f.get("cve_id")): f
        for f in result["correlation"]
        if f.get("package")
    }

    one = findings[("pkg-one", "CVE-2026-0001")]
    two = findings[("pkg-two", "CVE-2026-0001")]

    assert one["reachability_class"] == "STATICALLY_REACHABLE"
    assert one["verdict"] in {"LIKELY", "POSSIBLE"}
    assert two["reachability_class"] == "NOT_REACHABLE"
    assert two["verdict"] == "NOT_OBSERVED"
