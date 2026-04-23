from vulnreach.scan_response import augment_scan_response


def test_augment_scan_response_adds_summary_and_buckets() -> None:
    scan = {
        "status": "completed",
        "correlation": [
            {"cve_id": "CVE-1", "reachability_class": "DYNAMICALLY_REACHABLE"},
            {"cve_id": "CVE-2", "evidence": {"reachability_class": "STATICALLY_REACHABLE"}},
            {"cve_id": "CVE-3", "verdict": "POSSIBLE"},
            {"cve_id": "CVE-4", "verdict": "NOT_OBSERVED"},
        ],
    }

    enriched = augment_scan_response(scan)
    assert enriched["summary"] == {
        "total": 4,
        "dynamically_reachable": 1,
        "statically_reachable": 1,
        "uncertain": 1,
        "not_reachable": 1,
    }
    assert len(enriched["dynamically_reachable"]) == 1
    assert len(enriched["statically_reachable"]) == 1
    assert len(enriched["uncertain"]) == 1
    assert len(enriched["not_reachable"]) == 1
    assert enriched["pipeline_status"] == "PASS"


def test_augment_scan_response_marks_block_pipeline() -> None:
    scan = {"status": "blocked", "correlation": []}
    enriched = augment_scan_response(scan)
    assert enriched["pipeline_status"] == "BLOCK"


def test_analysis_coverage_reflects_raw_skipped_tools():
    """Tools with status=skipped in raw appear in tools_skipped, not tools_ran."""
    scan = {
        "status": "completed",
        "correlation": [],
        "raw": {
            "trivy": {"Results": []},
            "python_reachability": {"findings": []},
            "tainter": {"status": "skipped", "reason": "python_only_runtime_and_taint"},
            "dynamic_reachability": {"status": "skipped", "reason": "runtime disabled"},
        },
    }
    result = augment_scan_response(scan)
    cov = result["analysis_coverage"]
    assert "trivy" in cov["tools_ran"]
    assert "python_reachability" in cov["tools_ran"]
    assert "tainter" in cov["tools_skipped"]
    assert cov["tools_skipped"]["tainter"] == "python_only_runtime_and_taint"
    assert "dynamic_reachability" in cov["tools_skipped"]
    assert cov["evidence_layers"]["sca"] is True
    assert cov["evidence_layers"]["taint"] is False
    assert cov["evidence_layers"]["ast"] is True
    assert cov["evidence_layers"]["runtime"] is False


def test_analysis_coverage_full_pipeline():
    """Full pipeline shows all layers as True."""
    scan = {
        "status": "completed",
        "correlation": [],
        "raw": {
            "trivy": {"Results": []},
            "tainter": {"flows": []},
            "python_reachability": {"findings": []},
            "route_extractor": {"routes": []},
            "dynamic_reachability": {"coverage": {}},
        },
    }
    result = augment_scan_response(scan)
    cov = result["analysis_coverage"]
    assert cov["tools_skipped"] == {}
    assert cov["tools_errored"] == {}
    assert cov["evidence_layers"]["sca"] is True
    assert cov["evidence_layers"]["taint"] is True
    assert cov["evidence_layers"]["ast"] is True
    assert cov["evidence_layers"]["route"] is True
    assert cov["evidence_layers"]["runtime"] is True


def test_analysis_coverage_empty_raw():
    """Scan with no raw outputs (e.g., local mode without persistence) returns safe defaults."""
    scan = {"status": "completed", "correlation": []}
    result = augment_scan_response(scan)
    cov = result["analysis_coverage"]
    assert cov["tools_ran"] == []
    assert cov["tools_skipped"] == {}
    assert all(v is False for v in cov["evidence_layers"].values())
