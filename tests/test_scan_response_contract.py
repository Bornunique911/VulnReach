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
