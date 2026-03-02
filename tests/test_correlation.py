import pytest

from correlation.engine import (
    dynamic_reachability_verdict,
    priority_from_score,
    reachability_verdict,
    risk_score,
)


# ------------------------------------------------------------------
# Static reachability verdicts — import / call-chain evidence only
# CONFIRMED is never produced here; that is reserved for the dynamic path.
# ------------------------------------------------------------------
def test_static_reachability_verdict_rules():
    # call-chain present → LIKELY
    assert reachability_verdict(True, True, False) == "LIKELY"
    # import only → POSSIBLE
    assert reachability_verdict(True, False, False) == "POSSIBLE"
    # nothing → NOT_OBSERVED
    assert reachability_verdict(False, False, False) == "NOT_OBSERVED"
    # sink_reachable arg is accepted but ignored for static path
    assert reachability_verdict(True, True, True) == "LIKELY"


# ------------------------------------------------------------------
# Dynamic reachability verdicts — taint flow + runtime coverage
# ------------------------------------------------------------------
def test_dynamic_reachability_verdict_rules():
    # both taint flow + coverage → CONFIRMED
    assert dynamic_reachability_verdict(True, True) == "CONFIRMED"
    # runtime coverage only → LIKELY
    assert dynamic_reachability_verdict(False, True) == "LIKELY"
    # taint flow only (not executed at runtime) → POSSIBLE
    assert dynamic_reachability_verdict(True, False) == "POSSIBLE"
    # neither → NOT_OBSERVED
    assert dynamic_reachability_verdict(False, False) == "NOT_OBSERVED"


def test_risk_score_and_priority():
    score = risk_score("CRITICAL", "CONFIRMED", "public")
    assert score == 7.8
    assert priority_from_score(score) == "P1"

    low_score = risk_score("LOW", "NOT_OBSERVED", "private")
    assert low_score == 0.5
    assert priority_from_score(low_score) == "P4"


