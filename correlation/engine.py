from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Verdict = Literal["CONFIRMED", "LIKELY", "POSSIBLE", "NOT_OBSERVED"]
Exposure = Literal["public", "private", "internal"]


_SEVERITY_SCORES: dict[Severity, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


_REACHABILITY_MULTIPLIER: dict[Verdict, float] = {
    "CONFIRMED": 1.5,
    "LIKELY": 1.2,
    "POSSIBLE": 1.0,
    "NOT_OBSERVED": 0.5,
}


_EXPOSURE_MODIFIER: dict[Exposure, float] = {
    "public": 1.3,
    "internal": 1.0,
    "private": 1.0,
}


_PRIORITY_THRESHOLDS = (
    (5.0, "P1"),
    (4.0, "P2"),
    (3.0, "P3"),
)


def reachability_verdict(import_detected: bool, call_chain_exists: bool, sink_reachable: bool) -> Verdict:
    """Static reachability verdict based on import / call-chain evidence only.

    Rules:
    - call_chain_exists (static trace to sink) -> LIKELY
    - import_detected only -> POSSIBLE
    - none -> NOT_OBSERVED

    Note: sink_reachable is intentionally ignored here; it belongs to the
    dynamic verdict path (see dynamic_reachability_verdict).
    """
    if import_detected and call_chain_exists:
        return "LIKELY"
    if import_detected:
        return "POSSIBLE"
    return "NOT_OBSERVED"


def dynamic_reachability_verdict(has_taint_flow: bool, has_coverage_hit: bool) -> Verdict:
    """Dynamic verdict that requires BOTH taint-flow AND runtime coverage.

    Rules:
    - taint flow confirmed AND runtime coverage hit -> CONFIRMED
    - runtime coverage hit but no taint flow -> LIKELY  (runtime-only evidence)
    - taint flow but never executed at runtime -> POSSIBLE
    - neither -> NOT_OBSERVED
    """
    if has_taint_flow and has_coverage_hit:
        return "CONFIRMED"
    if has_coverage_hit:
        return "LIKELY"
    if has_taint_flow:
        return "POSSIBLE"
    return "NOT_OBSERVED"


# Confidence scores per evidence type
CONFIDENCE_SCORES = {
    "CONFIRMED": 0.95,  # Dynamic hit
    "LIKELY": 0.7,      # Static call chain
    "POSSIBLE": 0.4,    # Import only
    "NOT_OBSERVED": 0.1,
}


def confidence_from_verdict(verdict: Verdict) -> float:
    """Return confidence score for a given verdict."""
    return CONFIDENCE_SCORES.get(verdict, 0.1)


def risk_score(severity: Severity, verdict: Verdict, exposure: Exposure) -> float:
    base = _SEVERITY_SCORES.get(severity, 0)
    reach_mult = _REACHABILITY_MULTIPLIER.get(verdict, 0.0)
    exposure_mult = _EXPOSURE_MODIFIER.get(exposure, 1.0)
    return round(base * reach_mult * exposure_mult, 2)


def priority_from_score(score: float) -> str:
    for threshold, label in _PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "P4"


def apply_policy(severity: Severity, verdict: Verdict, rules: list[dict]) -> str:
    """Return BLOCK if any rule matches, else PASS."""

    for rule in rules:
        if rule.get("severity") == severity and rule.get("verdict") == verdict:
            return "BLOCK"
    return "PASS"

