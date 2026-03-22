from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Verdict = Literal["CONFIRMED", "LIKELY", "POSSIBLE", "NOT_OBSERVED"]
Exposure = Literal["public", "private", "internal"]
ReachabilityClass = Literal["DYNAMICALLY_REACHABLE", "STATICALLY_REACHABLE", "NOT_REACHABLE", "UNCERTAIN"]
StaticSubtype = Literal["FUNCTION", "FILE", "IMPORT", "TRANSITIVE"]


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

# Packages whose execution is primarily driven by framework bootstrap/routing,
# not by direct application code calling into the library.
_FRAMEWORK_PACKAGES = {
    "django", "flask", "fastapi", "starlette", "tornado",
    "aiohttp", "bottle", "sanic", "quart", "falcon",
}


def reachability_verdict(import_detected: bool, call_chain_exists: bool, sink_reachable: bool) -> Verdict:
    """Static reachability verdict based on import / call-chain / sink evidence.

    Rules:
    - import + call_chain + sink_reachable → CONFIRMED (full static trace to sink)
    - import + call_chain (no sink proof)  → LIKELY
    - import only                          → POSSIBLE
    - none                                 → NOT_OBSERVED
    """
    if import_detected and call_chain_exists and sink_reachable:
        return "CONFIRMED"
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


def classify_reachability(
    coverage_hit: bool,
    call_chain_exists: bool,
    import_detected: bool,
    function: str | None,
    file: str | None,
    evidence_type: str,
    package: str = "",
) -> tuple[ReachabilityClass, StaticSubtype | None]:
    """Classify vulnerability reachability into one of 4 tiers.

    Coverage.json is the ground truth for runtime execution. Classification rules:

    1. DYNAMICALLY_REACHABLE
       coverage hit AND (call_chain_exists OR a specific function was identified)
       → the vulnerable code was actually executed at runtime

    2. STATICALLY_REACHABLE (no coverage hit)
       import / file / function evidence present
       Sub-types:
         FUNCTION  — specific function name known
         FILE      — file is known, no specific function
         IMPORT    — only import was detected
         TRANSITIVE — framework-driven bootstrap (Django, Flask, etc.)

    3. UNCERTAIN
       evidence_type == "taint" AND no call chain AND no coverage hit
       → weak signal only; could be a flow that never actually triggers

    4. NOT_REACHABLE
       no import, no file/function, no coverage hit
    """
    has_function = bool(function)
    has_file = bool(file)

    # ── Rule 1: DYNAMICALLY REACHABLE ────────────────────────────────────────
    # Coverage is ground truth. Require at least call-chain OR function evidence
    # so we don't promote import-time-only hits to dynamic without a call trace.
    if coverage_hit and (call_chain_exists or has_function):
        return "DYNAMICALLY_REACHABLE", None

    # ── Rule 3: UNCERTAIN (checked before static to catch taint-only entries) ─
    if evidence_type == "taint" and not call_chain_exists and not coverage_hit:
        return "UNCERTAIN", None

    # ── Rule 2: STATICALLY REACHABLE ─────────────────────────────────────────
    if import_detected or has_file or has_function:
        pkg_norm = package.lower().replace("-", "_").replace(".", "_")
        # Strip common prefixes/suffixes to normalise "python-django" → "django"
        for prefix in ("python_", "py_"):
            if pkg_norm.startswith(prefix):
                pkg_norm = pkg_norm[len(prefix):]
        for suffix in ("_python",):
            if pkg_norm.endswith(suffix):
                pkg_norm = pkg_norm[: -len(suffix)]

        if pkg_norm in _FRAMEWORK_PACKAGES and not has_function:
            return "STATICALLY_REACHABLE", "TRANSITIVE"
        if has_function:
            return "STATICALLY_REACHABLE", "FUNCTION"
        if has_file:
            return "STATICALLY_REACHABLE", "FILE"
        # import_detected only
        return "STATICALLY_REACHABLE", "IMPORT"

    # ── Rule 4: NOT REACHABLE ─────────────────────────────────────────────────
    return "NOT_REACHABLE", None
