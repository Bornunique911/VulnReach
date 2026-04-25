# Pain Remediation Roadmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the 16 pain points identified from a security architect + security engineer perspective, restoring trust, improving signal quality, and unblocking enterprise adoption.

**Architecture:** Four phases ordered by blast radius and ROI. Phase 0 fixes things that undermine trust in the tool today (output correctness, security hygiene). Phase 1 fixes analysis quality (classification accuracy). Phase 2 adds enterprise integration (SBOM, VEX, CVSS/EPSS). Phase 3 stubs the large-effort items that need their own dedicated plans.

**Tech Stack:** Python 3.11+, FastAPI, Click, Pydantic, pytest, SQLite/Postgres, bcrypt, hashlib

---

## Scope Note

This plan covers Phases 0 and 1 in full implementation detail. Phase 2 and Phase 3 items each require a separate dedicated plan — this document scopes them and identifies the kickoff work.

**Separate plans needed:**
- `2026-04-24-sbom-vex-integration.md` — SBOM ingestion + VEX export
- `2026-04-24-cvss-epss-scoring.md` — Risk score alignment
- `2026-04-24-java-taint-production.md` — Java taint analysis
- `2026-04-24-ide-plugin-vscode.md` — VS Code extension

---

## File Map

| File | Changes |
|------|---------|
| `correlation/engine.py` | Add `evidence_basis` return value; demote import-only to UNCERTAIN |
| `correlation/service.py` | Thread `evidence_basis` through; emit `analysis_coverage` |
| `vulnreach/scan_response.py` | Add `analysis_coverage` and `evidence_basis` fields to output |
| `api/auth.py` | Replace saltless SHA-256 with salted hash for API keys |
| `api/server.py` | Store and validate salted API key hash |
| `tests/test_correlation.py` | New test cases for evidence_basis, import-only demotion |
| `tests/test_scan_response_contract.py` | Assert analysis_coverage present and correct |
| `tests/test_auth_resolver.py` | Assert API key round-trips with salted hash |

---

## Phase 0 — Trust & Credibility

> These fix things that undermine trust today. Ship before any marketing push.

---

### Task 1: Add `analysis_coverage` to scan output

**Problem:** When tainter isn't installed or runtime is disabled, the scan silently returns partial results with no indication of which layers were skipped. Engineers suppress CVEs thinking they have 5-layer evidence when they have 2.

**Fix:** Add an `analysis_coverage` object to every scan response that names which tools ran, which were skipped, and the resulting evidence completeness.

**Files:**
- Modify: `correlation/service.py`
- Modify: `vulnreach/scan_response.py`
- Test: `tests/test_scan_response_contract.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scan_response_contract.py — add to existing file

def test_analysis_coverage_present_in_response():
    """Every scan response must declare which evidence layers ran."""
    from vulnreach.scan_response import augment_scan_response

    base = {
        "scan_id": "test-123",
        "status": "completed",
        "correlation": [],
        "metadata": {"tools": ["trivy", "python_reachability"]},
    }
    result = augment_scan_response(base, tools_ran=["trivy", "python_reachability"], tools_skipped={"tainter": "not installed", "dynamic_reachability": "runtime disabled"})

    assert "analysis_coverage" in result
    cov = result["analysis_coverage"]
    assert cov["tools_ran"] == ["trivy", "python_reachability"]
    assert "tainter" in cov["tools_skipped"]
    assert cov["tools_skipped"]["tainter"] == "not installed"
    assert cov["evidence_layers"]["taint"] is False
    assert cov["evidence_layers"]["ast"] is True
    assert cov["evidence_layers"]["runtime"] is False


def test_analysis_coverage_full_pipeline():
    """Full pipeline shows all layers as True."""
    from vulnreach.scan_response import augment_scan_response

    base = {
        "scan_id": "test-456",
        "status": "completed",
        "correlation": [],
        "metadata": {"tools": ["trivy", "tainter", "python_reachability", "dynamic_reachability"]},
    }
    result = augment_scan_response(
        base,
        tools_ran=["trivy", "tainter", "python_reachability", "dynamic_reachability"],
        tools_skipped={},
    )

    cov = result["analysis_coverage"]
    assert cov["evidence_layers"]["taint"] is True
    assert cov["evidence_layers"]["ast"] is True
    assert cov["evidence_layers"]["runtime"] is True
    assert cov["tools_skipped"] == {}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hrishikesh/Desktop/github_projects/vulnreach-parent/vulnreach-main-pypi
pytest tests/test_scan_response_contract.py::test_analysis_coverage_present_in_response -v
```

Expected: `FAILED` — `augment_scan_response() got unexpected keyword argument 'tools_ran'`

- [ ] **Step 3: Implement `analysis_coverage` in `vulnreach/scan_response.py`**

Read the current file first, then add the `tools_ran` and `tools_skipped` parameters and the `analysis_coverage` assembly to `augment_scan_response()`:

```python
# Add this constant near the top of vulnreach/scan_response.py

_TAINT_TOOLS = {"tainter"}
_AST_TOOLS = {"python_reachability", "java_reachability", "multi_language_reachability"}
_RUNTIME_TOOLS = {"dynamic_reachability", "pytest_coverage"}


def _build_analysis_coverage(
    tools_ran: list[str],
    tools_skipped: dict[str, str],
) -> dict:
    ran_set = set(tools_ran)
    return {
        "tools_ran": tools_ran,
        "tools_skipped": tools_skipped,
        "evidence_layers": {
            "sca": bool(ran_set & {"trivy"}),
            "taint": bool(ran_set & _TAINT_TOOLS),
            "ast": bool(ran_set & _AST_TOOLS),
            "route": bool(ran_set & {"route_extractor"}),
            "runtime": bool(ran_set & _RUNTIME_TOOLS),
        },
    }
```

Then update the `augment_scan_response` signature:

```python
def augment_scan_response(
    scan: dict,
    tools_ran: list[str] | None = None,
    tools_skipped: dict[str, str] | None = None,
) -> dict:
    # ... existing body unchanged ...

    # Add at the end, before return:
    scan["analysis_coverage"] = _build_analysis_coverage(
        tools_ran=tools_ran or list((scan.get("metadata") or {}).get("tools") or []),
        tools_skipped=tools_skipped or {},
    )
    return scan
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_scan_response_contract.py -v
```

Expected: all `test_analysis_coverage_*` tests PASS

- [ ] **Step 5: Wire `tools_skipped` from the orchestrator**

In `api/server.py`, the orchestrator collects tool results. Find where `augment_scan_response` is called and pass the actual skipped tools. The orchestrator already tracks which agents ran — look for the `pipeline_status` assembly around line 340+ in `api/server.py`.

The pattern to find and update:

```python
# Before (approximate current call):
response = augment_scan_response(raw_scan)

# After:
response = augment_scan_response(
    raw_scan,
    tools_ran=list(completed_agent_names),   # agents that returned results
    tools_skipped=skipped_reasons,           # dict[agent_name, reason_string]
)
```

`skipped_reasons` should be populated by each agent that raises `AgentSkipped` or equivalent. If the agent framework doesn't have a skip reason mechanism yet, stub it:

```python
skipped_reasons: dict[str, str] = {}
# Populate from agent results — if an agent returned None or raised, record why
for name, result in agent_results.items():
    if result is None:
        skipped_reasons[name] = "no output returned"
```

- [ ] **Step 6: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: no regressions; new coverage tests pass

- [ ] **Step 7: Commit**

```bash
git add vulnreach/scan_response.py tests/test_scan_response_contract.py api/server.py
git commit -m "feat: add analysis_coverage to scan output to surface skipped evidence layers"
```

---

### Task 2: Disambiguate `CONFIRMED` verdict — add `evidence_basis`

**Problem:** `CONFIRMED` is used for both static (import+call_chain+sink) and dynamic (coverage+taint) findings. Engineers filing a P1 ticket can't tell whether the CVE was actually executed at runtime or just traced through AST.

**Fix:** Add `evidence_basis: "dynamic" | "static" | "taint_only" | "import_only"` to every finding in the correlation output.

**Files:**
- Modify: `correlation/engine.py`
- Modify: `correlation/service.py`
- Test: `tests/test_correlation.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_correlation.py — add to existing test file

def test_evidence_basis_dynamic_confirmed():
    """Dynamic confirmed findings must declare evidence_basis='dynamic'."""
    from correlation.engine import reachability_verdict, dynamic_reachability_verdict, evidence_basis_from_signals

    verdict = dynamic_reachability_verdict(has_taint_flow=True, has_coverage_hit=True)
    basis = evidence_basis_from_signals(
        finding_type="dynamic",
        has_coverage_hit=True,
        has_taint_flow=True,
        call_chain_exists=False,
        import_detected=False,
    )
    assert verdict == "CONFIRMED"
    assert basis == "dynamic"


def test_evidence_basis_static_confirmed():
    """Static confirmed findings (import+call_chain+sink) declare evidence_basis='static'."""
    from correlation.engine import evidence_basis_from_signals

    basis = evidence_basis_from_signals(
        finding_type="static",
        has_coverage_hit=False,
        has_taint_flow=False,
        call_chain_exists=True,
        import_detected=True,
        sink_reachable=True,
    )
    assert basis == "static"


def test_evidence_basis_import_only():
    """Import-only findings declare evidence_basis='import_only'."""
    from correlation.engine import evidence_basis_from_signals

    basis = evidence_basis_from_signals(
        finding_type="static",
        has_coverage_hit=False,
        has_taint_flow=False,
        call_chain_exists=False,
        import_detected=True,
        sink_reachable=False,
    )
    assert basis == "import_only"


def test_evidence_basis_taint_only():
    """Taint-only findings (no coverage) declare evidence_basis='taint_only'."""
    from correlation.engine import evidence_basis_from_signals

    basis = evidence_basis_from_signals(
        finding_type="static",
        has_coverage_hit=False,
        has_taint_flow=True,
        call_chain_exists=False,
        import_detected=False,
        sink_reachable=False,
    )
    assert basis == "taint_only"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_correlation.py::test_evidence_basis_dynamic_confirmed tests/test_correlation.py::test_evidence_basis_static_confirmed tests/test_correlation.py::test_evidence_basis_import_only tests/test_correlation.py::test_evidence_basis_taint_only -v
```

Expected: `FAILED` — `cannot import name 'evidence_basis_from_signals'`

- [ ] **Step 3: Add `evidence_basis_from_signals` to `correlation/engine.py`**

Add this function after the existing verdict functions (after line 80):

```python
def evidence_basis_from_signals(
    finding_type: str,
    has_coverage_hit: bool = False,
    has_taint_flow: bool = False,
    call_chain_exists: bool = False,
    import_detected: bool = False,
    sink_reachable: bool = False,
) -> str:
    """
    Returns a human-readable label for the strongest evidence type present.
    Distinct from verdict — two findings can share CONFIRMED but differ in basis.
    """
    if finding_type == "dynamic" and has_coverage_hit:
        return "dynamic"
    if has_taint_flow and call_chain_exists:
        return "static"
    if call_chain_exists and sink_reachable:
        return "static"
    if call_chain_exists:
        return "static"
    if has_taint_flow:
        return "taint_only"
    if import_detected:
        return "import_only"
    return "none"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_correlation.py::test_evidence_basis_dynamic_confirmed tests/test_correlation.py::test_evidence_basis_static_confirmed tests/test_correlation.py::test_evidence_basis_import_only tests/test_correlation.py::test_evidence_basis_taint_only -v
```

Expected: all 4 PASS

- [ ] **Step 5: Thread `evidence_basis` through `correlation/service.py`**

In `correlation/service.py`, after each finding's verdict is determined (around lines 115–138), call `evidence_basis_from_signals()` and attach the result to the finding dict:

```python
from correlation.engine import (
    reachability_verdict,
    dynamic_reachability_verdict,
    classify_reachability,
    risk_score,
    priority_from_score,
    confidence_from_verdict,
    evidence_basis_from_signals,  # add this import
)

# Inside the correlate() loop, after verdict is determined:
basis = evidence_basis_from_signals(
    finding_type=finding.get("finding_type", "static"),
    has_coverage_hit=evidence.get("has_coverage_hit", False),
    has_taint_flow=evidence.get("has_taint_flow", False),
    call_chain_exists=evidence.get("call_chain_exists", False),
    import_detected=evidence.get("import_detected", False),
    sink_reachable=evidence.get("sink_reachable", False),
)
finding["evidence_basis"] = basis
```

- [ ] **Step 6: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: no regressions

- [ ] **Step 7: Commit**

```bash
git add correlation/engine.py correlation/service.py tests/test_correlation.py
git commit -m "feat: add evidence_basis field to distinguish dynamic from static CONFIRMED findings"
```

---

### Task 3: Harden API key storage with per-key salt

**Problem:** `api/auth.py:47-48` stores API keys as raw `SHA-256(key)` with no salt. For a security tool, this is embarrassing in any vendor security review and will be flagged.

**Fix:** Store `salt:sha256(salt + key)` where salt is a cryptographically random 32-byte hex string generated per key. Backward compatible — keys created before this change use the `nosalt:` prefix sentinel and are validated with the old path during migration.

**Files:**
- Modify: `api/auth.py`
- Modify: `api/server.py` (if hash storage is there)
- Test: `tests/test_auth_resolver.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_auth_resolver.py — add to existing file

def test_api_key_hash_includes_salt():
    """API key hash storage must include a per-key salt."""
    from api.auth import hash_api_key, verify_api_key

    raw_key = "vrk_ab12cd34.testsecretvalue"
    stored = hash_api_key(raw_key)

    # Must not be just a 64-char hex string (raw SHA-256)
    assert ":" in stored, "stored hash must contain salt separator"
    prefix, _ = stored.split(":", 1)
    assert len(prefix) == 64, "salt must be 32 bytes (64 hex chars)"


def test_api_key_verify_correct_key():
    """Correct key must verify against its salted hash."""
    from api.auth import hash_api_key, verify_api_key

    raw_key = "vrk_ab12cd34.testsecretvalue"
    stored = hash_api_key(raw_key)
    assert verify_api_key(raw_key, stored) is True


def test_api_key_verify_wrong_key():
    """Wrong key must not verify."""
    from api.auth import hash_api_key, verify_api_key

    stored = hash_api_key("vrk_ab12cd34.correct")
    assert verify_api_key("vrk_ab12cd34.wrong", stored) is False


def test_api_key_different_hashes_same_key():
    """Same key hashed twice must produce different stored values (random salt)."""
    from api.auth import hash_api_key

    raw_key = "vrk_ab12cd34.testsecretvalue"
    h1 = hash_api_key(raw_key)
    h2 = hash_api_key(raw_key)
    assert h1 != h2, "each call must generate a fresh salt"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_auth_resolver.py::test_api_key_hash_includes_salt tests/test_auth_resolver.py::test_api_key_verify_correct_key tests/test_auth_resolver.py::test_api_key_verify_wrong_key tests/test_auth_resolver.py::test_api_key_different_hashes_same_key -v
```

Expected: `FAILED` — either `verify_api_key` doesn't exist, or hash doesn't contain `:`

- [ ] **Step 3: Update `api/auth.py` lines 47-48**

Replace the existing `hash_api_key` function and add `verify_api_key`:

```python
import hashlib
import hmac
import secrets


def hash_api_key(raw_key: str) -> str:
    """Returns 'salt_hex:sha256(salt_bytes + key_bytes)' for storage."""
    salt = secrets.token_bytes(32)
    salt_hex = salt.hex()
    digest = hashlib.sha256(salt + raw_key.encode()).hexdigest()
    return f"{salt_hex}:{digest}"


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Constant-time verification against a salted hash."""
    if ":" not in stored_hash:
        # Legacy unsalted hash — compare directly, then flag for rotation
        legacy = hashlib.sha256(raw_key.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored_hash)
    salt_hex, expected_digest = stored_hash.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    actual_digest = hashlib.sha256(salt + raw_key.encode()).hexdigest()
    return hmac.compare_digest(actual_digest, expected_digest)
```

- [ ] **Step 4: Update `api/server.py` to use `verify_api_key`**

Find `_resolve_api_key_principal()` around lines 155-166 in `api/server.py`. Replace any direct SHA-256 comparison with the new `verify_api_key`:

```python
from api.auth import hash_api_key, verify_api_key  # add verify_api_key to imports

# In _resolve_api_key_principal():
# Before:
#   key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
#   record = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()

# After:
# Must iterate candidate keys (can't do DB lookup by hash anymore — salt is random)
# To avoid full table scan, store a key prefix for lookup:
# The vrk_ format is "vrk_<8char_prefix>.<secret>" — use prefix as DB index
prefix = raw_token.split(".")[0] if "." in raw_token else ""
candidates = db.query(ApiKey).filter(ApiKey.key_prefix == prefix).all()
record = next((k for k in candidates if verify_api_key(raw_token, k.key_hash)), None)
```

If `ApiKey.key_prefix` column doesn't exist yet, add a migration:

```python
# In the ApiKey model (wherever it's defined), add:
key_prefix: str  # stores "vrk_ab12cd34" — the part before the dot

# When creating a new API key in create_api_key() (server.py ~217-248):
prefix = raw_key.split(".")[0] if "." in raw_key else raw_key[:12]
api_key_record = ApiKey(
    key_hash=hash_api_key(raw_key),
    key_prefix=prefix,
    # ... other fields unchanged
)
```

- [ ] **Step 5: Run the full auth test suite**

```bash
pytest tests/test_auth_resolver.py -v --tb=short
```

Expected: all tests pass including new ones

- [ ] **Step 6: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: no regressions

- [ ] **Step 7: Commit**

```bash
git add api/auth.py api/server.py tests/test_auth_resolver.py
git commit -m "fix: add per-key salt to API key storage (SHA-256 + random salt)"
```

---

## Phase 1 — Analysis Quality

> These fix the signal quality — reducing promotions that are barely better than raw Trivy.

---

### Task 4: Demote import-only findings from `STATICALLY_REACHABLE` to `UNCERTAIN`

**Problem:** `import_detected=True` alone in `correlation/engine.py:classify_reachability()` promotes a finding to `STATICALLY_REACHABLE, IMPORT`. This means any package that's installed and imported anywhere — which is almost everything — gets labeled "statically reachable." It's barely better than raw Trivy output and inflates the STATICALLY_REACHABLE bucket.

**Fix:** Require at minimum `call_chain_exists=True` for STATICALLY_REACHABLE. Import-only falls to UNCERTAIN.

**Files:**
- Modify: `correlation/engine.py:120-186`
- Test: `tests/test_correlation.py`
- Test: `tests/test_reachability_pairing.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_correlation.py — add these tests

def test_import_only_is_uncertain_not_statically_reachable():
    """Import detected without call chain must be UNCERTAIN, not STATICALLY_REACHABLE."""
    from correlation.engine import classify_reachability

    reachability_class, subtype = classify_reachability(
        import_detected=True,
        call_chain_exists=False,
        has_file=False,
        has_function=False,
        coverage_hit=False,
        has_taint_flow=False,
        evidence_type=None,
        package="requests",
        framework_packages=set(),
    )
    assert reachability_class == "UNCERTAIN"
    assert subtype is None


def test_call_chain_without_import_is_statically_reachable():
    """Call chain evidence promotes to STATICALLY_REACHABLE even without explicit import."""
    from correlation.engine import classify_reachability

    reachability_class, subtype = classify_reachability(
        import_detected=False,
        call_chain_exists=True,
        has_file=True,
        has_function=True,
        coverage_hit=False,
        has_taint_flow=False,
        evidence_type=None,
        package="requests",
        framework_packages=set(),
    )
    assert reachability_class == "STATICALLY_REACHABLE"
    assert subtype == "FUNCTION"


def test_import_plus_call_chain_is_statically_reachable():
    """Import + call chain together is still STATICALLY_REACHABLE."""
    from correlation.engine import classify_reachability

    reachability_class, subtype = classify_reachability(
        import_detected=True,
        call_chain_exists=True,
        has_file=True,
        has_function=False,
        coverage_hit=False,
        has_taint_flow=False,
        evidence_type=None,
        package="requests",
        framework_packages=set(),
    )
    assert reachability_class == "STATICALLY_REACHABLE"
    assert subtype == "FILE"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_correlation.py::test_import_only_is_uncertain_not_statically_reachable tests/test_correlation.py::test_call_chain_without_import_is_statically_reachable tests/test_correlation.py::test_import_plus_call_chain_is_statically_reachable -v
```

Expected: `test_import_only_is_uncertain_not_statically_reachable` FAILS (currently returns STATICALLY_REACHABLE)

- [ ] **Step 3: Update `classify_reachability()` in `correlation/engine.py`**

Read the current function at lines 120-186, then update the STATICALLY_REACHABLE branch. The change is: the `IMPORT` subtype path (import detected, no call chain) now returns `UNCERTAIN` instead of `STATICALLY_REACHABLE`:

```python
def classify_reachability(
    import_detected: bool,
    call_chain_exists: bool,
    has_file: bool,
    has_function: bool,
    coverage_hit: bool,
    has_taint_flow: bool,
    evidence_type: str | None,
    package: str,
    framework_packages: set[str],
) -> tuple[str, str | None]:

    # Rule 1: DYNAMICALLY_REACHABLE — runtime execution confirmed
    if coverage_hit and (call_chain_exists or has_function):
        return "DYNAMICALLY_REACHABLE", None

    # Rule 2: UNCERTAIN — taint only (no call chain, no coverage)
    if evidence_type == "taint" and not call_chain_exists and not coverage_hit:
        return "UNCERTAIN", None

    # Rule 3: STATICALLY_REACHABLE — requires call chain or function evidence
    # NOTE: import-only is no longer sufficient; it falls to UNCERTAIN below
    if call_chain_exists or has_function or has_file:
        if package in framework_packages and not has_function:
            return "STATICALLY_REACHABLE", "TRANSITIVE"
        if has_function:
            return "STATICALLY_REACHABLE", "FUNCTION"
        if has_file:
            return "STATICALLY_REACHABLE", "FILE"
        return "STATICALLY_REACHABLE", "FILE"  # call_chain_exists but no file/function details

    # Rule 4: UNCERTAIN — import detected but no structural evidence
    # Previously this was STATICALLY_REACHABLE/IMPORT — demoted for accuracy
    if import_detected:
        return "UNCERTAIN", None

    # Rule 5: NOT_REACHABLE
    return "NOT_REACHABLE", None
```

- [ ] **Step 4: Run the new tests**

```bash
pytest tests/test_correlation.py::test_import_only_is_uncertain_not_statically_reachable tests/test_correlation.py::test_call_chain_without_import_is_statically_reachable tests/test_correlation.py::test_import_plus_call_chain_is_statically_reachable -v
```

Expected: all 3 PASS

- [ ] **Step 5: Run the full correlation and reachability pairing test suites**

```bash
pytest tests/test_correlation.py tests/test_reachability_pairing.py -v --tb=short
```

Expected: passing. If existing tests assert `STATICALLY_REACHABLE` for import-only inputs, those tests are testing the wrong behavior — update the assertions to `UNCERTAIN`.

- [ ] **Step 6: Run the full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: no regressions. Note: the benchmark numbers in `docs/benchmark.md` will shift — NOT_REACHABLE and UNCERTAIN counts will increase, STATICALLY_REACHABLE will decrease. This is the correct behavior; update the benchmark doc to reflect new numbers.

- [ ] **Step 7: Update `docs/benchmark.md` with honest numbers**

Re-run the benchmark against the multi-tier-dvpa repo and update the tables in `docs/benchmark.md`. Key talking point: the shift from STATICALLY_REACHABLE/IMPORT to UNCERTAIN reflects higher accuracy — we're no longer claiming reachability we can't prove.

- [ ] **Step 8: Commit**

```bash
git add correlation/engine.py tests/test_correlation.py tests/test_reachability_pairing.py docs/benchmark.md
git commit -m "fix: demote import-only findings from STATICALLY_REACHABLE to UNCERTAIN

Import presence alone does not prove a vulnerable code path is called.
Requires call_chain_exists or has_function for STATICALLY_REACHABLE promotion."
```

---

### Task 5: Surface analysis completeness warning in CLI output

**Problem:** The CLI prints a clean summary table even when 3 of 5 evidence layers were skipped. Engineers walk away thinking they got a full scan.

**Fix:** Print a `[!] Partial analysis` warning block in CLI output when `analysis_coverage.tools_skipped` is non-empty.

**Files:**
- Modify: `vulnreach/cli/scan.py:15-30` (`_print_summary()`)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_scan.py (create if not exists, or add to existing CLI test file)

from click.testing import CliRunner
from unittest.mock import patch
from vulnreach.cli.scan import scan


def test_cli_warns_on_partial_analysis(tmp_path):
    """CLI must print a partial analysis warning when tools were skipped."""
    runner = CliRunner()

    mock_result = {
        "scan_id": "abc-123",
        "status": "completed",
        "summary": {"total": 5, "dynamically_reachable": 0, "statically_reachable": 3, "uncertain": 2, "not_reachable": 0},
        "analysis_coverage": {
            "tools_ran": ["trivy", "python_reachability"],
            "tools_skipped": {"tainter": "not installed", "dynamic_reachability": "runtime disabled"},
            "evidence_layers": {"sca": True, "taint": False, "ast": True, "route": False, "runtime": False},
        },
        "pipeline_status": "PASS",
    }

    with patch("vulnreach.cli.scan.run_local_scan", return_value=mock_result):
        result = runner.invoke(scan, ["--repo-path", str(tmp_path)])

    assert "Partial analysis" in result.output or "partial" in result.output.lower()
    assert "tainter" in result.output
    assert "dynamic_reachability" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_cli_scan.py::test_cli_warns_on_partial_analysis -v
```

Expected: `FAILED` — no partial analysis warning in output

- [ ] **Step 3: Update `_print_summary()` in `vulnreach/cli/scan.py`**

Read the current `_print_summary` function (lines 15-30), then add the coverage warning block:

```python
def _print_summary(result: dict) -> None:
    # ... existing summary table code unchanged ...

    # Add after the existing summary table:
    coverage = result.get("analysis_coverage", {})
    skipped = coverage.get("tools_skipped", {})
    if skipped:
        click.echo("")
        click.secho("[!] Partial analysis — the following evidence layers were not collected:", fg="yellow")
        for tool, reason in skipped.items():
            click.secho(f"    {tool}: {reason}", fg="yellow")
        layers = coverage.get("evidence_layers", {})
        missing = [name for name, ran in layers.items() if not ran]
        if missing:
            click.secho(f"    Missing layers: {', '.join(missing)}", fg="yellow")
        click.secho("    Results may under-report reachability. See docs/configuration.md for setup.", fg="yellow")
```

- [ ] **Step 4: Run the test**

```bash
pytest tests/test_cli_scan.py::test_cli_warns_on_partial_analysis -v
```

Expected: PASS

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: no regressions

- [ ] **Step 6: Commit**

```bash
git add vulnreach/cli/scan.py tests/test_cli_scan.py
git commit -m "feat: warn in CLI output when analysis layers were skipped"
```

---

## Phase 2 — Enterprise Integration (Separate Plans)

> Each item below is a distinct subsystem. Create a dedicated plan before implementing.

---

### Task 6: SBOM Ingestion — Kickoff Scope

**Problem:** Enterprises already have CycloneDX/SPDX SBOMs generated by their build pipelines. VulnReach forces a re-scan from source, creating a second SCA tool that disagrees with the first.

**Target Behavior:**
```bash
vulnreach scan --sbom cyclonedx.json --repo-path ./app
# OR
vulnreach scan --sbom spdx.json  # no repo needed; static-only mode
```

**What this plan needs to cover:**
- `POST /scan` accepting a `sbom_payload` field (base64-encoded CycloneDX/SPDX JSON)
- A new `ingestion/sbom_parser.py` that reads CycloneDX 1.4/1.5 and SPDX 2.3 JSON and emits the same `findings: list[dict]` format that Trivy produces
- Routing: if SBOM is provided, skip Trivy and use SBOM findings as SCA layer
- CLI: `--sbom <path>` option on `vulnreach scan`

**Create plan:** `docs/superpowers/plans/2026-04-24-sbom-vex-integration.md`

---

### Task 7: VEX Export — Kickoff Scope

**Problem:** VulnReach classifications can't propagate to Dependency-Track, SBOM managers, or procurement systems without VEX (Vulnerability Exploitability eXchange) output. The work done in VulnReach is isolated.

**Target Behavior:**
```bash
vulnreach export vex --scan-id abc-123 --format openvex
# GET /scan/{id}/export/vex?format=openvex|csaf
```

**What this plan needs to cover:**
- OpenVEX 0.2.0 JSON format output (https://github.com/openvex/spec)
- CSAF VEX 2.0 format (secondary priority)
- Mapping: `DYNAMICALLY_REACHABLE` + `CONFIRMED` → `status: "affected"`; `NOT_REACHABLE` → `status: "not_affected"` with `justification: "vulnerable_code_not_in_execute_path"`; `UNCERTAIN` → `status: "under_investigation"`
- New CLI command: `vulnreach export vex`
- New API route: `GET /scan/{id}/export/vex`

**Create plan:** `docs/superpowers/plans/2026-04-24-sbom-vex-integration.md` (same plan as SBOM, combined)

---

### Task 8: CVSS/EPSS Risk Score Alignment — Kickoff Scope

**Problem:** VulnReach's custom risk score (`4 × 1.5 × 1.3 = 7.8`) has no alignment to CVSS or EPSS. Security teams can't route findings to existing workflows that speak CVSS. Risk committees don't trust proprietary scores.

**Target Behavior:** Include `cvss_base_score`, `epss_score`, and `epss_percentile` on each finding. Keep the existing `risk_score` but label it `vulnreach_risk_score` to avoid confusion.

**What this plan needs to cover:**
- NVD API v2 integration to fetch CVSS base scores by CVE ID (with caching, rate limiting)
- FIRST.org EPSS API integration to fetch EPSS probability + percentile
- Optional: offline mode (embed a snapshot of EPSS scores, updated monthly)
- Schema update: add `cvss_base_score: float | None`, `epss_score: float | None`, `epss_percentile: float | None` to each correlation finding
- Rename `risk_score` to `vulnreach_risk_score` in response (with backward-compatible alias)

**Create plan:** `docs/superpowers/plans/2026-04-24-cvss-epss-scoring.md`

---

## Phase 3 — Ecosystem Expansion (Roadmap Stubs)

> These are large independent projects. Do not start without a dedicated plan and an assigned owner.

---

### Task 9: Java Taint Analysis — Production Ready

**Current state:** `agents/agent_tainter.py` is Python-only. Java reachability is experimental AST/call graph only — no source-to-sink taint.

**Scope:** Integrate a Java taint analysis engine (candidate: CodeQL free tier, Semgrep Pro, or custom AST visitor using `tree-sitter-java`) to produce source-to-sink flows for Java findings. Must handle Maven and Gradle projects.

**Create plan:** `docs/superpowers/plans/2026-04-24-java-taint-production.md`

---

### Task 10: VS Code IDE Plugin

**Current state:** No IDE integration. Security findings only surface in CI after merge.

**Scope:** A VS Code extension that calls the VulnReach CLI or API on save/open, and decorates source lines with inline reachability status for CVEs affecting functions in the file. Must work in both standalone mode (local scan) and client mode (server).

**Create plan:** `docs/superpowers/plans/2026-04-24-ide-plugin-vscode.md`

---

### Task 11: Docker-Free Runtime Analysis Option

**Current state:** Dynamic reachability requires Docker daemon access (`VULNREACH_ALLOW_DOCKER_DAEMON=true`). This is a privileged escalation path that fails most enterprise security reviews for CI tooling.

**Scope:** Support a `--runtime-mode process` option that runs the app as a local subprocess (not a container) for runtime coverage collection. Requires: process management, PORT detection, graceful shutdown, coverage flush. Suitable for Python apps with minimal external dependencies.

**Create plan:** `docs/superpowers/plans/2026-04-24-docker-free-runtime.md`

---

## Execution Summary

| Task | Phase | Effort | Files Touched |
|------|-------|--------|---------------|
| T1: analysis_coverage field | P0 | 2h | scan_response.py, server.py |
| T2: evidence_basis field | P0 | 2h | engine.py, service.py |
| T3: API key salt | P0 | 3h | auth.py, server.py |
| T4: import-only demotion | P1 | 3h | engine.py |
| T5: CLI partial analysis warning | P1 | 1h | cli/scan.py |
| T6: SBOM ingestion | P2 | separate plan | — |
| T7: VEX export | P2 | separate plan | — |
| T8: CVSS/EPSS alignment | P2 | separate plan | — |
| T9: Java taint | P3 | separate plan | — |
| T10: VS Code plugin | P3 | separate plan | — |
| T11: Docker-free runtime | P3 | separate plan | — |

**Phase 0 total (T1–T3):** ~1 week, can be parallelized across 2 engineers
**Phase 1 total (T4–T5):** ~1 day, single engineer

---

## Self-Review

**Spec coverage check:**
- Silent degradation → T1 (analysis_coverage) + T5 (CLI warning) ✓
- CONFIRMED ambiguity → T2 (evidence_basis) ✓
- API key salt → T3 ✓
- Import-only over-promotion → T4 ✓
- SBOM ingestion → T6 (scoped, separate plan) ✓
- VEX export → T7 (scoped, separate plan) ✓
- CVSS/EPSS → T8 (scoped, separate plan) ✓
- Polyglot taint → T9 (scoped, separate plan) ✓
- IDE plugin → T10 (scoped, separate plan) ✓
- Docker-free runtime → T11 (scoped, separate plan) ✓
- JWT refresh token → not included; deprioritized (API keys are the CI-safe path; refresh token adds complexity for minimal gain given 60min default is configurable via `JWT_EXPIRE_MINUTES`)
- Confidence score empirical calibration → not included; requires a labeled ground-truth dataset that doesn't exist yet — this is research, not an engineering task

**Placeholder scan:** No TBD, TODO, or "similar to" references found. All Phase 0/1 tasks have complete code.

**Type consistency:** `classify_reachability()` signature in T4 matches the existing function signature in `correlation/engine.py:120-186`. `evidence_basis_from_signals()` defined in T2 is imported by name in the same task — no cross-task signature drift.
