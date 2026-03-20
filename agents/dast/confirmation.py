"""Phase 3 — SQLi Confirmation Signals.

Implements four independent detection methods, checked in priority order:
  1. error_based   — DB error string in response body (fastest / highest confidence)
  2. coverage_based— taint-relevant sink line newly appears in coverage delta
  3. boolean_based — response diff between true/false conditions
  4. time_based    — significant latency spike on sleep payloads
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .models import CoverageDelta

# ---------------------------------------------------------------------------
# Error-based: DB error strings by dialect
# ---------------------------------------------------------------------------

_DB_ERROR_PATTERNS = re.compile(
    r"syntax error"
    r"|sql syntax"
    r"|you have an error in your sql"
    r"|ORA-\d{5}"          # Oracle
    r"|PLS-\d{5}"          # Oracle PL/SQL
    r"|pg_query\("         # PostgreSQL legacy PHP
    r"|PSQLException"
    r"|ERROR:\s+syntax"    # PostgreSQL
    r"|unterminated quoted string"
    r"|invalid input syntax for"
    r"|column .+ does not exist"
    r"|relation .+ does not exist"
    r"|mysql_fetch"
    r"|mysql_num_rows"
    r"|com\.mysql\.jdbc"
    r"|MySQLSyntaxErrorException"
    r"|SQLSTATE\["
    r"|sqlite3\.OperationalError"
    r"|OperationalError:"
    r"|ProgrammingError:"
    r"|InterfaceError:"
    r"|StatementHandle"
    r"|Microsoft OLE DB"
    r"|Unclosed quotation mark"
    r"|Incorrect syntax near"
    r"|ODBC SQL Server Driver"
    r"|Warning: mssql_"
    r"|nvarchar"
    r"|Conversion failed when converting"
    r"|near \"[^\"]*\": syntax error"   # SQLite syntax error
    r"|unrecognized token",
    re.IGNORECASE,
)

# Reflected SQL query in response body — app leaking the assembled query.
# Matches "SELECT ... FROM ... WHERE ..." which signals unsanitised SQL
# concatenation being exposed to the user.  The WHERE clause must contain
# at least one quote (raw or HTML-encoded &#x27;) to avoid matching benign
# SQL examples shown in educational/documentation pages.
_REFLECTED_SQL = re.compile(
    r"SELECT\s+.+?\s+FROM\s+\w+\s+WHERE\s+[^<]{0,300}(?:'|&#x27;|&apos;)",
    re.IGNORECASE | re.DOTALL,
)


def check_error_based(response_body: str) -> Tuple[bool, str]:
    """Return (triggered, matched_pattern) if a DB error string or reflected SQL query is found."""
    match = _DB_ERROR_PATTERNS.search(response_body)
    if match:
        return True, match.group(0)[:80]
    # Reflected SQL query — the app leaks the assembled query string containing
    # user input (e.g. Django view rendering sql_error in template)
    match = _REFLECTED_SQL.search(response_body)
    if match:
        return True, f"reflected_sql: {match.group(0)[:80]}"
    return False, ""


# ---------------------------------------------------------------------------
# Boolean-based: compare true-condition vs false-condition responses
# ---------------------------------------------------------------------------

_SIMILARITY_THRESHOLD = 0.15  # > 15% body size change counts as different


def check_boolean_based(
    body_true: str,
    body_false: str,
) -> Tuple[bool, str]:
    """Return (triggered, reason) if true/false conditions produce noticeably different responses.

    A large body difference suggests the condition is reflected (i.e. SQLi worked).
    """
    len_true = len(body_true)
    len_false = len(body_false)

    if len_true == 0 and len_false == 0:
        return False, "both_empty"

    max_len = max(len_true, len_false) or 1
    diff_ratio = abs(len_true - len_false) / max_len

    if diff_ratio > _SIMILARITY_THRESHOLD:
        return True, f"body_size_diff_{diff_ratio:.2f}"

    return False, ""


# ---------------------------------------------------------------------------
# Time-based: latency spike detection
# ---------------------------------------------------------------------------

# Default: if response takes >3s MORE than baseline, flag as time-based hit
_TIME_THRESHOLD_MS = 3_000.0


def check_time_based(
    latency_ms: float,
    baseline_latency_ms: float,
    threshold_ms: float = _TIME_THRESHOLD_MS,
) -> Tuple[bool, str]:
    """Return (triggered, reason) if latency exceeds baseline by threshold."""
    delta = latency_ms - baseline_latency_ms
    if delta >= threshold_ms:
        return True, f"latency_delta_{delta:.0f}ms"
    return False, ""


# ---------------------------------------------------------------------------
# Coverage-based: taint-relevant sink line appears in delta
# ---------------------------------------------------------------------------

def check_coverage_based(coverage_delta: CoverageDelta) -> Tuple[bool, str]:
    """Return (triggered, reason) if a taint-relevant sink line was newly covered."""
    if coverage_delta.taint_relevant and coverage_delta.newly_covered_lines:
        lines = ", ".join(coverage_delta.newly_covered_lines[:3])
        return True, f"sink_lines_hit: {lines}"
    return False, ""


# ---------------------------------------------------------------------------
# Composite check — run all signals, return first match
# ---------------------------------------------------------------------------

def check_all(
    response_body: str,
    latency_ms: float,
    coverage_delta: CoverageDelta,
    baseline_latency_ms: float = 0.0,
    boolean_ref_body: Optional[str] = None,
) -> Tuple[bool, str, dict]:
    """Check all confirmation signals.

    Returns:
        confirmed:  True if any signal fired.
        method:     Name of the first signal that fired.
        evidence:   Dict with details for the finding record.
    """
    evidence: dict = {}

    # 1. Error-based (fastest and most reliable)
    hit, pattern = check_error_based(response_body)
    if hit:
        evidence["db_error_pattern"] = pattern
        evidence["response_snippet"] = response_body[:300]
        return True, "error_based", evidence

    # 2. Coverage-based (when we have instrumented runtime data)
    hit, reason = check_coverage_based(coverage_delta)
    if hit:
        evidence["coverage_reason"] = reason
        evidence["newly_covered"] = coverage_delta.newly_covered_lines
        return True, "coverage_based", evidence

    # 3. Boolean-based (requires a reference response body)
    if boolean_ref_body is not None:
        hit, reason = check_boolean_based(response_body, boolean_ref_body)
        if hit:
            evidence["diff_reason"] = reason
            return True, "boolean_based", evidence

    # 4. Time-based (only when a baseline latency is known)
    if baseline_latency_ms > 0:
        hit, reason = check_time_based(latency_ms, baseline_latency_ms)
        if hit:
            evidence["latency_reason"] = reason
            evidence["latency_ms"] = latency_ms
            evidence["baseline_ms"] = baseline_latency_ms
            return True, "time_based", evidence

    return False, "", {}
