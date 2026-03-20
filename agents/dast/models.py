"""Data models for the Intelligent DAST pipeline (v1 — SQLi only)."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class TaintPathSource(BaseModel):
    """Where tainted data enters the application."""
    type: str  # "query_param" | "body_param" | "header" | "path_param" | "unknown"
    name: str  # parameter or header name
    endpoint: str  # e.g. "GET /users"


class TaintPathSink(BaseModel):
    """Where tainted data reaches a dangerous function."""
    type: str  # "sql_query" | "file_op" | "http_call"
    function: str  # e.g. "db.execute"
    file: str  # relative path
    line: int


class TaintPath(BaseModel):
    """A single source-to-sink taint flow, ready for DAST probing."""
    id: str
    source: TaintPathSource
    sink: TaintPathSink
    path: List[str]  # call chain steps: ["routes/users.py:18", "services/user.py:35", ...]
    confidence: str  # "high" | "medium" | "low"
    cve_id: Optional[str] = None


class TargetInfo(BaseModel):
    base_url: str
    openapi_spec_path: Optional[str] = None


class StackInfo(BaseModel):
    language: str = "python"
    framework: Optional[str] = None  # "flask" | "fastapi" | "django"
    orm: Optional[str] = None        # "sqlalchemy" | "django_orm" | "raw"
    version: Optional[str] = None


class CoverageBaseline(BaseModel):
    # file path → list of executed line numbers
    covered_lines: Dict[str, List[int]] = Field(default_factory=dict)
    total_lines: int = 0


class DastScanContext(BaseModel):
    """Full context assembled once at scan start and passed to the steering loop."""
    target: TargetInfo
    stack: StackInfo
    taint_paths: List[TaintPath]
    cves: List[Dict[str, Any]] = Field(default_factory=list)
    coverage_baseline: CoverageBaseline = Field(default_factory=CoverageBaseline)


# ---------------------------------------------------------------------------
# Per-iteration models
# ---------------------------------------------------------------------------

class CoverageDelta(BaseModel):
    # Lines newly covered since baseline, in "file.py:lineno" format
    newly_covered_lines: List[str] = Field(default_factory=list)
    # True when at least one taint-relevant sink line was newly hit
    taint_relevant: bool = False


class RequestSpec(BaseModel):
    """The HTTP request Claude wants to send."""
    method: str = "GET"
    endpoint: str
    params: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None


class ClaudeAction(BaseModel):
    """Structured JSON that Claude emits each turn."""
    action: Literal["test", "skip", "confirm", "give_up"]
    taint_path_id: str
    request: Optional[RequestSpec] = None
    reasoning: str


class IterationRecord(BaseModel):
    """Compact history item — full response bodies are NOT stored."""
    iteration: int
    payload_sent: Dict[str, Any]  # serialised RequestSpec
    status_code: int
    response_snippet: str         # first 300 chars of body
    latency_ms: float
    coverage_delta: CoverageDelta
    signals_triggered: List[str]  # ["error_based", "time_based", ...]


# ---------------------------------------------------------------------------
# Final finding
# ---------------------------------------------------------------------------

class DastFinding(BaseModel):
    """Structured output per taint path after the probing loop completes."""
    id: str
    taint_path_id: str
    vuln_class: str = "sql_injection"
    severity: str = "high"
    endpoint: str
    parameter: str
    confirmed_payload: Optional[str] = None
    confirmation_method: Optional[str] = None  # "error_based" | "boolean_based" | "time_based" | "coverage_based"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    reasoning: str
    cve_reference: Optional[str] = None
    # "confirmed" | "exhausted" | "skipped" | "give_up"
    status: str
    iterations_used: int = 0
