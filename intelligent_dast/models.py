"""Data models for the Intelligent DAST pipeline v2.

Stdlib dataclasses only — no external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VulnClass(Enum):
    SQL = "sql"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    DESERIALIZE = "deserialize"
    XXE = "xxe"
    CMDI = "cmdi"
    RCE = "rce"
    GENERIC = "generic"


class ParamLocation(Enum):
    QUERY = "query"
    BODY_JSON = "body_json"
    BODY_FORM = "body_form"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class Outcome(Enum):
    CONFIRMED = "confirmed"
    MUTATE = "mutate"
    STOP = "stop"


# ---------------------------------------------------------------------------
# Source / Sink definitions
# ---------------------------------------------------------------------------

@dataclass
class SourceDefinition:
    module: str
    function: str
    attribute: str
    framework: str


@dataclass
class SinkDefinition:
    module: str
    function: str
    vulnerable_parameters: List[int]
    vulnerability_class: str


# ---------------------------------------------------------------------------
# Flow location and steps
# ---------------------------------------------------------------------------

@dataclass
class FlowLocation:
    file: str
    line: int
    column: int


@dataclass
class FlowStep:
    location: FlowLocation
    description: str
    variable: str
    code_snippet: str
    function_name: str


# ---------------------------------------------------------------------------
# AttackFlow — a single source-to-sink data flow to probe
# ---------------------------------------------------------------------------

@dataclass
class AttackFlow:
    id: str
    vulnerability_class: VulnClass
    confidence: str
    message: str

    source_definition: SourceDefinition
    source_location: FlowLocation
    source_code: str

    sink_definition: SinkDefinition
    sink_location: FlowLocation
    sink_code: str

    steps: List[FlowStep]
    call_chain: List[str]
    variable_path: List[str]


# ---------------------------------------------------------------------------
# HTTP context for a single probe target
# ---------------------------------------------------------------------------

@dataclass
class HttpContext:
    flow_id: str
    method: HttpMethod
    url: str
    param_name: str
    param_location: ParamLocation
    param_schema: Optional[Dict] = None
    base_headers: Dict[str, str] = field(default_factory=dict)
    base_cookies: Dict[str, str] = field(default_factory=dict)
    raw_source_code: str = ""
    raw_sink_code: str = ""
    url_confidence: str = "fallback"  # "spec" | "inferred" | "fallback"
    source_type: str = "direct"  # "direct" | "indirect"
    spec_description: Optional[str] = None  # from OpenAPI operation description
    extra_params: Dict[str, str] = field(default_factory=dict)  # non-vulnerable required params with benign defaults


# ---------------------------------------------------------------------------
# Per-iteration result
# ---------------------------------------------------------------------------

@dataclass
class IterationResult:
    iteration: int
    payload: str
    request_method: str
    request_url: str
    request_body: Optional[Dict] = None
    response_status: int = 0
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# LLM analysis decision
# ---------------------------------------------------------------------------

@dataclass
class AnalysisDecision:
    outcome: Outcome
    confidence: str
    reason: str
    signal_strength: str  # "strong" | "medium" | "weak"
    suggested_payload: Optional[str] = None  # only when outcome is MUTATE


# ---------------------------------------------------------------------------
# Confirmed finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    flow_id: str
    vulnerability_class: str
    confirmed_at_iteration: int
    payload: str
    evidence: str
    request_snapshot: Dict = field(default_factory=dict)
    response_snapshot: Dict = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> Dict:
        """JSON-serializable dictionary representation."""
        data = asdict(self)
        return data
