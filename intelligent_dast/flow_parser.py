"""Parse raw VulnReach tainter JSON output into AttackFlow objects.

Input:  raw taint JSON dict (structure matches VulnReach tainter output)
Output: list[AttackFlow] + list[FlowParseError] for malformed flows

No external dependencies — stdlib only.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .models import (
    AttackFlow,
    FlowLocation,
    FlowStep,
    SinkDefinition,
    SourceDefinition,
    VulnClass,
)

logger = logging.getLogger(__name__)

# Map raw vulnerability_class strings to VulnClass enum values
_VULN_CLASS_MAP: Dict[str, VulnClass] = {
    "sql": VulnClass.SQL,
    "sql_injection": VulnClass.SQL,
    "sqli": VulnClass.SQL,
    "xss": VulnClass.XSS,
    "cross_site_scripting": VulnClass.XSS,
    "ssrf": VulnClass.SSRF,
    "server_side_request_forgery": VulnClass.SSRF,
    "ssti": VulnClass.SSTI,
    "server_side_template_injection": VulnClass.SSTI,
    "deserialization": VulnClass.DESERIALIZE,
    "deserialize": VulnClass.DESERIALIZE,
    "xxe": VulnClass.XXE,
    "xml_external_entity": VulnClass.XXE,
    "cmdi": VulnClass.CMDI,
    "command_injection": VulnClass.CMDI,
    "os_command_injection": VulnClass.CMDI,
    "rce": VulnClass.RCE,
    "remote_code_execution": VulnClass.RCE,
    "code_injection": VulnClass.RCE,
    "eval_injection": VulnClass.RCE,
}

# Sink-based refinement: when vuln class resolves to GENERIC, inspect the sink
# to infer a more specific class. Maps (module_prefix, function_set) → VulnClass.
_SINK_REFINEMENT: List[tuple] = [
    # Command injection sinks
    (("subprocess",), {"call", "run", "Popen", "check_output", "check_call"}, VulnClass.CMDI),
    (("os",), {"system", "popen", "popen2", "popen3", "popen4"}, VulnClass.CMDI),
    # Deserialization sinks
    (("pickle", "cPickle", "_pickle"), {"loads", "load"}, VulnClass.DESERIALIZE),
    (("yaml",), {"load", "unsafe_load", "full_load"}, VulnClass.DESERIALIZE),
    (("marshal",), {"loads", "load"}, VulnClass.DESERIALIZE),
    # XXE sinks
    (("xml", "lxml", "defusedxml", "xml.etree", "xml.sax", "xml.dom"), {"parse", "fromstring", "iterparse"}, VulnClass.XXE),
    # SSTI sinks
    (("jinja2",), {"from_string", "render_template_string"}, VulnClass.SSTI),
    (("flask",), {"render_template_string"}, VulnClass.SSTI),
    # RCE / eval sinks
    (("builtins",), {"eval", "exec"}, VulnClass.RCE),
]

# Only HIGH and MEDIUM confidence flows are kept
_ALLOWED_CONFIDENCE = {"HIGH", "MEDIUM"}


@dataclass
class FlowParseError:
    """Records why a single flow could not be parsed."""
    flow_id: str
    reason: str


def parse_flows(data: dict) -> Tuple[List[AttackFlow], List[FlowParseError]]:
    """Parse a raw tainter output dict into AttackFlow objects.

    Args:
        data: Top-level tainter JSON. Expected shape:
              ``{"flows": [...]}``, ``{"results": [...]}``,
              ``{"vulnerabilities": [...]}``, or a bare list.

    Returns:
        (flows, errors) — successfully parsed AttackFlows and per-flow errors.
    """
    raw_flows = _extract_flow_list(data)

    flows: List[AttackFlow] = []
    errors: List[FlowParseError] = []

    for i, raw in enumerate(raw_flows):
        if not isinstance(raw, dict):
            errors.append(FlowParseError(f"flow-{i:03d}", "entry is not a dict"))
            continue

        flow_id = raw.get("id") or f"flow-{i:03d}"
        result = _parse_single_flow(raw, flow_id)

        if isinstance(result, FlowParseError):
            errors.append(result)
        else:
            logger.debug(
                f"[flow_parser] Parsed flow {result.id} ({result.vulnerability_class.value})"
            )
            flows.append(result)

    logger.info(
        f"[flow_parser] Parsed {len(flows)} flows, {len(errors)} errors "
        f"from {len(raw_flows)} raw entries"
    )
    return flows, errors


def load_flows_from_file(
    path: str,
) -> Tuple[List[AttackFlow], List[FlowParseError]]:
    """Load and parse tainter JSON from a file path.

    Args:
        path: Path to the tainter JSON output file.

    Returns:
        (flows, errors) tuple from ``parse_flows``.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    data = json.loads(text)
    if isinstance(data, list):
        data = {"flows": data}
    return parse_flows(data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_flow_list(data: dict) -> List[Dict[str, Any]]:
    """Normalise top-level tainter output to a list of flow dicts."""
    if isinstance(data, list):
        return data
    for key in ("flows", "results", "vulnerabilities"):
        candidate = data.get(key)
        if isinstance(candidate, list):
            return candidate
    return []


def _parse_single_flow(
    raw: Dict[str, Any], flow_id: str
) -> AttackFlow | FlowParseError:
    """Parse one raw flow dict into an AttackFlow, or FlowParseError on failure."""

    # --- Confidence filter ---
    confidence = (raw.get("confidence") or "MEDIUM").upper()
    if confidence not in _ALLOWED_CONFIDENCE:
        logger.debug(f"[flow_parser] Skipping flow {flow_id}: confidence={confidence}")
        return FlowParseError(flow_id, f"confidence '{confidence}' not in {_ALLOWED_CONFIDENCE}")

    # --- Vulnerability class ---
    raw_class = (raw.get("vulnerability_class") or "").lower().strip()
    vuln_class = _VULN_CLASS_MAP.get(raw_class, VulnClass.GENERIC)

    message = raw.get("message") or ""

    # --- Source ---
    source_raw = raw.get("source")
    if not isinstance(source_raw, dict):
        return FlowParseError(flow_id, "missing or invalid 'source' object")

    source_def_raw = source_raw.get("definition") or {}
    source_loc_raw = source_raw.get("location") or {}
    source_code = source_raw.get("code") or ""

    source_definition = SourceDefinition(
        module=source_def_raw.get("module") or "",
        function=source_def_raw.get("function") or "",
        attribute=source_def_raw.get("attribute") or "",
        framework=source_def_raw.get("framework") or "",
    )
    source_location = _parse_location(source_loc_raw, flow_id, "source")

    # --- Sink ---
    sink_raw = raw.get("sink")
    if not isinstance(sink_raw, dict):
        return FlowParseError(flow_id, "missing or invalid 'sink' object")

    sink_def_raw = sink_raw.get("definition") or {}
    sink_loc_raw = sink_raw.get("location") or {}
    sink_code = sink_raw.get("code") or ""

    vuln_params = sink_def_raw.get("vulnerable_parameters") or []
    if not isinstance(vuln_params, list):
        vuln_params = []

    sink_definition = SinkDefinition(
        module=sink_def_raw.get("module") or "",
        function=sink_def_raw.get("function") or "",
        vulnerable_parameters=[int(p) for p in vuln_params if _is_int(p)],
        vulnerability_class=sink_def_raw.get("vulnerability_class") or raw_class,
    )
    sink_location = _parse_location(sink_loc_raw, flow_id, "sink")

    # --- Steps ---
    steps_raw = raw.get("steps") or []
    steps: List[FlowStep] = []
    for step_raw in steps_raw:
        if not isinstance(step_raw, dict):
            continue
        step_loc_raw = step_raw.get("location") or {}
        steps.append(FlowStep(
            location=FlowLocation(
                file=step_loc_raw.get("file") or "",
                line=int(step_loc_raw.get("line") or 0),
                column=int(step_loc_raw.get("column") or 0),
            ),
            description=step_raw.get("description") or "",
            variable=step_raw.get("variable") or "",
            code_snippet=step_raw.get("code_snippet") or "",
            function_name=step_raw.get("function_name") or "",
        ))

    # --- Call chain and variable path ---
    call_chain = raw.get("call_chain") or []
    if not isinstance(call_chain, list):
        call_chain = []
    variable_path = raw.get("variable_path") or []
    if not isinstance(variable_path, list):
        variable_path = []

    # Second-pass: refine GENERIC using sink metadata
    vuln_class = _refine_generic_class(vuln_class, sink_definition)

    return AttackFlow(
        id=flow_id,
        vulnerability_class=vuln_class,
        confidence=confidence,
        message=message,
        source_definition=source_definition,
        source_location=source_location,
        source_code=source_code,
        sink_definition=sink_definition,
        sink_location=sink_location,
        sink_code=sink_code,
        steps=steps,
        call_chain=[str(c) for c in call_chain],
        variable_path=[str(v) for v in variable_path],
    )


def _refine_generic_class(
    vuln_class: VulnClass, sink_def: SinkDefinition,
) -> VulnClass:
    """If vuln_class is GENERIC, try to infer a better class from the sink."""
    if vuln_class != VulnClass.GENERIC:
        return vuln_class

    sink_module = (sink_def.module or "").lower()
    sink_func = sink_def.function or ""

    for module_prefixes, func_set, refined_class in _SINK_REFINEMENT:
        if any(sink_module.startswith(prefix) or sink_module == prefix for prefix in module_prefixes):
            if sink_func in func_set:
                logger.info(
                    f"[flow_parser] Refined GENERIC → {refined_class.value} "
                    f"(sink: {sink_module}.{sink_func})"
                )
                return refined_class

    return vuln_class


def _parse_location(
    loc_raw: Dict[str, Any], flow_id: str, label: str
) -> FlowLocation:
    """Parse a location dict into FlowLocation."""
    return FlowLocation(
        file=loc_raw.get("file") or "",
        line=int(loc_raw.get("line") or 0),
        column=int(loc_raw.get("column") or 0),
    )


def _is_int(value: Any) -> bool:
    """Check if a value can be safely cast to int."""
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False
