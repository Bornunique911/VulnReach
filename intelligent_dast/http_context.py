"""Build an HttpContext from an AttackFlow, optionally enriched by an OpenAPI spec.

Three-layer resolution:
  Layer 1 — infer param location + method from taint source patterns
  Layer 2 — overlay with OpenAPI spec (if provided)
  Layer 3 — fallback defaults

No external dependencies — stdlib only.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AttackFlow, HttpContext, HttpMethod, ParamLocation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer 1 — source pattern → ParamLocation + method hint
# ---------------------------------------------------------------------------

# (pattern compiled regex, ParamLocation, HttpMethod hint)
_SOURCE_PATTERNS: List[tuple[re.Pattern[str], ParamLocation, HttpMethod]] = [
    # Django-style patterns (must be before generic "form" match)
    (re.compile(r"POST\.get|POST\[", re.IGNORECASE), ParamLocation.BODY_FORM, HttpMethod.POST),
    (re.compile(r"GET\.get|GET\[", re.IGNORECASE), ParamLocation.QUERY, HttpMethod.GET),
    (re.compile(r"data\.get|data\[", re.IGNORECASE), ParamLocation.BODY_JSON, HttpMethod.POST),
    # Flask / generic patterns
    (re.compile(r"args\.get|query", re.IGNORECASE), ParamLocation.QUERY, HttpMethod.GET),
    (re.compile(r"form", re.IGNORECASE), ParamLocation.BODY_FORM, HttpMethod.POST),
    (re.compile(r"get_json|\.json", re.IGNORECASE), ParamLocation.BODY_JSON, HttpMethod.POST),
    (re.compile(r"view_args|<\w+>", re.IGNORECASE), ParamLocation.PATH, HttpMethod.GET),
    (re.compile(r"headers\.get", re.IGNORECASE), ParamLocation.HEADER, HttpMethod.GET),
    (re.compile(r"cookies\.get", re.IGNORECASE), ParamLocation.COOKIE, HttpMethod.GET),
]

# Extract param name from .get('name') or .get("name") or ['name'] or ["name"]
_GET_CALL_PARAM = re.compile(r"""(?:\.get\(\s*|[\[]\s*)['"]([^'"]+)['"]""")

# Generic tokens to exclude when building URL path hints
_GENERIC_TOKENS = frozenset({
    "", "app", "api", "main", "views", "routes", "urls", "handlers",
    "db", "models", "utils", "helpers", "services", "core",
})


def build_http_context(
    flow: AttackFlow,
    base_url: str,
    openapi_spec: Optional[Dict[str, Any]] = None,
) -> HttpContext:
    """Construct an HttpContext for probing an AttackFlow.

    Args:
        flow:         The parsed taint flow to probe.
        base_url:     Target application base URL (e.g. "http://localhost:3000").
        openapi_spec: Parsed OpenAPI spec dict (optional). Expected to have a
                      "paths" key mapping path strings to method→operation dicts.

    Returns:
        An HttpContext ready to be used by the steering loop.
    """
    base_url = base_url.rstrip("/")

    # --- Detect indirect source (function parameter, not request attribute) ---
    source_type = "direct"
    source_attr = flow.source_definition.attribute or ""
    if source_attr.startswith("param:"):
        source_type = "indirect"

    # --- Layer 1: infer from taint source ---
    param_location: Optional[ParamLocation] = None
    method_hint: Optional[HttpMethod] = None

    # Check source attribute, function, and source code for patterns
    source_signals = " ".join([
        source_attr,
        flow.source_definition.function,
        flow.source_code,
    ])

    for pattern, ploc, mhint in _SOURCE_PATTERNS:
        if pattern.search(source_signals):
            param_location = ploc
            method_hint = mhint
            break

    # For indirect sources, scan steps for the real HTTP input (e.g. request.POST["url"])
    step_param_name = ""
    if source_type == "indirect" and flow.steps:
        step_param_name, step_loc, step_method = _scan_steps_for_http_input(flow.steps)
        if step_param_name:
            param_location = step_loc
            method_hint = step_method

    # Extract param_name from source code: request.args.get('data', ...) → "data"
    param_name = _extract_param_name(flow.source_code)

    # For indirect sources, prefer param name found in steps over source code
    if not param_name and step_param_name:
        param_name = step_param_name

    if not param_name:
        if source_type == "indirect":
            # Use the variable name from "param:variable_name"
            param_name = source_attr.split(":", 1)[1] or "param"
        else:
            param_name = source_attr or "param"

    # Infer URL path from call chain
    url_path = _infer_url_path(flow.call_chain, flow.source_location.file)
    url_confidence = "inferred" if url_path != "/unknown" else "fallback"
    logger.debug(
        f"[http_context] flow={flow.id}: url_path={url_path} "
        f"confidence={url_confidence} (from call_chain={flow.call_chain})"
    )

    # --- Layer 2: OpenAPI overlay ---
    spec_description: Optional[str] = None
    extra_params: Dict[str, str] = {}

    if openapi_spec:
        spec_result = _match_openapi(
            openapi_spec, flow.call_chain, flow.sink_definition.function,
            flow.sink_location.file, param_name,
        )
        if spec_result:
            spec_path, spec_method, spec_param_in, spec_param_schema, spec_description = spec_result
            url_path = spec_path
            url_confidence = "spec"
            if spec_method:
                method_hint = HttpMethod(spec_method)
            if spec_param_in:
                param_location = _openapi_in_to_param_location(spec_param_in)

            # Extract extra required params with benign defaults from the spec
            extra_params = _extract_extra_params(openapi_spec, spec_path, spec_method, param_name)

            logger.info(
                f"[http_context] flow={flow.id}: url resolved via spec → {spec_path}"
            )
        else:
            logger.info(
                f"[http_context] flow={flow.id}: no OpenAPI match, "
                f"url resolved via {'inferred' if url_confidence == 'inferred' else 'fallback'} → {url_path}"
            )
    else:
        logger.info(
            f"[http_context] flow={flow.id}: url resolved via "
            f"{'inferred' if url_confidence == 'inferred' else 'fallback'} → {url_path}"
        )

    # --- Layer 3: fallback ---
    if param_location is None:
        param_location = ParamLocation.QUERY
    if method_hint is None:
        method_hint = HttpMethod.GET

    url = f"{base_url}{url_path}"

    return HttpContext(
        flow_id=flow.id,
        method=method_hint,
        url=url,
        param_name=param_name,
        param_location=param_location,
        raw_source_code=flow.source_code,
        raw_sink_code=flow.sink_code,
        url_confidence=url_confidence,
        source_type=source_type,
        spec_description=spec_description,
        extra_params=extra_params,
    )


# ---------------------------------------------------------------------------
# Param name extraction
# ---------------------------------------------------------------------------

def _scan_steps_for_http_input(
    steps: List,
) -> tuple[str, Optional[ParamLocation], Optional[HttpMethod]]:
    """Scan taint flow steps for the real HTTP input when source is indirect.

    Looks for patterns like request.POST["url"], request.GET.get("q"), etc.
    in step code snippets.

    Returns (param_name, param_location, method_hint) or ("", None, None).
    """
    for step in steps:
        snippet = step.code_snippet or ""
        if not snippet:
            continue
        for pattern, ploc, mhint in _SOURCE_PATTERNS:
            if pattern.search(snippet):
                name = _extract_param_name(snippet)
                if name:
                    return name, ploc, mhint
    return "", None, None


def _extract_param_name(source_code: str) -> str:
    """Extract parameter name from a .get('name') call in source code."""
    match = _GET_CALL_PARAM.search(source_code)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# URL path inference from call chain
# ---------------------------------------------------------------------------

def _infer_url_path(call_chain: List[str], source_file: str) -> str:
    """Best-effort URL path from the call chain or source file.

    Looks for route-like patterns in the call chain first, then falls back
    to deriving a slug from the last function name in the call chain.

    For dotted entries like "introduction.views.sql_lab", the last component
    ("sql_lab") is used as the URL slug → "/sql_lab".
    For file:function entries like "routes/users.py:get_user", the function
    name ("get_user") is used → "/get_user".
    """
    # Check for explicit route patterns in call chain entries
    for entry in call_chain:
        match = re.search(r"""['"](/[\w/{}<>:-]+)['"]""", entry)
        if match:
            return match.group(1)

    # Derive URL slug from the last component of the last call chain entry
    if call_chain:
        last = call_chain[-1]
        if ":" in last:
            # "routes/users.py:get_user" → "get_user"
            func_name = last.split(":")[-1].strip().lower()
        elif "." in last:
            # "introduction.views.sql_lab" → "sql_lab"
            func_name = last.split(".")[-1].strip().lower()
        else:
            func_name = Path(last).stem.lower()

        if func_name and func_name not in _GENERIC_TOKENS:
            return f"/{func_name}"

    # Fall back to source file stem
    if source_file:
        stem = Path(source_file).stem.lower()
        if stem not in _GENERIC_TOKENS:
            return f"/{stem}"

    return "/unknown"


# ---------------------------------------------------------------------------
# OpenAPI matching
# ---------------------------------------------------------------------------

def _match_openapi(
    spec: Dict[str, Any],
    call_chain: List[str],
    sink_function: str,
    sink_file: str,
    param_name: str,
) -> Optional[tuple[str, str, str, Optional[Dict], Optional[str]]]:
    """Find the best OpenAPI operation matching this flow.

    Uses explicit matching: the spec operationId or path slug must match
    a call_chain function name. If neither matches, returns None — never
    falls back to the first/last spec entry.

    Returns (path, method, param_in, param_schema, description) or None.
    """
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return None

    # Extract the last function name from the call chain for matching
    chain_func_names: set[str] = set()
    for entry in call_chain:
        if ":" in entry:
            chain_func_names.add(entry.split(":")[-1].strip().lower())
        elif "." in entry:
            chain_func_names.add(entry.split(".")[-1].strip().lower())
    chain_func_names -= _GENERIC_TOKENS

    if not chain_func_names:
        return None

    for path_str, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        # Extract path slug tokens for matching (e.g. "/sql_lab" → {"sql_lab"})
        path_slugs = set(re.split(r"[/_\-{}]+", path_str.lower())) - {"", "api", "v1", "v2"}

        for method, operation in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(operation, dict):
                continue

            # Match 1: operationId against call_chain function names
            op_id = (operation.get("operationId") or "").lower()
            matched = op_id and op_id in chain_func_names

            # Match 2: path slug against call_chain function names
            if not matched:
                matched = bool(chain_func_names & path_slugs)

            if not matched:
                continue

            param_in, param_schema = _find_param_in_operation(operation, param_name)
            description = operation.get("description") or operation.get("summary") or None

            return (path_str, method.upper(), param_in, param_schema, description)

    return None


def _find_param_in_operation(
    operation: Dict[str, Any], param_name: str
) -> tuple[str, Optional[Dict]]:
    """Search an OpenAPI operation for a parameter by name.

    Returns (location_string, schema_or_None). location_string is one of
    "query", "path", "header", "cookie", "body", or "" if not found.
    """
    # Check parameters array
    for p in operation.get("parameters") or []:
        if not isinstance(p, dict):
            continue
        if (p.get("name") or "").lower() == param_name.lower():
            return p.get("in", ""), p.get("schema")

    # Check requestBody properties
    content = (operation.get("requestBody") or {}).get("content", {})
    for content_type in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
        body_schema = content.get(content_type, {}).get("schema", {})
        props = body_schema.get("properties") or {}
        if param_name in props:
            return "body", props[param_name]

    return "", None


def _extract_extra_params(
    spec: Dict[str, Any],
    path: str,
    method: str,
    vulnerable_param: str,
) -> Dict[str, str]:
    """Extract non-vulnerable required params from the OpenAPI spec with benign defaults.

    For endpoints that require multiple fields, the form handler may never reach
    the vulnerable code path without all required fields present.
    """
    _TYPE_DEFAULTS = {
        "string": "test",
        "integer": "1",
        "number": "1",
        "boolean": "true",
    }

    paths = spec.get("paths", {})
    operation = paths.get(path, {}).get(method.lower(), {})
    if not isinstance(operation, dict):
        return {}

    extra: Dict[str, str] = {}

    # Check requestBody for required properties
    content = (operation.get("requestBody") or {}).get("content", {})
    for content_type in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
        body_schema = content.get(content_type, {}).get("schema", {})
        required = set(body_schema.get("required", []))
        props = body_schema.get("properties") or {}
        for prop_name, prop_schema in props.items():
            if prop_name.lower() == vulnerable_param.lower():
                continue
            if prop_name in required or required == set():
                prop_type = prop_schema.get("type", "string") if isinstance(prop_schema, dict) else "string"
                extra[prop_name] = _TYPE_DEFAULTS.get(prop_type, "test")
        if extra:
            break

    return extra


def _openapi_in_to_param_location(openapi_in: str) -> ParamLocation:
    """Map OpenAPI 'in' value to ParamLocation enum."""
    mapping = {
        "query": ParamLocation.QUERY,
        "path": ParamLocation.PATH,
        "header": ParamLocation.HEADER,
        "cookie": ParamLocation.COOKIE,
        "body": ParamLocation.BODY_JSON,
    }
    return mapping.get(openapi_in, ParamLocation.QUERY)
