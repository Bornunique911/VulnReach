"""Phase 1 — Input Assembly.

Assembles a DastScanContext from the existing ScanContext produced by earlier
pipeline agents (tainter, trivy, coverage, route_extractor).

Adapter responsibilities:
  • taint_flows (from TainterAgent metadata)  → TaintPath[]
  • coverage.json (if present in repo_path)   → CoverageBaseline
  • OpenAPI spec (if present)                 → endpoint+parameter enrichment
  • vulnerabilities                           → CVE list for context
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.models import ScanContext
from .models import (
    CoverageBaseline,
    DastScanContext,
    StackInfo,
    TaintPath,
    TaintPathSink,
    TaintPathSource,
    TargetInfo,
)

logger = logging.getLogger(__name__)

# Sink function name patterns that indicate SQL operations
_SQL_SINK_PATTERNS = re.compile(
    r"execute|query|raw|cursor|fetchall|fetchone|scalar|"
    r"filter_by|filter\(|where\(|select\(|insert\(|update\(|delete\(",
    re.IGNORECASE,
)

# Map common framework route prefixes to their variable-capture pattern
_FRAMEWORK_HINTS = {
    "flask": ("flask", "@app.route", "@blueprint.route"),
    "fastapi": ("fastapi", "@router.", "@app."),
    "django": ("django", "path(", "re_path(", "url("),
}


def assemble(
    context: ScanContext,
    base_url: str,
) -> DastScanContext:
    """Build a DastScanContext from the scan pipeline's shared ScanContext.

    Args:
        context:  The ScanContext populated by previous pipeline agents.
        base_url: The running application's base URL (from config or container).

    Returns:
        A fully assembled DastScanContext ready for the steering loop.
    """
    repo_path = Path(context.repo_path) if context.repo_path else None

    taint_paths = _build_taint_paths(context.taint_flows)

    # Enrich source endpoints from OpenAPI spec if available
    if taint_paths and repo_path:
        openapi_endpoints = _load_openapi_endpoints(repo_path)
        if openapi_endpoints:
            taint_paths = _enrich_sources(taint_paths, openapi_endpoints)

    coverage_baseline = _load_coverage_baseline(repo_path)

    stack = _detect_stack(context, repo_path)

    openapi_path: Optional[str] = None
    if repo_path:
        for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
            candidate = repo_path / name
            if candidate.exists():
                openapi_path = str(candidate)
                break

    # Compact CVE list — just id, affects, sink_type for context
    cves = [
        {
            "id": v.get("cve_id") if isinstance(v.get("cve_id"), str) else (v.get("cve_id") or [""])[0],
            "package": v.get("package"),
            "severity": v.get("severity"),
        }
        for v in context.vulnerabilities
    ]

    return DastScanContext(
        target=TargetInfo(base_url=base_url, openapi_spec_path=openapi_path),
        stack=stack,
        taint_paths=taint_paths,
        cves=cves,
        coverage_baseline=coverage_baseline,
    )


# ---------------------------------------------------------------------------
# Taint path construction
# ---------------------------------------------------------------------------

def _build_taint_paths(raw_flows: List[Dict[str, Any]]) -> List[TaintPath]:
    """Adapt tainter flow summaries (from TainterAgent metadata) into TaintPath objects."""
    paths: List[TaintPath] = []

    for i, flow in enumerate(raw_flows):
        path_id = flow.get("id") or f"tp-{i:03d}"
        vuln_class = (flow.get("vulnerability_class") or "").lower()

        # v1 scope: SQLi only — skip other classes
        if vuln_class and "sql" not in vuln_class and vuln_class not in ("", "unknown"):
            logger.debug(f"[dast][assembler] Skipping non-SQL flow {path_id} ({vuln_class})")
            continue

        # --- Sink ---
        sink_fn = flow.get("sink_function") or "execute"
        sink_file = flow.get("sink_file") or "unknown"
        sink_line = flow.get("sink_line") or 0
        sink_module = flow.get("sink_module") or ""
        sink_fn_full = f"{sink_module}.{sink_fn}".lstrip(".") if sink_module else sink_fn

        # Only include flows where the sink looks like a SQL operation
        if not _SQL_SINK_PATTERNS.search(sink_fn_full):
            # Heuristic: if vulnerability_class is sql_injection keep it anyway
            if "sql" not in vuln_class:
                continue

        # --- Source (best-effort) ---
        source_file = flow.get("source_file") or ""
        # Derive a placeholder source name from the call chain or source file
        call_chain = flow.get("call_chain") or []
        source_param = _infer_source_param(flow)
        source_endpoint = _infer_source_endpoint(source_file, call_chain)

        # --- Confidence mapping ---
        raw_conf = (flow.get("confidence") or "medium")
        if isinstance(raw_conf, (int, float)):
            conf_str = "high" if raw_conf >= 0.8 else ("medium" if raw_conf >= 0.5 else "low")
        else:
            conf_str = str(raw_conf).lower()
            if conf_str not in ("high", "medium", "low"):
                conf_str = "medium"

        paths.append(
            TaintPath(
                id=path_id,
                source=TaintPathSource(
                    type="query_param",  # default; enriched later from OpenAPI
                    name=source_param,
                    endpoint=source_endpoint,
                ),
                sink=TaintPathSink(
                    type="sql_query",
                    function=sink_fn_full,
                    file=sink_file,
                    line=sink_line,
                ),
                path=call_chain,
                confidence=conf_str,
            )
        )

    logger.info(f"[dast][assembler] Built {len(paths)} SQL taint paths from {len(raw_flows)} flows")
    return paths


def _infer_source_param(flow: Dict[str, Any]) -> str:
    """Best-effort: extract a parameter name from flow metadata."""
    source_type = (flow.get("source_type") or flow.get("source") or "").lower()
    # Tainter sometimes includes the parameter name in the source type string
    for indicator in ("user_id", "id", "name", "query", "q", "search", "username", "email"):
        if indicator in source_type:
            return indicator
    # Fall back to the source file stem as a hint
    src_file = flow.get("source_file") or ""
    stem = Path(src_file).stem if src_file else ""
    return stem or "param"


def _infer_source_endpoint(source_file: str, call_chain: List[str]) -> str:
    """Best-effort: infer the HTTP endpoint from file name / call chain."""
    hints = [source_file] + call_chain
    for hint in hints:
        # Look for route patterns like "/users", "/api/v1/items"
        match = re.search(r"['\"](/[\w/{}:<>-]+)['\"]", str(hint))
        if match:
            return match.group(1)
    # Fall back to guessing from source filename
    stem = Path(source_file).stem if source_file else ""
    if stem and stem not in ("routes", "views", "api", "app", "main"):
        return f"/{stem}"
    return "/unknown"


# ---------------------------------------------------------------------------
# OpenAPI enrichment
# ---------------------------------------------------------------------------

def _load_openapi_endpoints(repo_path: Path) -> List[Dict[str, Any]]:
    """Parse OpenAPI spec → list of {method, path, params} dicts."""
    for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
        spec_file = repo_path / name
        if not spec_file.exists():
            continue
        try:
            if name.endswith(".json"):
                spec = json.loads(spec_file.read_text(encoding="utf-8"))
            else:
                import yaml  # type: ignore
                spec = yaml.safe_load(spec_file.read_text(encoding="utf-8"))

            endpoints = []
            for path, methods in (spec.get("paths") or {}).items():
                for method, op in methods.items():
                    if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        continue
                    params = []
                    for p in (op.get("parameters") or []):
                        params.append({
                            "name": p.get("name"),
                            "in": p.get("in"),  # "query" | "path" | "header"
                        })
                    # Also extract request body fields for POST/PUT —
                    # check both application/json and form-encoded content types.
                    content = (op.get("requestBody") or {}).get("content", {})
                    for content_type in (
                        "application/json",
                        "application/x-www-form-urlencoded",
                        "multipart/form-data",
                    ):
                        body_schema = content.get(content_type, {}).get("schema", {})
                        for field_name in (body_schema.get("properties") or {}):
                            params.append({"name": field_name, "in": "body"})

                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "params": params,
                    })
            logger.info(f"[dast][assembler] Loaded {len(endpoints)} endpoints from {name}")
            return endpoints
        except Exception as exc:
            logger.warning(f"[dast][assembler] Could not parse {name}: {exc}")

    return []


def _enrich_sources(
    taint_paths: List[TaintPath],
    endpoints: List[Dict[str, Any]],
) -> List[TaintPath]:
    """Match taint path source endpoints to concrete OpenAPI params."""
    for tp in taint_paths:
        if tp.source.endpoint != "/unknown":
            # Exact / pattern match against OpenAPI path
            matched = _match_endpoint_exact(tp.source.endpoint, endpoints)
        else:
            # Fallback: fuzzy-match using call chain (view fn name) + sink info
            matched = _match_endpoint_fuzzy(tp.sink.function, tp.sink.file, tp.path, endpoints)

        if not matched:
            continue

        ep = matched
        for param in ep["params"]:
            pname = param.get("name") or ""
            pin = param.get("in") or ""
            if not pname:
                continue
            if pin in ("query", "body"):
                tp.source.name = pname
                tp.source.type = "query_param" if pin == "query" else "body_param"
                tp.source.endpoint = f"{ep['method']} {ep['path']}"
                break

    return taint_paths


def _match_endpoint_exact(
    endpoint: str, endpoints: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Return the first OpenAPI endpoint whose path matches the given endpoint string."""
    for ep in endpoints:
        ep_path = ep["path"]
        pattern = re.sub(r"\{[^}]+\}", r"[^/]+", re.escape(ep_path))
        if re.fullmatch(pattern, endpoint):
            return ep
    return None


def _match_endpoint_fuzzy(
    sink_fn: str, sink_file: str, call_chain: List[str], endpoints: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """When endpoint is unknown, score OpenAPI endpoints by token overlap with
    the sink function name and file path, then return the best match that has
    at least one injectable (query/body) parameter.

    Example: sink_fn="search_posts" matches "/api/posts/search/" because
    both "search" and "posts" appear in the path.
    """
    _GENERIC = {"", "execute", "query", "cursor", "views", "api", "app", "main", "routes", "db", "models"}
    # Prefer the view function name from the call chain (e.g. "api.views.search_posts" → "search_posts")
    view_fn = call_chain[-1].split(".")[-1] if call_chain else ""
    fn_tokens = set(re.split(r"[_\W]+", view_fn.lower())) - _GENERIC
    # Fall back to sink function tokens if call chain gave nothing useful
    if not fn_tokens:
        fn_tokens = set(re.split(r"[_\W]+", sink_fn.lower())) - _GENERIC
    # Add tokens from the last two segments of sink file path
    file_parts = set(Path(sink_file).parts[-2:]) if sink_file else set()
    fn_tokens |= {p.lower().replace(".py", "") for p in file_parts} - _GENERIC

    if not fn_tokens:
        return None

    best_ep: Optional[Dict[str, Any]] = None
    best_score = 0

    for ep in endpoints:
        # Only consider endpoints with injectable params
        has_injectable = any(p.get("in") in ("query", "body") for p in ep["params"])
        if not has_injectable:
            continue
        path_tokens = set(re.split(r"[/_\-{}]+", ep["path"].lower())) - {"", "api", "v1", "v2"}
        score = len(fn_tokens & path_tokens)
        if score > best_score:
            best_score = score
            best_ep = ep

    if best_ep and best_score > 0:
        logger.info(
            f"[dast][assembler] Fuzzy-matched sink '{sink_fn}' → {best_ep['method']} {best_ep['path']} "
            f"(score={best_score})"
        )
    return best_ep if best_score > 0 else None


# ---------------------------------------------------------------------------
# Coverage baseline
# ---------------------------------------------------------------------------

def _load_coverage_baseline(repo_path: Optional[Path]) -> CoverageBaseline:
    """Load coverage.json from repo root (written by DynamicReachabilityAgent)."""
    if not repo_path:
        return CoverageBaseline()

    cov_file = repo_path / "coverage.json"
    if not cov_file.exists():
        return CoverageBaseline()

    try:
        data = json.loads(cov_file.read_text(encoding="utf-8"))
        covered: Dict[str, List[int]] = {}
        total = 0
        for filepath, info in (data.get("files") or {}).items():
            executed = info.get("executed_lines") or []
            covered[filepath] = executed
            total += len(info.get("executed_lines") or []) + len(info.get("missing_lines") or [])
        logger.info(f"[dast][assembler] Loaded coverage baseline: {len(covered)} files")
        return CoverageBaseline(covered_lines=covered, total_lines=total)
    except Exception as exc:
        logger.warning(f"[dast][assembler] Could not load coverage.json: {exc}")
        return CoverageBaseline()


# ---------------------------------------------------------------------------
# Stack detection
# ---------------------------------------------------------------------------

def _detect_stack(context: ScanContext, repo_path: Optional[Path]) -> StackInfo:
    """Detect Python framework and ORM from installed packages and source files."""
    framework: Optional[str] = None
    orm: Optional[str] = None

    # Check import_map (populated by MetadataAgent)
    pkg_names = set(context.import_map.keys())
    if "flask" in pkg_names:
        framework = "flask"
    elif "fastapi" in pkg_names:
        framework = "fastapi"
    elif "django" in pkg_names:
        framework = "django"

    if "sqlalchemy" in pkg_names:
        orm = "sqlalchemy"
    elif "django" in pkg_names and framework == "django":
        orm = "django_orm"
    elif "databases" in pkg_names or "asyncpg" in pkg_names:
        orm = "raw_async"

    # Fall back: scan requirements.txt if import_map is empty
    if not framework and repo_path:
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            content = req_file.read_text(encoding="utf-8").lower()
            if "flask" in content:
                framework = "flask"
            elif "fastapi" in content:
                framework = "fastapi"
            elif "django" in content:
                framework = "django"
            if "sqlalchemy" in content:
                orm = "sqlalchemy"

    return StackInfo(language="python", framework=framework, orm=orm)
