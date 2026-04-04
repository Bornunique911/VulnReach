"""RouteExtractorAgent wraps static route extraction as a tool."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.agent import BaseTool
from core.models import AgentResult, RouteFinding, ScanContext

EXCLUDE_DIRS = {"env", "venv", ".venv", "tests", "security_findings", "build", "dist", ".git", "__pycache__"}
SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


@dataclass
class Route:
    method: str
    path: str
    handler: Optional[str]
    file: str
    framework: str
    prefix: Optional[str] = None


def extract_routes(project_root: str) -> List[Route]:
    routes: List[Route] = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for name in files:
            if name.endswith(".py"):
                routes.extend(_parse_python_routes(os.path.join(root, name), project_root))
                routes.extend(_parse_django_routes(os.path.join(root, name), project_root))
            elif name.endswith(".js"):
                routes.extend(_parse_express_routes(os.path.join(root, name), project_root))
            elif name.endswith(".java"):
                routes.extend(_parse_spring_routes(os.path.join(root, name), project_root))
    return routes


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except Exception:
        return path


# ------------------ Python: Flask / FastAPI ------------------

def _parse_python_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return routes

    pending_decorators: List[Dict[str, str]] = []

    for line in lines:
        deco = line.strip()
        route_match = re.match(r"@(\w+)\.route\(\s*['\"]([^'\"]+)", deco)
        fastapi_match = re.match(r"@(\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)", deco, re.IGNORECASE)

        if route_match:
            obj, path_str = route_match.groups()
            methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", deco, re.IGNORECASE)
            methods = _extract_methods(methods_match.group(1)) if methods_match else ["GET"]
            for m in methods:
                pending_decorators.append({"method": m, "path": path_str, "framework": "flask"})
            continue

        if fastapi_match:
            obj, method, path_str = fastapi_match.groups()
            pending_decorators.append({"method": method.upper(), "path": path_str, "framework": "fastapi"})
            continue

        func_match = re.match(r"def\s+(\w+)\s*\(", deco)
        if func_match and pending_decorators:
            handler = func_match.group(1)
            for deco_info in pending_decorators:
                routes.append(
                    Route(
                        method=deco_info["method"],
                        path=deco_info["path"],
                        handler=handler,
                        file=_rel(path, project_root),
                        framework=deco_info["framework"],
                    )
                )
            pending_decorators = []

    return routes


def _extract_methods(raw: str) -> List[str]:
    methods = []
    for token in raw.split(','):
        t = token.strip().strip("'\" ").upper()
        if t in SUPPORTED_METHODS:
            methods.append(t)
    return methods or ["GET"]


# ------------------ Node.js: Express ------------------

def _parse_express_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    prefix_map: Dict[str, str] = {}
    call_re = re.compile(r"(app|router|\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)")
    use_re = re.compile(r"app\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\w+)\s*\)")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return routes

    for match in use_re.finditer(content):
        prefix, router_var = match.groups()
        prefix_map[router_var] = prefix

    for match in call_re.finditer(content):
        obj, method, route_path = match.groups()
        method_upper = method.upper()
        if method_upper not in SUPPORTED_METHODS:
            continue
        prefix = prefix_map.get(obj)
        full_path = f"{prefix.rstrip('/')}{route_path}" if prefix else route_path
        handler = _extract_handler_from_call(content, match.end())
        routes.append(
            Route(
                method=method_upper,
                path=full_path,
                handler=handler,
                file=_rel(path, project_root),
                framework="express",
                prefix=prefix,
            )
        )

    return routes


def _extract_handler_from_call(content: str, start_idx: int) -> Optional[str]:
    tail = content[start_idx: content.find('\n', start_idx)]
    handler_match = re.search(r"['\"]\s*,\s*([A-Za-z_][\w]*)", tail)
    return handler_match.group(1) if handler_match else None


# ------------------ Java: Spring Boot ------------------

def _parse_spring_routes(path: str, project_root: str) -> List[Route]:
    routes: List[Route] = []
    class_prefix = None
    pending_method_annotations: List[Dict[str, str]] = []

    mapping_re = re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\(([^)]*)\)")
    class_re = re.compile(r"public\s+class\s+(\w+)")
    method_re = re.compile(r"public\s+[\w<>,\s]+\s+(\w+)\s*\(")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return routes

    for line in lines:
        line_stripped = line.strip()

        class_match = class_re.search(line_stripped)
        if class_match:
            class_prefix = None
            pending_method_annotations = []
            continue

        map_match = mapping_re.search(line_stripped)
        if map_match:
            mapping, params = map_match.groups()
            method = _spring_mapping_to_method(mapping, params)
            path_str = _spring_extract_path(params)

            if mapping == "RequestMapping" and path_str and method is None:
                class_prefix = path_str
                continue

            if method and path_str:
                pending_method_annotations.append({"method": method, "path": path_str})
            continue

        method_match = method_re.search(line_stripped)
        if method_match and pending_method_annotations:
            handler = method_match.group(1)
            for ann in pending_method_annotations:
                prefix = class_prefix or ""
                full_path = f"{prefix.rstrip('/')}{ann['path']}" if prefix else ann['path']
                routes.append(
                    Route(
                        method=ann["method"],
                        path=full_path or "/",
                        handler=handler,
                        file=_rel(path, project_root),
                        framework="spring",
                        prefix=class_prefix,
                    )
                )
            pending_method_annotations = []

    return routes


def _spring_mapping_to_method(mapping: str, params: str) -> Optional[str]:
    if mapping != "RequestMapping":
        return mapping.replace("Mapping", "").upper()
    method_match = re.search(r"method\s*=\s*RequestMethod\.([A-Z]+)", params)
    if method_match:
        return method_match.group(1)
    return None


def _spring_extract_path(params: str) -> Optional[str]:
    path_match = re.search(r"path\s*=\s*\{?['\"]([^'\"}]+)", params)
    if not path_match:
        path_match = re.search(r"value\s*=\s*\{?['\"]([^'\"}]+)", params)
    return path_match.group(1) if path_match else None


# ------------------ Python: Django ------------------

def _clean_django_path(pattern: str) -> str:
    """Normalise a Django URL pattern string to a display path."""
    clean = pattern.lstrip("^").rstrip("$")
    # Convert Django 2+ angle-bracket converters: <int:pk> → {pk}
    clean = re.sub(r"<\w+:(\w+)>", r"{\1}", clean)
    clean = re.sub(r"<(\w+)>", r"{\1}", clean)
    # Convert regex named groups: (?P<pk>\d+) → {pk}
    clean = re.sub(r"\(\?P<(\w+)>[^)]+\)", r"{\1}", clean)
    # Strip trailing regex quantifiers that aren't path separators
    clean = re.sub(r"(?<!/)[+*?]", "", clean)
    if not clean.startswith("/"):
        clean = "/" + clean
    return clean


def _parse_django_routes(path: str, project_root: str) -> List[Route]:
    """Parse Django URL patterns from urls.py / url conf files.

    Handles:
      - path('route/', view)          – Django 2+ ``path``
      - re_path(r'^route/', view)     – Django 2+ ``re_path``
      - url(r'^route/', view)         – Django 1.x ``url``
      - router.register(r'prefix', …) – DRF DefaultRouter / SimpleRouter
      - @api_view(['GET', 'POST'])     – DRF function-based view decorator
    """
    routes: List[Route] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return routes

    # Quick pre-filter: skip files with no Django URL signals
    if not any(
        tok in content
        for tok in ("urlpatterns", "router.register", "api_view", "re_path", "include(")
    ):
        return routes

    lines = content.splitlines()

    # ── path() / re_path() / url() ─────────────────────────────────────────
    url_re = re.compile(
        r"(?:^|[(\[,])\s*(?:path|re_path|url)\s*\(\s*r?['\"]([^'\"]*)['\"]",
        re.MULTILINE,
    )
    for m in url_re.finditer(content):
        raw = m.group(1)
        # Skip include() redirects (they contain no view handler themselves)
        # and empty paths handled by include()
        clean = _clean_django_path(raw)
        routes.append(
            Route(
                method="GET",
                path=clean,
                handler=None,
                file=_rel(path, project_root),
                framework="django",
            )
        )

    # ── DRF router.register() ──────────────────────────────────────────────
    router_re = re.compile(
        r"router\.register\s*\(\s*r?['\"]([^'\"]*)['\"]",
        re.IGNORECASE,
    )
    for m in router_re.finditer(content):
        prefix = _clean_django_path(m.group(1))
        routes.append(
            Route(
                method="GET",
                path=prefix.rstrip("/") + "/",
                handler=None,
                file=_rel(path, project_root),
                framework="django-rest",
            )
        )

    # ── @api_view decorator ────────────────────────────────────────────────
    api_view_re = re.compile(r"@api_view\s*\(\s*\[([^\]]+)\]\s*\)")
    pending: List[str] = []
    for line in lines:
        av_m = api_view_re.search(line)
        if av_m:
            raw_methods = av_m.group(1)
            pending = [
                m.strip().strip("'\" ").upper()
                for m in raw_methods.split(",")
                if m.strip().strip("'\" ").upper() in SUPPORTED_METHODS
            ]
            continue
        if pending:
            func_m = re.match(r"def\s+(\w+)\s*\(", line.strip())
            if func_m:
                for method in pending:
                    routes.append(
                        Route(
                            method=method,
                            path="/",
                            handler=func_m.group(1),
                            file=_rel(path, project_root),
                            framework="django-rest",
                        )
                    )
                pending = []
            elif line.strip():
                pending = []

    return routes


class RouteExtractorAgent(BaseTool):
    tool_name = "route_extractor"

    def __init__(self, timeout_seconds: int = 60) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.repo_path:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "missing_repo_path"})

        repo_path = os.path.abspath(context.repo_path)
        if not os.path.exists(repo_path):
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": repo_path},
            )

        try:
            routes: List[Route] = await asyncio.wait_for(asyncio.to_thread(extract_routes, repo_path), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "route_extraction_timeout"})
        except Exception as exc:  # pragma: no cover
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "route_extraction_failed", "details": str(exc)})

        findings = [RouteFinding.model_validate(r.__dict__).model_dump() for r in routes]
        metadata = {"status": "ok", "raw": [r.__dict__ for r in routes], "finding_count": len(findings)}
        return AgentResult.model_validate({"tool_name": self.tool_name, "findings": findings, "metadata": metadata})

