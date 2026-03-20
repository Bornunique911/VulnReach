"""OpenAPI Generator Agent — LLM-based OpenAPI spec inference.

Flow:
  Step 1 — Pre-flight:
    • Dockerfile present?       → no  → skip (dynamic reachability won't run anyway)
    • OpenAPI spec present?     → yes → skip (nothing to generate)
    • openapi_generator enabled?→ no  → skip
    • API key available?        → no  → skip

  Step 2 — Collect source context
    Reads the app's entry-point and route files (up to _MAX_SOURCE_FILES,
    truncated to _MAX_FILE_CHARS each) to give the LLM enough signal to
    infer paths, methods, and request/response shapes.

  Step 3 — Call LLM
    Sends a structured prompt to the configured provider (Anthropic / OpenAI)
    requesting a valid OpenAPI 3.0 JSON document.

  Step 4 — Write openapi.json
    Validates the response contains minimal OpenAPI structure, then writes
    openapi.json to the repo root so dynamic_reachability can use it.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.agent import BaseAgent
from core.models import AgentResult, ScanContext

logger = logging.getLogger(__name__)

# Files to probe, in priority order.  All paths are relative to repo root.
_ENTRY_POINTS = (
    "app.py", "main.py", "wsgi.py", "asgi.py", "server.py",
    "application.py", "run.py",
)
_ROUTE_FILES = (
    "routes.py", "views.py", "api.py", "urls.py",
    "router.py", "endpoints.py",
)
_SCHEMA_FILES = (
    "models.py", "schemas.py", "serializers.py",
)

# How many source files to read (keeps prompt within token budget).
_MAX_SOURCE_FILES = 6
# Characters to include per file (avoids blowing the context window).
_MAX_FILE_CHARS = 3_000

# Regex patterns that indicate a file defines routes.
_ROUTE_PATTERNS = re.compile(
    r"@app\.route|@router\.(get|post|put|patch|delete)|"
    r"router\.add_api_route|path\(|re_path\(|url\(",
    re.IGNORECASE,
)

_SYSTEM_PROMPT = """\
You are an expert in REST API design and OpenAPI 3.0 specifications.
You will receive Python source files from a web application.
Your task is to infer a complete, valid OpenAPI 3.0 JSON specification.

Rules:
- Return ONLY the raw JSON — no markdown fences, no explanation.
- The JSON must have "openapi", "info", and "paths" top-level keys.
- Use "openapi": "3.0.0" and infer a reasonable "info.title" from the code.
- For every route you can identify, add an entry under "paths".
- Include request body schemas and response schemas where inferable.
- If you cannot confidently determine a schema, use {} or a generic object.
- Do not invent endpoints not evidenced by the source code.
"""

_USER_PROMPT_TEMPLATE = """\
Here are the source files for the Python web application.
Generate the OpenAPI 3.0 JSON specification based on the routes and schemas you can identify.

{file_sections}

Return ONLY valid JSON — no markdown, no explanation.
"""


class OpenAPIGeneratorAgent(BaseAgent):
    tool_name = "openapi_generator"

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        # ------------------------------------------------------------------
        # Step 1 — Pre-flight
        # ------------------------------------------------------------------
        if not context.repo_path:
            return self._skipped("missing_repo_path")

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return self._skipped("repo_path_not_found")

        # Only useful if dynamic reachability will run.
        dockerfile = repo_path / "Dockerfile"
        if not dockerfile.exists():
            return self._skipped("no_dockerfile")

        # If an OpenAPI spec already exists, nothing to do.
        existing = self._find_existing_spec(repo_path)
        if existing:
            logger.info(f"[openapi_gen] OpenAPI spec already exists at {existing} — skipping")
            return self._skipped("openapi_spec_already_exists")

        # Check config.
        cfg = self._get_config(context)
        if not cfg.get("enabled"):
            return self._skipped("openapi_generator_not_enabled")

        api_key = self._resolve_api_key(cfg)
        if not api_key:
            env_var = cfg.get("api_key_env", "ANTHROPIC_API_KEY")
            logger.warning(f"[openapi_gen] API key env var {env_var!r} not set — skipping")
            return self._skipped(f"api_key_not_set:{env_var}")

        # ------------------------------------------------------------------
        # Step 2 — Collect source context
        # ------------------------------------------------------------------
        source_files = self._collect_source_files(repo_path)
        if not source_files:
            return self._skipped("no_source_files_found")

        logger.info(f"[openapi_gen] Using {len(source_files)} source files for LLM context")

        # ------------------------------------------------------------------
        # Step 3 — Call LLM
        # ------------------------------------------------------------------
        spec_json, llm_meta = await self._call_llm(cfg, api_key, source_files)
        if spec_json is None:
            return AgentResult(
                tool_name=self.tool_name,
                status="failed",
                findings=[],
                metadata={**llm_meta, "source_files": [p for p, _ in source_files]},
            )

        # ------------------------------------------------------------------
        # Step 4 — Write openapi.json
        # ------------------------------------------------------------------
        out_path = repo_path / "openapi.json"
        try:
            out_path.write_text(json.dumps(spec_json, indent=2), encoding="utf-8")
        except OSError as exc:
            return AgentResult(
                tool_name=self.tool_name,
                status="failed",
                findings=[],
                metadata={"error": "write_failed", "details": str(exc)},
            )

        paths_count = len(spec_json.get("paths", {}))
        logger.info(f"[openapi_gen] Wrote {out_path} ({paths_count} paths)")

        return AgentResult(
            tool_name=self.tool_name,
            findings=[],
            metadata={
                "status": "ok",
                "output_path": str(out_path),
                "paths_count": paths_count,
                "source_files": [p for p, _ in source_files],
                "llm": llm_meta,
            },
        )

    # ------------------------------------------------------------------
    # Pre-flight helpers
    # ------------------------------------------------------------------

    def _find_existing_spec(self, repo_path: Path) -> Optional[str]:
        for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
            candidate = repo_path / name
            if candidate.exists():
                return str(candidate)
        return None

    def _get_config(self, context: ScanContext) -> Dict[str, Any]:
        """Extract openapi_generator settings from context.config, return dict."""
        try:
            cfg_obj = context.config.scan.openapi_generator  # type: ignore[union-attr]
            return cfg_obj.model_dump()
        except AttributeError:
            return {}

    def _resolve_api_key(self, cfg: Dict[str, Any]) -> Optional[str]:
        """Read API key from the env var named in config."""
        env_var = cfg.get("api_key_env", "ANTHROPIC_API_KEY")
        return os.environ.get(env_var) or None

    # ------------------------------------------------------------------
    # Step 2 — Source file collection
    # ------------------------------------------------------------------

    def _collect_source_files(self, repo_path: Path) -> List[Tuple[str, str]]:
        """
        Collect (relative_path, truncated_content) pairs from the repo.

        Priority:
          1. Named entry-points and route files (exact matches).
          2. Any .py file in root or one level deep that contains route decorators.
          3. Named schema files.

        Capped at _MAX_SOURCE_FILES total.
        """
        candidates: List[Path] = []
        seen: set[Path] = set()

        def _add(p: Path) -> None:
            if p.exists() and p not in seen and p.suffix == ".py":
                candidates.append(p)
                seen.add(p)

        # 1. Named entry-points and route files
        for name in (*_ENTRY_POINTS, *_ROUTE_FILES):
            _add(repo_path / name)
            # also look one level deep (e.g. src/app.py, api/routes.py)
            for sub in repo_path.iterdir():
                if sub.is_dir() and not sub.name.startswith("."):
                    _add(sub / name)

        # 2. Files with route patterns not yet picked up
        if len(candidates) < _MAX_SOURCE_FILES:
            for py_file in sorted(repo_path.rglob("*.py")):
                if py_file in seen:
                    continue
                if len(candidates) >= _MAX_SOURCE_FILES * 2:
                    break
                try:
                    text = py_file.read_text(encoding="utf-8", errors="replace")
                    if _ROUTE_PATTERNS.search(text):
                        candidates.append(py_file)
                        seen.add(py_file)
                except OSError:
                    pass

        # 3. Named schema files (append at end, lower priority)
        for name in _SCHEMA_FILES:
            _add(repo_path / name)

        # Build result list, capped and truncated
        result: List[Tuple[str, str]] = []
        for path in candidates[:_MAX_SOURCE_FILES]:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                if len(content) > _MAX_FILE_CHARS:
                    content = content[:_MAX_FILE_CHARS] + "\n... (truncated)"
                rel = str(path.relative_to(repo_path))
                result.append((rel, content))
            except OSError:
                pass

        return result

    # ------------------------------------------------------------------
    # Step 3 — LLM call (Anthropic / OpenAI)
    # ------------------------------------------------------------------

    async def _call_llm(
        self,
        cfg: Dict[str, Any],
        api_key: str,
        source_files: List[Tuple[str, str]],
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Call the configured LLM and parse the OpenAPI JSON from the response."""
        file_sections = "\n\n".join(
            f"### {rel_path}\n```python\n{content}\n```"
            for rel_path, content in source_files
        )
        user_prompt = _USER_PROMPT_TEMPLATE.format(file_sections=file_sections)

        provider = cfg.get("provider", "anthropic")
        model = cfg.get("model", "claude-sonnet-4-6")
        max_tokens = cfg.get("max_tokens", 4096)

        if provider == "anthropic":
            return await self._call_anthropic(api_key, model, max_tokens, user_prompt)
        elif provider == "openai":
            return await self._call_openai(api_key, model, max_tokens, user_prompt)
        else:
            return None, {"error": f"unknown_provider:{provider}"}

    async def _call_anthropic(
        self,
        api_key: str,
        model: str,
        max_tokens: int,
        user_prompt: str,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        try:
            import anthropic
        except ImportError:
            return None, {"error": "anthropic_sdk_not_installed"}

        try:
            client = anthropic.Anthropic(api_key=api_key)
            # Run in executor to avoid blocking the event loop
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                ),
            )
            raw_text = response.content[0].text
            meta = {
                "provider": "anthropic",
                "model": model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        except Exception as exc:
            logger.error(f"[openapi_gen] Anthropic call failed: {exc}")
            return None, {"error": "anthropic_call_failed", "details": str(exc)}

        return self._parse_llm_json(raw_text), meta

    async def _call_openai(
        self,
        api_key: str,
        model: str,
        max_tokens: int,
        user_prompt: str,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        try:
            import openai
        except ImportError:
            return None, {"error": "openai_sdk_not_installed"}

        try:
            client = openai.OpenAI(api_key=api_key)
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                ),
            )
            raw_text = response.choices[0].message.content or ""
            usage = response.usage
            meta = {
                "provider": "openai",
                "model": model,
                "input_tokens": usage.prompt_tokens if usage else None,
                "output_tokens": usage.completion_tokens if usage else None,
            }
        except Exception as exc:
            logger.error(f"[openapi_gen] OpenAI call failed: {exc}")
            return None, {"error": "openai_call_failed", "details": str(exc)}

        return self._parse_llm_json(raw_text), meta

    # ------------------------------------------------------------------
    # Step 4 helper — JSON extraction + validation
    # ------------------------------------------------------------------

    def _parse_llm_json(self, raw: str) -> Optional[Dict[str, Any]]:
        """
        Extract and validate JSON from LLM response.
        Handles responses wrapped in markdown code fences.
        """
        text = raw.strip()

        # Strip markdown code fences if present (```json ... ``` or ``` ... ```)
        fence_match = re.search(r"```(?:json)?\s*\n?([\s\S]+?)\n?```", text)
        if fence_match:
            text = fence_match.group(1).strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object within surrounding text
            obj_match = re.search(r"\{[\s\S]+\}", text)
            if obj_match:
                try:
                    data = json.loads(obj_match.group(0))
                except json.JSONDecodeError:
                    logger.error("[openapi_gen] Could not parse JSON from LLM response")
                    return None
            else:
                logger.error("[openapi_gen] No JSON object found in LLM response")
                return None

        if not isinstance(data, dict):
            logger.error("[openapi_gen] LLM response is not a JSON object")
            return None

        # Minimal OpenAPI structure check
        if "openapi" not in data or "paths" not in data:
            logger.error(
                f"[openapi_gen] Response missing required keys — got: {list(data.keys())[:10]}"
            )
            return None

        return data

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _skipped(self, reason: str) -> AgentResult:
        logger.info(f"[openapi_gen] Skipped — {reason}")
        return AgentResult(
            tool_name=self.tool_name,
            status="skipped",
            findings=[],
            metadata={"reason": reason},
        )
