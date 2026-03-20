"""Phase 2 — Intelligent DAST Steering Loop.

Claude receives the assembled DastScanContext, picks a taint path, generates a
targeted SQLi payload, executes it via httpx, reads the response + coverage
delta, and decides what to probe next — without human intervention.

Loop contract (per taint path):
  while iterations < max_iter:
      call Claude(system_prompt, dast_context, taint_path, history)
      parse ClaudeAction JSON
      if action in (confirm, skip, give_up): break
      execute HTTP request
      run confirmation signals
      if confirmed: emit DastFinding(confirmed) and break
      append compact record to history
  else:
      emit DastFinding(exhausted)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore

try:
    import anthropic as anthropic_sdk
except ImportError:
    anthropic_sdk = None  # type: ignore

try:
    from ollama import AsyncClient as OllamaAsyncClient
except ImportError:
    OllamaAsyncClient = None  # type: ignore

from .confirmation import check_all
from .models import (
    ClaudeAction,
    CoverageDelta,
    DastFinding,
    DastScanContext,
    IterationRecord,
    RequestSpec,
    TaintPath,
)

logger = logging.getLogger(__name__)

# Maximum loop iterations per taint path
_DEFAULT_MAX_ITER = 5

# Keep last N history items to avoid blowing the context window
_MAX_HISTORY = 8

# Trim response bodies to this many chars before storing in history / sending to Claude
_BODY_SNIPPET_LEN = 300

# System prompt — instructs Claude on its role and required output format
_SYSTEM_PROMPT = """\
You are a DAST (Dynamic Application Security Testing) engine embedded in a security scanner.
Your job is to confirm whether a given taint path in a Python application is exploitable \
via SQL injection.

You receive:
  • A single taint path under test (source parameter → database sink)
  • The application stack (framework, ORM)
  • A history of previous probe attempts for this path (payload sent, status code, \
response snippet, latency, signals triggered)
  • A coverage delta (whether the taint sink line was newly executed after the last request)

You MUST respond with ONLY a valid JSON object — no prose before or after it — \
in this exact schema:
{
  "action": "test | skip | confirm | give_up",
  "taint_path_id": "<id from the taint path>",
  "request": {
    "method": "GET | POST | PUT | PATCH | DELETE",
    "endpoint": "/path",
    "params": {},
    "headers": {},
    "body": null
  },
  "reasoning": "One-sentence explanation of your decision"
}

Action semantics:
  "test"     — Send this request. Include a concrete "request" object with your payload.
  "skip"     — This path is not injectable (e.g. auth-required, parameter not reflected). \
No "request" needed.
  "confirm"  — Previous attempt results provide sufficient evidence of SQL injection. \
No "request" needed.
  "give_up"  — You've exhausted useful payload variations or evidence is conclusive \
that no injection exists. No "request" needed.

Stop conditions:
  • Emit "confirm" immediately if "error_based", "coverage_based", "time_based", or \
"boolean_based" signals appeared in the history.
  • Emit "give_up" after trying at least 3 variations with no signal.
  • Emit "skip" only if the path is structurally non-injectable (not merely hard).

SQL injection strategy:
  Start with error-based probes (fastest signal):
    Classic:        ' OR 1=1--
    Closing paren:  ') OR ('1'='1
    Double-quote:   " OR 1=1--
  Then boolean-based if no error was returned:
    True condition:   ' OR 1=1--
    False condition:  ' OR 1=2--   (compare response sizes)
  Then time-based as a last resort:
    PostgreSQL:  '; SELECT pg_sleep(5)--
    MySQL:       '; SELECT SLEEP(5)--
    MSSQL:       '; WAITFOR DELAY '0:0:5'--
  Adapt payload encoding to parameter location:
    query param:       append raw to value string (GET request, use "params")
    form body (POST):  inject into the string field value in "params" dict
                       (Django views read request.POST — always use "params" for POST data)
    JSON body:         inject into the string field value in "body" dict
    path param:        URL-encode if needed
  Do not repeat an identical payload twice.
  Never ask questions. Always emit valid JSON.\
"""


class SteeringLoop:
    """LLM-steered DAST loop for SQL injection confirmation.

    Supports two providers:
      • "anthropic" — uses the Anthropic SDK (requires API credits)
      • "ollama"    — calls local Ollama via its OpenAI-compatible endpoint
                      (no API key or cloud account needed)
    """

    def __init__(
        self,
        base_url: str,
        provider: str = "anthropic",
        model: str = "claude-sonnet-4-6",
        api_key: str = "",
        ollama_base_url: str = "http://localhost:11434",
        max_iter: int = _DEFAULT_MAX_ITER,
        auth_credentials: Optional[Dict[str, Any]] = None,
    ) -> None:
        if aiohttp is None:
            raise RuntimeError("aiohttp package is required for SteeringLoop")

        self._provider = provider
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._max_iter = max_iter
        self._auth_credentials = auth_credentials or {}
        # Session cookie jar populated by _bootstrap_auth (if auth_credentials set)
        self._session_cookies: Dict[str, str] = {}

        if provider == "anthropic":
            if anthropic_sdk is None:
                raise RuntimeError("anthropic package is required when provider='anthropic'")
            if not api_key:
                raise RuntimeError("api_key is required when provider='anthropic'")
            self._anthropic_client = anthropic_sdk.Anthropic(api_key=api_key)
            self._ollama_client = None
        elif provider == "ollama":
            if OllamaAsyncClient is None:
                raise RuntimeError("ollama package is required when provider='ollama'. Run: pip install ollama")
            self._anthropic_client = None  # type: ignore[assignment]
            self._ollama_client = OllamaAsyncClient(host=ollama_base_url)
        else:
            raise RuntimeError(f"Unknown provider: {provider!r}. Use 'anthropic' or 'ollama'")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def _bootstrap_auth(self) -> None:
        """If auth_credentials are configured, log in and store the session cookie.

        Expects keys: login_url, username_field, password_field, username, password
        """
        if not self._auth_credentials:
            return

        login_url = self._auth_credentials.get("login_url", "/accounts/login/")
        username_field = self._auth_credentials.get("username_field", "login")
        password_field = self._auth_credentials.get("password_field", "password")
        username = self._auth_credentials.get("username", "")
        password = self._auth_credentials.get("password", "")

        if not username or not password:
            logger.warning("[dast][auth] auth_credentials missing username or password — skipping login")
            return

        url = f"{self._base_url}{login_url}"
        try:
            timeout = aiohttp.ClientTimeout(total=15.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    url,
                    data={username_field: username, password_field: password},
                    allow_redirects=True,
                ) as resp:
                    # After following redirects, cookies from intermediate 302
                    # responses live in the session's cookie jar, not resp.cookies.
                    from yarl import URL
                    jar_cookies = {
                        k: v.value
                        for k, v in session.cookie_jar.filter_cookies(URL(self._base_url)).items()
                    }
                    if "sessionid" in jar_cookies:
                        self._session_cookies = jar_cookies
                        logger.info(f"[dast][auth] Login successful for '{username}' at {url}")
                    else:
                        logger.warning(
                            f"[dast][auth] Login to {url} returned status={resp.status} "
                            f"but no sessionid cookie — DAST will probe unauthenticated"
                        )
        except Exception as exc:
            logger.warning(f"[dast][auth] Login request failed: {exc} — proceeding unauthenticated")

    async def run(self, dast_context: DastScanContext) -> List[DastFinding]:
        """Probe all taint paths, return a DastFinding per path."""
        await self._bootstrap_auth()

        # High confidence paths first — maximise early confirmed findings
        sorted_paths = sorted(
            dast_context.taint_paths,
            key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.confidence, 3),
        )

        findings: List[DastFinding] = []
        for taint_path in sorted_paths:
            finding = await self._probe_path(taint_path, dast_context)
            findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Per-path loop
    # ------------------------------------------------------------------

    async def _probe_path(
        self,
        taint_path: TaintPath,
        dast_context: DastScanContext,
    ) -> DastFinding:
        """Run the steering loop for a single taint path."""
        history: List[IterationRecord] = []
        # Track baseline latency for time-based comparison (average of first 2 probes)
        baseline_latency_ms: float = 0.0
        boolean_ref_body: Optional[str] = None

        for iteration in range(1, self._max_iter + 1):
            # ---- Ask Claude ----
            action = await self._ask_claude(taint_path, dast_context, history)

            if action.action == "skip":
                logger.info(f"[dast][loop] tp={taint_path.id} iter={iteration} → skip")
                return self._make_finding(taint_path, "skipped", history, action.reasoning)

            if action.action == "confirm":
                logger.info(f"[dast][loop] tp={taint_path.id} iter={iteration} → Claude confirms")
                # Find first confirmed iteration for evidence
                confirmed_record = next(
                    (r for r in history if r.signals_triggered), None
                )
                return self._make_confirmed_finding(taint_path, history, confirmed_record, action.reasoning)

            if action.action == "give_up":
                logger.info(f"[dast][loop] tp={taint_path.id} iter={iteration} → give_up")
                return self._make_finding(taint_path, "give_up", history, action.reasoning)

            # action == "test": send the request
            if not action.request:
                logger.warning(f"[dast][loop] tp={taint_path.id} action=test but no request — skipping iteration")
                continue

            # ---- Execute request ----
            status_code, body, latency_ms = await self._execute(action.request)

            # Build coverage delta (v1: empty unless baseline has the sink line)
            coverage_delta = self._compute_coverage_delta(taint_path, dast_context)

            # Update baseline latency from first clean probes
            if iteration <= 2 and status_code < 500:
                baseline_latency_ms = (
                    latency_ms if baseline_latency_ms == 0
                    else (baseline_latency_ms + latency_ms) / 2
                )

            # Boolean-based: store first response as reference body
            if boolean_ref_body is None and status_code < 500:
                boolean_ref_body = body

            # ---- Check confirmation signals ----
            confirmed, method, evidence = check_all(
                response_body=body,
                latency_ms=latency_ms,
                coverage_delta=coverage_delta,
                baseline_latency_ms=baseline_latency_ms,
                boolean_ref_body=boolean_ref_body if iteration > 1 else None,
            )

            signals = [method] if confirmed else []
            record = IterationRecord(
                iteration=iteration,
                payload_sent=action.request.model_dump(),
                status_code=status_code,
                response_snippet=body[:_BODY_SNIPPET_LEN],
                latency_ms=latency_ms,
                coverage_delta=coverage_delta,
                signals_triggered=signals,
            )
            history.append(record)

            logger.info(
                f"[dast][loop] tp={taint_path.id} iter={iteration} "
                f"status={status_code} latency={latency_ms:.0f}ms "
                f"signals={signals}"
            )

            if confirmed:
                return self._make_confirmed_finding(taint_path, history, record, "", evidence, method)

        # Exhausted all iterations
        logger.info(f"[dast][loop] tp={taint_path.id} → exhausted after {self._max_iter} iterations")
        return self._make_finding(taint_path, "exhausted", history, "Max iterations reached without confirmation")

    # ------------------------------------------------------------------
    # Claude interaction
    # ------------------------------------------------------------------

    async def _ask_claude(
        self,
        taint_path: TaintPath,
        dast_context: DastScanContext,
        history: List[IterationRecord],
    ) -> ClaudeAction:
        """Call the configured LLM with current state, parse and return ClaudeAction.

        Retries once on JSON parse failure, then falls back to 'give_up'.
        History is trimmed to the last _MAX_HISTORY items to stay within
        the model's context window.
        """
        user_message = self._build_user_message(taint_path, dast_context, history)

        for attempt in range(2):
            try:
                raw_text = await self._call_llm(user_message)
                logger.debug(f"[dast][llm] raw response: {raw_text[:300]}")

                # Strip markdown code fences if present
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
                raw_text = re.sub(r"\s*```$", "", raw_text, flags=re.MULTILINE)

                data = json.loads(raw_text)

                # Validate required fields
                if "action" not in data or "taint_path_id" not in data:
                    raise ValueError("Missing required fields in Claude output")

                # Build RequestSpec if present
                req_data = data.get("request")
                request = RequestSpec(**req_data) if req_data else None

                return ClaudeAction(
                    action=data["action"],
                    taint_path_id=data["taint_path_id"],
                    request=request,
                    reasoning=data.get("reasoning", ""),
                )

            except (json.JSONDecodeError, ValueError, KeyError) as exc:
                logger.warning(
                    f"[dast][claude] Parse failed (attempt {attempt + 1}): {exc}"
                )
                if attempt == 0:
                    # Retry with explicit reminder
                    user_message += (
                        "\n\nIMPORTANT: Your previous response could not be parsed as JSON. "
                        "Respond with ONLY a valid JSON object, no other text."
                    )
                    continue

            except Exception as exc:
                logger.error(f"[dast][claude] API error: {exc}")
                break

        # Fallback: give up this path rather than crashing the scan
        return ClaudeAction(
            action="give_up",
            taint_path_id=taint_path.id,
            reasoning="Claude response could not be parsed after retry",
        )

    async def _call_llm(self, user_message: str) -> str:
        """Dispatch to the configured LLM provider, return raw text response."""
        if self._provider == "anthropic":
            response = await asyncio.to_thread(
                self._anthropic_client.messages.create,
                model=self._model,
                max_tokens=512,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            return response.content[0].text.strip()

        # Ollama — native AsyncClient
        response = await self._ollama_client.chat(
            model=self._model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        )
        return response.message.content.strip()

    def _build_user_message(
        self,
        taint_path: TaintPath,
        dast_context: DastScanContext,
        history: List[IterationRecord],
    ) -> str:
        """Serialise current probe state to a compact JSON string for Claude."""
        # Trim history to avoid context overflow
        trimmed_history = history[-_MAX_HISTORY:]

        payload: Dict[str, Any] = {
            "taint_path": taint_path.model_dump(),
            "stack": dast_context.stack.model_dump(),
            "target_base_url": self._base_url,
            "history": [r.model_dump() for r in trimmed_history],
            "instruction": (
                "Based on the taint path and probe history above, decide your next action. "
                "If any history item has non-empty signals_triggered, emit 'confirm'. "
                "Respond with ONLY a valid JSON object."
            ),
        }
        return json.dumps(payload, default=str)

    # ------------------------------------------------------------------
    # HTTP execution
    # ------------------------------------------------------------------

    async def _execute(
        self,
        req: RequestSpec,
    ) -> Tuple[int, str, float]:
        """Send the HTTP request, return (status_code, body_text, latency_ms)."""
        url = f"{self._base_url}{req.endpoint}"
        method = req.method.upper()

        t0 = time.monotonic()
        try:
            timeout = aiohttp.ClientTimeout(total=15.0)
            async with aiohttp.ClientSession(
                timeout=timeout,
                cookies=self._session_cookies,
            ) as session:
                kwargs: dict = {"headers": req.headers, "allow_redirects": False}
                if method == "GET":
                    kwargs["params"] = req.params
                else:
                    # Send as form-encoded data so Django request.POST works
                    body = req.body if req.body else (req.params or None)
                    if body:
                        kwargs["data"] = body
                    else:
                        kwargs["data"] = {}

                async with session.request(method, url, **kwargs) as response:
                    body = await response.text()
                    status_code = response.status
                    # Persist any new session cookies (e.g., refreshed sessionid)
                    for k, v in response.cookies.items():
                        self._session_cookies[k] = v.value

            latency_ms = (time.monotonic() - t0) * 1000
            return status_code, body[:2000], latency_ms

        except asyncio.TimeoutError:
            latency_ms = (time.monotonic() - t0) * 1000
            logger.warning(f"[dast][http] Timeout for {method} {url}")
            return 0, "TIMEOUT", latency_ms

        except Exception as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            logger.warning(f"[dast][http] Request error for {method} {url}: {exc}")
            return 0, f"ERROR: {exc}", latency_ms

    # ------------------------------------------------------------------
    # Coverage delta
    # ------------------------------------------------------------------

    def _compute_coverage_delta(
        self,
        taint_path: TaintPath,
        dast_context: DastScanContext,
    ) -> CoverageDelta:
        """v1: static check — is the sink file/line present in the baseline coverage?

        Full per-request coverage diffing requires the instrumented container to
        write coverage after each request.  That's left for v2.  For now we check
        whether the taint sink was already covered in the pre-scan baseline,
        giving Claude a useful signal about overall code reachability.
        """
        sink_file = taint_path.sink.file
        sink_line = taint_path.sink.line
        baseline = dast_context.coverage_baseline.covered_lines

        # Normalise path: try exact match then basename match
        covered = baseline.get(sink_file) or []
        if not covered:
            for fpath, lines in baseline.items():
                if fpath.endswith(sink_file) or sink_file.endswith(fpath.split("/")[-1]):
                    covered = lines
                    break

        if sink_line and sink_line in covered:
            return CoverageDelta(
                newly_covered_lines=[f"{sink_file}:{sink_line}"],
                taint_relevant=True,
            )

        return CoverageDelta()

    # ------------------------------------------------------------------
    # Finding constructors
    # ------------------------------------------------------------------

    def _make_confirmed_finding(
        self,
        taint_path: TaintPath,
        history: List[IterationRecord],
        record: Optional[IterationRecord],
        reasoning: str,
        evidence: Optional[Dict[str, Any]] = None,
        method: str = "",
    ) -> DastFinding:
        payload_str: Optional[str] = None
        confirmation_method = method

        if record:
            req = record.payload_sent
            # Build a readable payload string from params or body
            params = req.get("params") or req.get("body") or {}
            payload_str = json.dumps(params) if params else None
            if not confirmation_method and record.signals_triggered:
                confirmation_method = record.signals_triggered[0]
            evidence = evidence or {
                "response_snippet": record.response_snippet,
                "status_code": record.status_code,
                "latency_ms": record.latency_ms,
            }

        return DastFinding(
            id=f"dast-{uuid.uuid4().hex[:8]}",
            taint_path_id=taint_path.id,
            endpoint=taint_path.source.endpoint,
            parameter=taint_path.source.name,
            confirmed_payload=payload_str,
            confirmation_method=confirmation_method or "unknown",
            evidence=evidence or {},
            reasoning=reasoning or f"SQL injection confirmed via {confirmation_method}",
            cve_reference=taint_path.cve_id,
            status="confirmed",
            iterations_used=len(history),
        )

    def _make_finding(
        self,
        taint_path: TaintPath,
        status: str,
        history: List[IterationRecord],
        reasoning: str,
    ) -> DastFinding:
        return DastFinding(
            id=f"dast-{uuid.uuid4().hex[:8]}",
            taint_path_id=taint_path.id,
            endpoint=taint_path.source.endpoint,
            parameter=taint_path.source.name,
            evidence={"iterations": len(history)},
            reasoning=reasoning,
            cve_reference=taint_path.cve_id,
            status=status,
            iterations_used=len(history),
        )


# Lazy import to avoid circular dependency at module load time
import re  # noqa: E402 — used in _ask_claude for stripping code fences
