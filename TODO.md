# VulnReach — OWASP Incubator Readiness TODO

> Tracks gaps that must be closed before submitting to the OWASP Software Incubator.
> Priority: **P0** = blocker, **P1** = required, **P2** = strongly recommended, **P3** = nice-to-have.

---

## 1. Open Source Hygiene (P0 — Blockers)

- [x] **Add a LICENSE file** — Apache 2.0 added at repo root.
- [x] **Add `CONTRIBUTING.md`** — Bug reports, dev setup, PR process, agent guide, commit style.
- [x] **Add `CODE_OF_CONDUCT.md`** — Contributor Covenant + OWASP Code of Conduct.
- [x] **Add `SECURITY.md`** — Responsible disclosure policy, scope, and design notes.
- [x] **Remove or redact internal scan artifacts** — `scans/` is gitignored and untracked; no action needed.
- [x] **Audit `TODO-PRIVATE.md`** — Already gitignored and untracked; notes merged into `TODO.md`.

---

## 2. Core Functionality Gaps (P1 — Required for Credibility)

### Dynamic Reachability

- [x] **Coverage ↔ finding correlation is incomplete** — `_correlate()` now falls back to `context.import_map` (populated by MetadataAgent via `importlib.metadata`) when a PyPI name is absent from the hardcoded `_PYPI_TO_IMPORT` dict. Niche packages are resolved at runtime.
- [x] **Line-number evidence not surfaced in API response** — `ReachabilityFinding` now has a `line: Optional[int]` field. `_correlate()` populates it from the best call-site or import-line hit detected via the AST/coverage pass.
- [x] **eBPF mode is experimental and untested** — `logger.warning(...)` emitted whenever `runtime.ebpf.enabled=true`, even when the tracer is available. Warning text calls it EXPERIMENTAL and directs users to the stable mode.
- [x] **Multi-stage Dockerfile patching breaks** — `_patch_dockerfile()` now detects the final `FROM` line index and only scans for `CMD` and `WORKDIR` within that stage. The `.coveragerc` path is derived from the detected WORKDIR instead of hardcoded `/app/`.
- [x] **Custom WORKDIR not handled** — `container_workdir: str = ""` added to `RuntimeSettings`. When set, it is prepended to `_CONTAINER_PREFIXES` in `_correlate()` for coverage path resolution. Auto-detection from Dockerfile WORKDIR also added as default behaviour.

### Taint Analysis

- [x] **Tainter wheel is not a public artifact** — Documented in `docs/development.md`: install from local wheel or GitHub source; all features degrade gracefully without it. `scan.sample.yml` marks tainter as `# OPTIONAL`.
- [x] **Misleading ERROR log when tainter exits rc=1 with findings** — `rc=1` is tainter's convention for "findings found". Demoted to `DEBUG`; `ERROR` is now reserved for rc≠0 with no stdout (genuine failure).
- [x] **Taint flow → CVE correlation is heuristic only** — `logger.debug(...)` warning added when a flow lacks an explicit `packages` field and the heuristic sink-file import scan is used. Warning explains the false-positive risk and flags the path to a stricter mode.

### Correlation Engine

- [x] **`dynamic_reachability_verdict` not called from main orchestrator** — Root cause was `call_chain_exists` not being propagated into `dynamic_reach_map`; `classify_reachability()` silently fell through. Fixed in orchestrator: `call_chain_exists` now set to `True` when `sink_reachable=True` (call-site execution IS a call chain). Service now calls `dynamic_reachability_verdict()` canonically instead of duplicating the logic inline.
- [x] **Static + dynamic evidence merge is incomplete** — Service now compounds confidence when both `dyn` and `sta` maps have evidence for the same CVE: `confidence = min(0.99, base_conf × 1.10)`. Removes the dead `dynamic_reachability_verdict` import from the orchestrator.

---

## 3. Testing (P1 — OWASP projects must demonstrate quality gates)

- [x] **Zero integration tests** — `tests/test_integration.py` added: 6 end-to-end tests covering happy path, dynamic reachability tier, policy block, partial-on-failure, no-vuln scan, and raw output storage. Uses `InMemoryRepository` + real `Orchestrator` + real `CorrelationService`.
- [x] **No API endpoint tests** — `tests/test_api_server.py` added: 22 tests covering health, tools, login, POST /scan (auth, missing repo, unknown tool, 413, success), GET /scan (ownership, admin bypass, 404-not-403), GET /scans (analyst vs admin), raw output endpoints.
- [x] **No database tests** — `tests/test_repository.py` added: 11 tests against real Postgres (auto-skipped in local dev without DB; run in CI via postgres service container). Covers scan lifecycle, vulns, raw output, correlation, and user CRUD.
- [x] **No coverage gate in CI** — `.github/workflows/ci.yml` added with 3 jobs: lint (ruff), test (`pytest --cov --cov-fail-under=60` with postgres service), docker-build smoke test.
- [x] **Agent tests are all unit tests with mocked subprocesses** — Integration tests exercise the full agent runner path via `InMemoryRepository`; binary smoke tests deferred to P2 (require real Docker/Trivy in CI).
- [x] **`agent_dynamic_reachability.py` has no tests at all** — `tests/test_dynamic_reachability.py` added: 27 unit tests covering `_patch_dockerfile` (single-stage, multi-stage, WORKDIR detection), `_parse_cmd_line`, `_parse_file_imports` (AST alias resolution), `_target_host`, and `_correlate` (all 3 strategies + edge cases).

---

## 4. Documentation (P1 — Required for Incubator Submission)

- [x] **Rewrite `README.md`** — Full rewrite: what/why, feature table, quickstart, docs index, requirements, license/OWASP badge.
- [x] **Write a deployment guide** — `docs/deployment.md`: Docker Compose, all env vars with types/defaults, first-time setup, native mode, production considerations.
- [x] **Write a configuration reference** — `docs/configuration.md`: every key in `config/schema.py` documented with type, default, and effect.
- [x] **Write an API reference** — `docs/api.md`: all endpoints, auth, request/response schemas, error codes, finding schema.
- [x] **Write a developer guide** — `docs/development.md`: project layout, pipeline walkthrough, adding an agent, correlation engine internals, DB schema.
- [x] **Document `tainter` dependency** — Covered in `docs/development.md#tainter`: what it is, install options, what works without it, what breaks.
- [x] **Add architecture diagram** — Already existed in `docs/architecture.md` (Mermaid pipeline, evidence chain, confidence ladder, Gantt).

---

## 5. API & Security Hardening (P1 — Self-Hosting Tool Must Be Secure)

- [x] **No rate limiting on `/login`** — `slowapi` decorator: 10 req/min per IP; returns 429 on excess.
- [x] **No CORS policy** — `CORSMiddleware` added; origins from `CORS_ORIGINS` env var (comma-separated); defaults to `*` with `allow_credentials=False`.
- [x] **Scan ID enumeration** — `_fetch_scan_owned()` helper enforces ownership on all scan read endpoints; non-owners (and unauthenticated users) always get 404, never 403. Admins bypass the check. `created_by` stored in scan metadata at creation time. `list_scans` filters to own scans for non-admins.
- [x] **No request body size limit** — `_MaxBodySizeMiddleware` rejects bodies over `MAX_REQUEST_BODY_BYTES` (default 1 MB) with HTTP 413.
- [x] **JWT secret has no rotation mechanism** — Already implemented in `auth.py` (`.env.local` mtime watch); documented rotation procedure with `openssl rand -hex 32` + `sed` one-liner in `SECURITY.md`.
- [x] **No audit log** — `vulnreach.audit` logger added; emits structured lines on `scan_created` (with user, repo, tools) and `scan_accessed`. Routable to a separate log handler via standard Python logging config.
- [x] **Dockerfile patch mutates user source code** — Compose mode now writes `Dockerfile.patched` to the `coverage_dir` tempdir instead of `repo_path`. Docker Compose accepts absolute paths for `build.dockerfile`.

---

## 6. Language & Ecosystem Support (P2 — Broadens OWASP Relevance)

- [ ] **Node.js / JavaScript support is stubbed, not functional** — `runner.py` has `node` branches but no working agent. Either implement or explicitly remove from docs/config.
- [ ] **Java support is stubbed** — Same as above.
- [ ] **No SBOM ingestion** — Accept CycloneDX / SPDX as input alongside Trivy output, so teams using existing SCA pipelines can plug in.
- [x] **PyPI mapping has ~50 entries; thousands exist** — `_correlate()` in `agent_dynamic_reachability.py` now accepts `import_map` (from MetadataAgent / `importlib.metadata`) and uses it as a runtime fallback when a PyPI name is absent from the hardcoded `_PYPI_TO_IMPORT` dict. Niche packages that were silently missed are now resolved.

---

## 7. Reliability & Scalability (P2)

- [ ] **Blocking Docker operations stall the event loop** — `asyncio.create_subprocess_exec` is non-blocking, but `docker image build` can take minutes. Long scans block the FastAPI worker. Offload to a task queue (e.g. Celery, ARQ) or at minimum document the single-scan constraint.
- [ ] **No scan cancellation** — Once a scan is started it runs to completion or timeout. Add `DELETE /scan/{id}` or `POST /scan/{id}/cancel`.
- [ ] **No cleanup of orphaned containers** — If the server crashes mid-scan, Docker containers from that scan are never removed. Add a startup cleanup routine.
- [ ] **`/tmp/vulnreach` not configurable at runtime** — `VULNREACH_WORK_DIR` must match the bind mount in `docker-compose.yml`. Document this constraint clearly and validate at startup.
- [ ] **Coverage flush retry is best-effort** — 3 retries × 5s = 15s max. Under heavy load or slow containers this can fail silently. Expose `runtime.coverage_flush_retries` as a config key.

---

## 8. CI / CD (P2)

- [ ] **No CI pipeline defined** — Add `.github/workflows/ci.yml` that runs: lint (`ruff`), type check (`mypy`), unit tests, and build Docker image.
- [ ] **No dependency pinning** — `requirements.txt` has unpinned versions. Pin with `pip-compile` and add dependabot or renovate for automated updates.
- [ ] **No Docker image published** — Publish `ghcr.io/vulnreach/vulnreach-agent` so users can run without cloning.
- [ ] **No version tagging scheme** — Define semantic versioning and tag releases.

---

## 9. OWASP Incubator Specific (P0/P1)

- [ ] **Submit OWASP Project Application** — Requires: project name, description, leader info, license, GitHub URL, and OWASP chapter sponsor.
- [x] **Ensure no vendor lock-in in defaults** — `OpenAPIGeneratorSettings.provider` and `IntelligentDastSettings.provider` now default to `"none"`. LLM features are disabled unless explicitly opted in. `scan.sample.yml` updated with `provider: none` comments.
- [x] **Separate `tainter` as an optional plugin** — Documented in `docs/development.md`: install options, graceful skip behavior, what works/breaks without it. `scan.sample.yml` now marks tainter as `# OPTIONAL`.
- [x] **Add `OWASP.md` or section in README** — `OWASP.md` created: mission alignment table, evidence chain description, optional component matrix, OWASP standards referenced.

---

## Summary Counts

| Priority | Total | Done | Remaining |
|----------|-------|------|-----------|
| P0 — Blocker | 7 | 6 | 1 |
| P1 — Required | 33 | 33 | 0 |
| P2 — Recommended | 13 | 1 | 12 |
| **Total** | **53** | **40** | **13** |


