# Changelog

## [Unreleased] — 2026-03-27

### Added

#### Testing & CI
- **Integration test suite** — `tests/test_integration.py` (6 tests) exercises the full pipeline end-to-end: `Orchestrator` + `CorrelationService` + `InMemoryRepository`. Covers static-only findings, dynamic reachability tier promotion, policy block (`CRITICAL+CONFIRMED → blocked`), partial scan on agent failure, clean repo (no vulns), and raw output storage.
- **API endpoint tests** — `tests/test_api_server.py` (22 tests) covers every public endpoint: `/health`, `/tools`, `/login` (success, wrong password, unknown user), `POST /scan` (auth required, missing repo, unknown tool, 413 body size limit, success with auto-injected `git`), `GET /scan/{id}` (ownership enforcement returning 404-not-403 to prevent ID enumeration, admin bypass), `GET /scans` (analyst sees own only, admin sees all), `GET /scan/{id}/raw` (list tools, missing tool 404, success). psycopg2 stubbed via `sys.modules` before import so no real database required.
- **PostgresRepository tests** — `tests/test_repository.py` (11 tests) validates the full storage contract against a real Postgres instance. Auto-skipped locally when `DATABASE_URL` is not set or psycopg2 is mocked; runs in CI against a postgres service container. Covers scan lifecycle, vulnerability storage, raw output CRUD, correlation storage, and user management.
- **`agent_dynamic_reachability` unit tests** — `tests/test_dynamic_reachability.py` (27 tests) covers all pure-Python logic: `_patch_dockerfile` (single-stage, multi-stage, WORKDIR detection, already-patched guard), `_parse_cmd_line` (JSON-array and shell forms), `_parse_file_imports` (AST alias resolution, dotted imports, syntax errors), `_target_host` (native vs Docker), and `_correlate` (strategy 1 direct library hit, 2a call-site and import-line, 3 taint stack, no-evidence skip, multiple CVEs per package, import-map fallback, custom container WORKDIR, short package name guard).
- **CI pipeline** — `.github/workflows/ci.yml` with three jobs: `lint` (ruff), `test` (pytest with postgres service, `--cov-fail-under=60` coverage gate, coverage artifact upload), `docker-build` (smoke-test image build on every push/PR to main).
- **`InMemoryRepository`** — Added to `tests/conftest.py`: a full in-memory implementation of the `StorageRepository` interface used across integration tests without a real database.

### Bug Fixes

#### Tests
- **`test_correlation.py` stale assertion** — `reachability_verdict(True, True, True)` was asserted to return `"LIKELY"` but the engine correctly returns `"CONFIRMED"` (import + call_chain + sink_reachable = full static trace to sink). Updated assertion and clarified comments.
- **`test_repository.py` psycopg2 mock contamination** — When `test_api_server.py` ran before `test_repository.py`, it replaced `psycopg2` in `sys.modules` with a `MagicMock`. The skip guard checked the URL string but not the module type, so `pytest.importorskip` passed and DB calls returned mocks. Fixed by checking `isinstance(sys.modules.get("psycopg2"), MagicMock)` at both the module-level skip mark and inside the `repo` fixture.

---

## [Unreleased] — 2026-03-26

### Bug Fixes

#### Docker / Infrastructure
- **Git clone not on bind mount** — `GitAgent` was cloning repos into the system temp dir (`/tmp/vulnreach-<repo>-<random>`) instead of `_WORK_BASE` (`/tmp/vulnreach/`). The host Docker daemon couldn't resolve the build context path for sibling containers. Fixed by passing `dir=_WORK_BASE` to `tempfile.mkdtemp`.
- **`docker compose` plugin missing** — Dockerfile only installed `docker-ce-cli`; `docker compose` subcommand was unavailable inside the container. Fixed by adding `docker-compose-plugin` to the apt install step.
- **`localhost` unreachable from inside Docker** — Health checks and Schemathesis were targeting `http://localhost:<port>` which resolves to the vulnreach container's own loopback, not the host. Added `_target_host()` helper that returns `host.docker.internal` when running inside Docker (detected via `/.dockerenv`), falling back to `localhost` for native runs. Applied to all three scan modes (Dockerfile, compose, eBPF).
- **`host.docker.internal` not resolvable on Linux** — Added `extra_hosts: host.docker.internal:host-gateway` to `docker-compose.yml` so the hostname resolves on Linux Docker hosts (it works automatically on Docker Desktop for macOS/Windows).
- **Tainter hardcoded macOS binary path** — `_run_scan` ignored its `tainter_bin` argument and had `/Library/Frameworks/Python.framework/Versions/3.11/bin/tainter` hardcoded, causing `[Errno 2] No such file or directory` inside the container. Fixed by calling `"tainter"` directly and catching `FileNotFoundError` for a clean skip.
- **`shutil.which` resolving host PATH into container** — Removed `shutil.which("tainter")` pre-flight check; availability is now determined at execution time via `FileNotFoundError`.
- **Tainter installed from local wheel** — Added `COPY libs/tainter-0.1.0-py3-none-any.whl` + `pip install` step to Dockerfile so `tainter` is available on PATH inside the container.

#### Dynamic Reachability — Coverage
- **Coverage restricted to app code only** — `.coveragerc` was generated with `source = .`, excluding site-packages entirely. Strategy 1 (direct library path match) never fired. Fixed by removing the `source` restriction and adding `omit` patterns for packaging noise (`pip`, `setuptools`, `pkg_resources`, `coverage`, `distutils`, `ensurepip`, internal `_*` modules). Coverage now traces site-packages so library execution is directly observable.
- **Strategy 1 only matched filenames, not full paths** — `import_name in hit_files` checked basename only (e.g. `adapters.py`), missing site-packages paths like `/usr/local/lib/python3.11/site-packages/requests/adapters.py`. Added full-path check: `f"/site-packages/{import_name}"` against `hit_files_full`.
- **Container paths not resolving to host files** — Coverage JSON produced inside Docker containers uses paths like `/app/api/views.py`. On the host, `Path("/app/api/views.py")` doesn't exist, and `repo_path / "/app/..."` discards the prefix (Python absolute path join). Fixed by stripping known container WORKDIR prefixes (`/app/`, `/code/`, `/srv/`, `/usr/src/app/`, `/home/app/`) before joining with `repo_path`.
- **Coverage flush unreliable** — `_extract_coverage_via_compose` ran once with a 30s timeout and no success validation. Fixed with retry logic (3 attempts, 5s apart), also copies `.coverage*` from `/app/` in addition to `/tmp/`, and validates `coverage.json` exists with >50 bytes before declaring success. Returns a bool indicating success.

#### Dynamic Reachability — Correlation
- **Aliased imports invisible to call-site matching** — Regex scanning for call sites matched raw token names (e.g. `sa`, `np`) instead of the real package names (`sqlalchemy`, `numpy`). `from flask import render_template` → `render_template(` was not linked back to `flask`. Replaced regex import scanning with AST-based `_parse_file_imports()` that builds two maps per file:
  - `alias_to_pkg`: `import sqlalchemy as sa` → `{sa: sqlalchemy}`
  - `imported_names`: `from flask import render_template` → `{render_template: flask}`
  Call-site matching now resolves through both maps before recording a hit.
- **Flat 0.40 confidence for all import-level evidence** — Strategy 2a assigned the same confidence regardless of how strong the evidence was. Replaced with three sub-levels:
  - Call-site line executed → **0.80** confidence, `sink_reachable=True`
  - Import line itself executed → **0.65** confidence, `sink_reachable=False`
  - File-level fallback (file ran, imports pkg, line unconfirmed) → **0.40** confidence
- **PyPI → import name mapping too small** — `_PYPI_TO_IMPORT` had only 7 entries, causing silent misses for common packages with mismatched names. Expanded to ~50 entries covering: crypto (`pyjwt→jwt`, `pyopenssl→OpenSSL`, `pycryptodome→Crypto`, `argon2-cffi→argon2`), DB drivers (`psycopg2-binary→psycopg2`, `cx-oracle→cx_Oracle`, `pymysql→pymysql`), web extensions (`djangorestframework→rest_framework`, `flask-login→flask_login`, `flask-cors→flask_cors`), media (`opencv-python→cv2`), messaging (`kafka-python→kafka`, `grpcio→grpc`), and others.

#### API
- **`/scan` returning 400 with no log context** — Added `logger.info` and `logger.warning` to the scan endpoint so config load failures and request parameters are visible in container logs, making it easier to diagnose path mismatches.

### Notes
- When running vulnreach via docker-compose, `repo_path` fields must use container-internal paths (e.g. `/app/scans/myrepo`) or use `repo_url` for git clone. Host filesystem paths are not accessible inside the container unless explicitly mounted.
- The `VULNREACH_TARGET_HOST` environment variable can be set to override the auto-detected target host used for health checks and Schemathesis.
