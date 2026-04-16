# CI / CD Reference

This document describes every workflow in `.github/workflows/`, when it runs, what it checks, and how to reproduce it locally. Read this before raising a PR.

---

## Workflow Overview

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| CI | `ci.yml` | Every PR, push to main | Lint, unit tests, language fixtures, Docker smoke |
| Build and Test | `build-test.yml` | Every PR, push to main/develop | Package build, flake8 syntax check |
| eBPF E2E | `ebpf-e2e.yml` | PR/push touching eBPF paths, manual | Full eBPF pipeline on real Linux kernel |
| Docker Publish | `docker-publish.yml` | PR (build only), tag `v*.*.*`, release | Build image; push to ghcr.io + docker.io on release |
| PyPI Publish | `python-publish.yml` | PR (build only), release | Build package; publish to PyPI on release |

---

## 1. CI (`ci.yml`)

**Runs on:** every PR (any branch), push to `main` / `master`

**Jobs run in parallel:**

### 1a. Lint
```
Tool: ruff
Command: ruff check .
```
Checks all Python files for style and correctness violations. Zero tolerance — any ruff error fails the build.

**Run locally:**
```bash
pip install ruff
ruff check .

# Auto-fix what ruff can:
ruff check . --fix
```

### 1b. Unit tests (coverage ≥ 60%)

Spins up a real PostgreSQL 15 service container. Tests run against it via `DATABASE_URL`.

```
Tool: pytest + pytest-cov
Coverage gate: --cov-fail-under=60
Excluded: labs/, tests/, __pycache__
```

**Environment required:**
| Variable | CI value |
|----------|----------|
| `DATABASE_URL` | `postgresql://vulnreach:vulnreach@localhost:5432/vulnreach_test` |
| `JWT_SECRET` | auto-generated per run |
| `BCRYPT_ROUNDS` | `4` (fast hashing in CI) |

**Run locally:**
```bash
# Start postgres
docker run -d \
  -e POSTGRES_USER=vulnreach \
  -e POSTGRES_PASSWORD=vulnreach \
  -e POSTGRES_DB=vulnreach_test \
  -p 5432:5432 \
  postgres:15

export DATABASE_URL=postgresql://vulnreach:vulnreach@localhost:5432/vulnreach_test
export JWT_SECRET=local-dev-secret
export BCRYPT_ROUNDS=4

pip install -r requirements.txt pytest pytest-cov coverage tainter
pytest tests/ --cov=. --cov-omit="labs/*,tests/*" --cov-fail-under=60 -v
```

### 1c. Language fixtures (Java, JavaScript, Go)

Runs `test_language_fixtures.py` and `test_scan_response_contract.py` three times in parallel — once per language — via a matrix with `VULNREACH_FIXTURE_LANGUAGE` set. Validates that multi-language analyzer output shape is deterministic.

**Run locally:**
```bash
VULNREACH_FIXTURE_LANGUAGE=java pytest -q tests/test_language_fixtures.py tests/test_scan_response_contract.py
VULNREACH_FIXTURE_LANGUAGE=javascript pytest -q tests/test_language_fixtures.py tests/test_scan_response_contract.py
VULNREACH_FIXTURE_LANGUAGE=go pytest -q tests/test_language_fixtures.py tests/test_scan_response_contract.py
```

### 1d. Docker image build (smoke)

Builds the production Dockerfile to catch broken dependencies or mis-ordered `COPY` steps. Does not push anything.

**Run locally:**
```bash
docker build --tag vulnreach-agent:local --file Dockerfile .
```

---

## 2. Build and Test (`build-test.yml`)

**Runs on:** every PR (any branch), push to `main` / `master` / `develop`

Checks Python package builds correctly and catches syntax errors with flake8.

```
flake8 . --select=E9,F63,F7,F82   ← hard errors (syntax, undefined names)
flake8 . --exit-zero               ← style warnings (non-blocking)
python -m build                    ← wheel + sdist must succeed
```

Build artifacts (`dist/`) are uploaded and kept for 7 days — useful for inspecting what would be published to PyPI.

**Run locally:**
```bash
pip install build flake8
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
python -m build
```

---

## 3. eBPF E2E (`ebpf-e2e.yml`)

**Runs on:** PR or push to `main` that touches any of:
```
agents/ebpf/**
agents/agent_dynamic_reachability.py
labs/ebpf-e2e/**
tests/test_ebpf_e2e.py
.github/workflows/ebpf-e2e.yml
```
Also available via `workflow_dispatch` (manual trigger from GitHub Actions UI).

**Requirements:** Linux kernel ≥4.9, `bpftrace`, `docker`, `VULNREACH_ALLOW_DOCKER_DAEMON=true`.
Skips automatically on macOS / Docker Desktop / kernels without tracepoint support.

**What it does:**
1. Installs `bpftrace` on the runner
2. Verifies kernel + bpftrace with a dry-run probe (`tracepoint:syscalls:sys_enter_openat`)
3. Builds `labs/ebpf-e2e/target` (ubuntu:22.04 + USDT Python)
4. Starts the target and waits for `/health` to respond
5. Runs `tests/test_ebpf_e2e.py` under `sudo -E` (required for `CAP_BPF`)
6. Collects container logs on failure

**Run locally (Linux only):**
```bash
# Install bpftrace
sudo apt-get install -y bpftrace

# Start the target
cd labs/ebpf-e2e && docker compose up -d --build && cd ../..

# Run tests
export VULNREACH_ALLOW_DOCKER_DAEMON=true
export VULNREACH_ALLOW_EBPF=1
sudo -E pytest tests/test_ebpf_e2e.py -v

# Tear down
cd labs/ebpf-e2e && docker compose down
```

**Test classes:**

| Class | Guard | What it tests |
|-------|-------|---------------|
| `TestEbpfSidecarE2E` | Linux + bpftrace + Docker + VULNREACH_ALLOW_DOCKER_DAEMON | Full pipeline: eBPF sidecar → correlator → DYNAMICALLY_REACHABLE verdict |
| `TestEbpfProbeSelection` | Linux only (no bpftrace needed) | probe_router.py logic — USDT selection, openat fallback |

---

## 4. Docker Publish (`docker-publish.yml`)

**Runs on:**
- **PR** — builds image, does **not** push (login steps are skipped)
- **Tag `v*.*.*`** — builds and pushes to `ghcr.io` and `docker.io`
- **GitHub Release published** — same as tag

**Registries:**
| Registry | Image | Secret required |
|----------|-------|----------------|
| `ghcr.io` | `ghcr.io/<owner>/vulnreach` | `GITHUB_TOKEN` (automatic) |
| `docker.io` | `<DOCKERHUB_USERNAME>/vulnreach` | `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` |

**Tags generated automatically:**
- `2.0.1` (full version)
- `2.0` (major.minor)
- `latest` (on default branch only)

**To publish a new Docker image:**
```bash
git tag v2.0.2
git push origin v2.0.2
# workflow triggers automatically
```

**Run locally:**
```bash
docker build -t vulnreach:local .
# To push manually (not recommended — use the workflow):
docker tag vulnreach:local ghcr.io/<owner>/vulnreach:latest
docker push ghcr.io/<owner>/vulnreach:latest
```

---

## 5. PyPI Publish (`python-publish.yml`)

**Runs on:**
- **PR** — builds `dist/` (wheel + sdist), does **not** publish
- **GitHub Release published** — builds and publishes to PyPI

Uses [PyPA Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API token stored in secrets. The `pypi` GitHub Actions environment must be configured in repository settings.

**Jobs:**
1. `build` — always runs; uploads `dist/` as an artifact (except on PRs)
2. `publish-to-pypi` — runs only on `release` events; downloads the artifact and publishes

**To publish a new PyPI release:**
1. Bump `version` in `pyproject.toml`
2. Commit and tag: `git tag v2.0.2 && git push origin v2.0.2`
3. Create a GitHub Release from the tag
4. The workflow publishes automatically

**Run locally:**
```bash
pip install build
python -m build
# Inspect dist/ before publishing:
ls dist/
# Test upload (TestPyPI):
pip install twine
twine upload --repository testpypi dist/*
```

---

## PR Checklist

Before opening a PR:

```bash
# 1. Lint
ruff check .

# 2. Tests
pytest tests/ --cov=. --cov-fail-under=60 -v

# 3. Package build
python -m build

# 4. Docker build
docker build -t vulnreach:local .

# 5. If you touched agents/ebpf/ or agent_dynamic_reachability.py — run eBPF tests on Linux
VULNREACH_ALLOW_DOCKER_DAEMON=true VULNREACH_ALLOW_EBPF=1 sudo -E pytest tests/test_ebpf_e2e.py -v
```

All five commands must pass locally before pushing. The CI will run all of them on every PR — a clean local run avoids back-and-forth fix commits.

---

## Secrets Reference

| Secret | Used by | How to set |
|--------|---------|------------|
| `DOCKERHUB_USERNAME` | `docker-publish.yml` | Repository Settings → Secrets → Actions |
| `DOCKERHUB_TOKEN` | `docker-publish.yml` | hub.docker.com → Account Settings → Security → Access Tokens |
| `GITHUB_TOKEN` | `docker-publish.yml` | Automatic — no setup needed |
| PyPI trusted publisher | `python-publish.yml` | PyPI project → Publishing → Add a trusted publisher (GitHub Actions) |

---

## Environment Variables (CI runtime)

| Variable | Set in | Purpose |
|----------|--------|---------|
| `DATABASE_URL` | `ci.yml` | PostgreSQL connection for integration tests |
| `JWT_SECRET` | `ci.yml` | Auth token signing — auto-generated per run |
| `BCRYPT_ROUNDS` | `ci.yml` | Set to `4` for fast password hashing in tests |
| `VULNREACH_FIXTURE_LANGUAGE` | `ci.yml` | Selects language for fixture matrix |
| `VULNREACH_ALLOW_DOCKER_DAEMON` | `ebpf-e2e.yml` | Required to enable Docker-based dynamic scans |
| `VULNREACH_ALLOW_EBPF` | `ebpf-e2e.yml` | Required to enable eBPF tracing mode |
