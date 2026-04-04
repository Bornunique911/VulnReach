# VulnReach

**Runtime-aware SCA — proves which CVEs are actually reachable, not just installed.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

Traditional SCA tools report every CVE in every dependency. VulnReach filters that noise by proving — through static analysis, taint tracking, and live runtime coverage — which vulnerabilities can actually be reached and exploited in your application.

---

## Project Status

### Latest Development (shipped)

- Dependency-aware **parallel runner pipeline** for faster scans
- **Monorepo/multi-language reachability** (Python, Java, JavaScript, Go, C#, PHP)
- Stable scan response contract: `summary` + classified buckets on `GET /scan/{id}`
- Shared scan response normalization across API and package local mode (parity)
- Secure-by-default runtime boundary:
  - base compose runs without Docker socket mount
  - dynamic scans require explicit opt-in
  - runtime profile uses restricted `docker-socket-proxy`
- Deterministic fixture quality gates for Java/JavaScript/Go in CI
- Threat model + incubator application readiness checklist published

### In Progress

- Subprocess/command execution hardening audit across all agent paths
- Data retention/redaction policy for raw artifacts
- Maintainer response SLA + support policy
- Signed release artifacts/provenance
- Nightly end-to-end fixture scans and performance baselines

### Experimental

- `scan.runtime.ebpf` tracing mode (Linux-focused, explicit opt-in)
- AI-assisted OpenAPI generation and Intelligent DAST flows

See:
- [docs/incubator-readiness.md](docs/incubator-readiness.md)
- [docs/threat-model.md](docs/threat-model.md)

---

## How it works

Each CVE is classified through a five-layer evidence chain:

```
1. SCA (Trivy)              → is the package installed and vulnerable?
2. Taint analysis (tainter) → does user input flow to the vulnerable sink?
3. AST analysis             → is the vulnerable function in your call graph?
4. Route exposure           → is the call path reachable from an HTTP endpoint?
5. Runtime coverage         → was the vulnerable code actually executed?
```

The result is a prioritised finding list with four tiers:

| Tier | Meaning |
|------|---------|
| `DYNAMICALLY_REACHABLE` | Runtime coverage confirmed execution — fix immediately |
| `STATICALLY_REACHABLE` | Code path proven via AST/taint — high priority |
| `UNCERTAIN` | Weak signal only — investigate |
| `NOT_REACHABLE` | No evidence — suppress from alert queue |

---

## Quick Start

### With Docker Compose (recommended)

> **Security notice** — before starting, copy `.env.example` to `.env.local` and
> replace every `CHANGE_ME` value with a strong random secret.  
> Do **not** expose VulnReach on a public network without setting real credentials
> and configuring `CORS_ORIGINS`.

```bash
git clone https://github.com/ihrishikesh0896/vulnreach.git
cd vulnreach

# 1. Create your local config
cp .env.example .env.local

# 2. Fill in every CHANGE_ME — generate secrets with: openssl rand -hex 32
$EDITOR .env.local

# 3. Start the stack
docker compose up --build

# Optional: enable dynamic runtime scans (Docker daemon access via restricted socket proxy)
# docker compose -f docker-compose.yml -f docker-compose.runtime.yml up --build
```

### Run a scan

Auth options:
- Short-lived JWT: `POST /login`
- Long-lived API token (API key): create in UI `Settings -> API Keys`, then use it as `Authorization: Bearer <API_KEY>`

```bash
# Get a token (replace with the credentials you set in .env.local)
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"<your-admin-user>","password":"<your-admin-password>"}' | jq -r .access_token)

# Start scan from a GitHub repo
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/yourorg/yourapp"}'

# Poll for results
curl http://localhost:8000/scan/<scan_id> \
  -H "Authorization: Bearer $TOKEN" | jq .summary
```

---

## Add More Users

VulnReach currently seeds only the initial admin user from `.env.local`.
There is no `/users` create endpoint yet, so additional users are created via repository methods.

### Create an Analyst User (Docker Compose)

```bash
docker compose exec vulnreach python -c "import uuid; from storage import get_repository; from api.auth import hash_password; r=get_repository(); r.create_user(str(uuid.uuid4()), 'analyst1', hash_password('CHANGE_ME_STRONG_PASSWORD'), 'analyst'); print('created analyst1')"
```

### Create an Admin User (Docker Compose)

```bash
docker compose exec vulnreach python -c "import uuid; from storage import get_repository; from api.auth import hash_password; r=get_repository(); r.create_user(str(uuid.uuid4()), 'admin2', hash_password('CHANGE_ME_STRONG_PASSWORD'), 'admin'); print('created admin2')"
```

### Verify Login

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"CHANGE_ME_STRONG_PASSWORD"}'
```

---

## Features

- **Zero noise SCA** — only surfaces CVEs with a proven code path
- **Runtime confirmation** — Docker-based coverage collection via `coverage.py`
- **Taint tracking** — traces user input → vulnerable sinks (SQL, subprocess, YAML, pickle)
- **LLM-steered DAST** — Claude/OpenAI/Ollama generates and validates exploit payloads (optional)
- **CI/CD gates** — `policy.block_if` fails builds on confirmed critical findings
- **JWT auth** — multi-user, role-based access (admin / analyst)
- **API tokens (API keys)** — long-lived machine auth for curl/CI (`Authorization: Bearer <API_KEY>`)
- **PDF export** — `GET /scan/{id}/export/pdf`
- **No vendor lock-in** — LLM features default to `provider: none`; Ollama supported for offline use

---

## Documentation

### Usage

- [USAGE_PACKAGE.md](USAGE_PACKAGE.md) — package/CLI installation, dependencies, startup, usage
- [USAGE_UI.md](USAGE_UI.md) — UI/server installation, dependencies, startup, usage

### Operators / Deployers

- [docs/deployment.md](docs/deployment.md) — Docker Compose setup, env vars, production notes
- [docs/configuration.md](docs/configuration.md) — full `scan.yml` config reference
- [docs/api.md](docs/api.md) — REST endpoints and schemas

### Architecture / Security

- [docs/architecture.md](docs/architecture.md) — pipeline design and execution model
- [docs/threat-model.md](docs/threat-model.md) — trust boundaries, STRIDE, abuse cases
- [docs/incubator-readiness.md](docs/incubator-readiness.md) — OSS/incubator application readiness status
- [docs/DAST.md](docs/DAST.md) — DAST concepts and flow

### Contributors

- [docs/development.md](docs/development.md) — internals, agents, storage, extension points
- [OWASP.md](OWASP.md) — OWASP incubator application notes
- [SECURITY.md](SECURITY.md) — vulnerability disclosure and key rotation
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution process
- [CHANGELOG.md](CHANGELOG.md) — release history

---

## Requirements

- Python 3.11+
- PostgreSQL 13+
- Docker + Docker Compose v2 (for dynamic analysis)
- `trivy` on PATH ([install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))

Optional (all skip gracefully if absent):
- `semgrep` — `pip install semgrep`
- `tainter` — see [development guide](docs/development.md#tainter--optional-taint-analysis)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
