# VulnReach

**Runtime-aware SCA — proves which CVEs are actually reachable, not just installed.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue)](OWASP.md)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

Traditional SCA tools report every CVE in every dependency. VulnReach filters that noise by proving — through static analysis, taint tracking, and live runtime coverage — which vulnerabilities can actually be reached and exploited in your application.

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

```bash
git clone https://github.com/owasp/vulnreach.git
cd vulnreach

# Configure secrets
cp .env.example .env.local
# Edit .env.local: DATABASE_URL, JWT_SECRET, SEED_ADMIN_USERNAME, SEED_ADMIN_PASSWORD

docker compose up --build
```

### Run a scan

```bash
# Get a token
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r .access_token)

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

## Features

- **Zero noise SCA** — only surfaces CVEs with a proven code path
- **Runtime confirmation** — Docker-based coverage collection via `coverage.py`
- **Taint tracking** — traces user input → vulnerable sinks (SQL, subprocess, YAML, pickle)
- **LLM-steered DAST** — Claude/OpenAI/Ollama generates and validates exploit payloads (optional)
- **CI/CD gates** — `policy.block_if` fails builds on confirmed critical findings
- **JWT auth** — multi-user, role-based access (admin / analyst)
- **PDF export** — `GET /scan/{id}/export/pdf`
- **No vendor lock-in** — LLM features default to `provider: none`; Ollama supported for offline use

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/deployment.md](docs/deployment.md) | Docker Compose setup, env vars, production config |
| [docs/configuration.md](docs/configuration.md) | Full config reference for `scan.yml` |
| [docs/api.md](docs/api.md) | API endpoints, request/response schemas |
| [docs/architecture.md](docs/architecture.md) | Pipeline diagrams, evidence chain, confidence ladder |
| [docs/development.md](docs/development.md) | Adding agents, correlation engine, database schema |
| [docs/tainter.md](docs/development.md#tainter--optional-taint-analysis) | Optional taint analysis component |
| [OWASP.md](OWASP.md) | OWASP mission alignment |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure, JWT rotation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](CHANGELOG.md) | Recent changes |

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

VulnReach is an [OWASP Incubator Project](OWASP.md).
