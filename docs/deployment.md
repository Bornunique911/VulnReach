# Deployment Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start — Docker Compose](#quick-start--docker-compose)
- [Environment Variables](#environment-variables)
- [First-Time Setup](#first-time-setup)
- [Native (No Docker)](#native-no-docker)
- [Production Considerations](#production-considerations)

---

## Prerequisites

| Dependency | Version | Notes |
|------------|---------|-------|
| Docker | 24+ | Required for dynamic reachability analysis |
| Docker Compose | v2 plugin | `docker compose` (not `docker-compose`) |
| PostgreSQL | 13+ | External or via the bundled compose service |
| Python | 3.11+ | For native runs only |

Optional tools (gracefully skipped if absent):

- `trivy` — [install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
- `semgrep` — `pip install semgrep`
- `tainter` — see [tainter.md](tainter.md)

---

## Quick Start — Docker Compose

```bash
git clone https://github.com/owasp/vulnreach.git
cd vulnreach

# 1. Copy and edit secrets
cp .env.example .env.local
#    Set: DATABASE_URL, JWT_SECRET, SEED_ADMIN_USERNAME, SEED_ADMIN_PASSWORD

# 2. Start everything (API + Postgres)
docker compose up --build

# 3. Verify
curl http://localhost:8000/health
# {"status":"ok","boot_id":"..."}
```

The API is available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

---

## Environment Variables

All variables are read from `.env.local` (takes precedence) and then `.env`. Changes to `.env.local` are picked up **without restart** — useful for secret rotation.

### Required

| Variable | Example | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://user:pass@localhost:5432/vulnreach` | PostgreSQL connection string |
| `JWT_SECRET` | `$(openssl rand -hex 32)` | HS256 signing key — minimum 256 bits |
| `SEED_ADMIN_USERNAME` | `admin` | Username for the bootstrap admin account |
| `SEED_ADMIN_PASSWORD` | `changeme` | Password for the bootstrap admin account |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_EXPIRE_MINUTES` | `60` | Token lifetime in minutes |
| `BCRYPT_ROUNDS` | `12` | bcrypt work factor (increase for higher security) |
| `CORS_ORIGINS` | `` (empty = `*`) | Comma-separated allowed origins, e.g. `https://app.example.com` |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Max request body size in bytes (default 1 MB) |
| `VULNREACH_WORK_DIR` | `/tmp/vulnreach` | Bind-mounted work dir for Docker-in-Docker scans |
| `VULNREACH_TARGET_HOST` | auto-detected | Override hostname for sibling container health checks |
| `ANTHROPIC_API_KEY` | — | Required only if `provider: anthropic` in config |
| `OPENAI_API_KEY` | — | Required only if `provider: openai` in config |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama endpoint for local LLM inference |
| `DB_MIN_CONN` | `1` | PostgreSQL connection pool minimum |
| `DB_MAX_CONN` | `5` | PostgreSQL connection pool maximum |

### Generating a JWT secret

```bash
openssl rand -hex 32
```

---

## First-Time Setup

### 1. Database

VulnReach auto-creates its schema on first startup. No manual migrations required.

```sql
-- Verify schema was created (connect to your database):
\dt
-- Should list: scans, vulnerabilities, reachability_evidence,
--              correlation_results, raw_outputs, semgrep_findings,
--              routes_extracted, users
```

### 2. Admin user

Set `SEED_ADMIN_USERNAME` and `SEED_ADMIN_PASSWORD` in `.env.local`. The admin account is created on startup if it does not already exist.

```bash
# Test login
curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq .
```

### 3. Run your first scan

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r .access_token)

curl -s -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/yourorg/yourapp"}' | jq .
```

---

## Native (No Docker)

Use this for development or when Docker is unavailable. Dynamic reachability analysis requires Docker regardless.

```bash
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
pip install schemathesis coverage

# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost:5432/vulnreach"
export JWT_SECRET="$(openssl rand -hex 32)"
export SEED_ADMIN_USERNAME="admin"
export SEED_ADMIN_PASSWORD="changeme"

uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Production Considerations

### Reverse proxy

Place VulnReach behind nginx or Caddy. Do not expose port 8000 directly.

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    client_max_body_size 2M;
}
```

### Docker socket security

VulnReach mounts `/var/run/docker.sock` to perform dynamic analysis. This grants significant host privileges. Recommendations:

- Run VulnReach in an isolated VM or namespace, not on a shared production host
- Use Docker socket proxy (e.g. [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)) to restrict API surface
- Restrict network access so only authorised clients reach port 8000

### CORS

Set `CORS_ORIGINS` to the exact origin(s) of your dashboard:

```bash
CORS_ORIGINS=https://vulnreach.yourorg.com
```

Leaving it empty defaults to `*` (permissive — acceptable for internal/air-gapped deployments).

### JWT rotation

To rotate the JWT secret and immediately invalidate all sessions:

```bash
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env.local
```

The server picks up the change on the next request. All existing tokens are rejected; users must log in again. See [SECURITY.md](../SECURITY.md) for details.
