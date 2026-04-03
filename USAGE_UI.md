# VulnReach UI Usage

This guide is for running and using the web UI (`dashboard`) and API server.

---

## 1. Installation

### 1.1 Prerequisites
- Docker `24+`
- Docker Compose v2 (`docker compose`)
- `.env.local` based on `.env.example`

### 1.2 Configure environment
```bash
cp .env.example .env.local
```

Set at minimum:
- `POSTGRES_PASSWORD`
- `DATABASE_URL` (matching password)
- `JWT_SECRET`
- `SEED_ADMIN_USERNAME`
- `SEED_ADMIN_PASSWORD`

---

## 2. Dependencies

### Base UI/server stack
- `vulnreach` API service
- `db` (PostgreSQL)

### Optional dynamic runtime profile (high privilege path)
- `docker-socket-proxy`
- Explicit opt-in env in runtime profile:
  - `VULNREACH_ALLOW_DOCKER_DAEMON=true`
  - `DOCKER_HOST=tcp://docker-socket-proxy:2375`

---

## 3. Startup

### 3.1 Base startup (recommended default)
```bash
docker compose up --build
```

### 3.2 Startup with dynamic runtime profile
```bash
docker compose -f docker-compose.yml -f docker-compose.runtime.yml up --build
```

Use this only when you need dynamic runtime scanning.

---

## 4. Verify Services

### 4.1 Container health
```bash
docker compose ps
```

Expected:
- `db` healthy
- `vulnreach` running

### 4.2 API health
```bash
curl -s http://localhost:8000/health
```

Expected JSON:
```json
{"status":"ok","boot_id":"..."}
```

---

## 5. UI Usage

### 5.1 Open UI
- URL: `http://localhost:8000`

### 5.2 Login
- Use `SEED_ADMIN_USERNAME` / `SEED_ADMIN_PASSWORD` from `.env.local`

### 5.3 Start a scan from UI
- Go to "New Scan"
- Provide:
  - `repo_url` (recommended), or
  - `repo_path` + `config_path`
- Submit and monitor status in Scan History

### 5.4 Review results
- Open scan details
- Check:
  - summary bucket counts
  - correlation findings
  - reachability evidence

---

## 6. API Usage (from UI deployment)

### 6.1 Login via API
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

### 6.2 Start scan
```bash
curl -s -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/your-org/your-repo"}'
```

### 6.3 Poll scan
```bash
curl -s http://localhost:8000/scan/<scan_id> \
  -H "Authorization: Bearer $TOKEN"
```

---

## 7. Common Issues

- UI loads but login fails:
  - verify seeded credentials and `.env.local`.
- API returns `401`:
  - token missing/expired.
- Dynamic agent skipped:
  - expected unless runtime profile and opt-in are enabled.
- Browser CORS issues on separate frontend origin:
  - set `CORS_ORIGINS` to your UI origin.
