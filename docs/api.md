# API Reference

Base URL: `http://localhost:8000`
Interactive docs (Swagger UI): `http://localhost:8000/docs`
OpenAPI schema: `http://localhost:8000/openapi.json`

---

## Authentication

All protected endpoints require a JWT Bearer token obtained from `POST /login`.

```
Authorization: Bearer <token>
```

Tokens are signed HS256, expire after `JWT_EXPIRE_MINUTES` (default 60 minutes), and are immediately invalidated when `JWT_SECRET` changes in `.env.local`.

---

## Public Endpoints

### `GET /health`

Liveness check. No authentication required.

**Response `200`**
```json
{ "status": "ok", "boot_id": "abc123" }
```

---

### `GET /tools`

List all registered agent names. No authentication required.

**Response `200`**
```json
{
  "available_tools": [
    "git", "trivy", "tainter", "python_reachability",
    "dynamic_reachability", "intelligent_dast", "semgrep",
    "route_extractor", "metadata", "pytest_coverage", "openapi_generator"
  ]
}
```

---

## Auth Endpoints

### `POST /login`

Rate-limited: 10 requests/minute per IP.

**Request**
```json
{ "username": "admin", "password": "changeme" }
```

**Response `200`**
```json
{ "access_token": "<jwt>", "token_type": "bearer" }
```

**Errors**

| Status | Detail |
|--------|--------|
| `401` | `"Invalid credentials"` |
| `429` | Rate limit exceeded |

---

## Scan Endpoints

### `POST /scan`

Start an async scan. Returns immediately; poll `GET /scan/{scan_id}` for results.

**Request**
```json
{
  "repo_url": "https://github.com/org/app",
  "repo_path": "/local/path/to/app",
  "config_path": "/path/to/scan.yml",
  "tools": ["trivy", "tainter"]
}
```

`repo_url` or `repo_path` is required. `config_path` is required for local scans; optional for `repo_url` scans (auto-discovered or defaulted).

**Response `200`**
```json
{
  "scan_id": "a1b2c3d4-...",
  "status": "started",
  "tools": ["git", "trivy", "tainter"],
  "repo_url": "https://github.com/org/app",
  "repo_path": null
}
```

**Errors**

| Status | Detail |
|--------|--------|
| `400` | Missing `repo_path`/`repo_url`, invalid `config_path`, unknown tool name |
| `401` | Missing or invalid token |
| `413` | Request body exceeds 1 MB |

---

### `GET /scan/{scan_id}`

Get scan status and full results.

**Response `200`**
```json
{
  "scan_id": "a1b2c3d4-...",
  "status": "completed",
  "metadata": { "repo_url": "...", "tools": [...], "created_by": {...} },
  "created_at": "2026-03-26T10:00:00Z",
  "vulnerabilities": [...],
  "correlation": [...],
  "dynamically_reachable": [...],
  "statically_reachable": [...],
  "not_reachable": [...],
  "uncertain": [...],
  "summary": {
    "total": 12,
    "dynamically_reachable": 2,
    "statically_reachable": 5,
    "not_reachable": 4,
    "uncertain": 1
  },
  "pipeline_status": "PASS"
}
```

**Scan status values**

| Status | Meaning |
|--------|---------|
| `started` | Scan queued / running |
| `completed` | All agents finished successfully |
| `partial` | Some agents failed; results may be incomplete |
| `blocked` | A `policy.block_if` rule matched — CI gate should fail |

**Errors**

| Status | Detail |
|--------|--------|
| `404` | Scan not found or not owned by the requesting user |

---

### `GET /scans`

List all scans owned by the authenticated user. Admins see all scans.

**Response `200`**
```json
{
  "scans": [
    { "id": "...", "status": "completed", "metadata": {...}, "created_at": "..." }
  ]
}
```

---

### `GET /scan/{scan_id}/raw`

List agent names that have raw output stored for this scan.

**Response `200`**
```json
{ "scan_id": "...", "tools": ["trivy", "tainter", "dynamic_reachability"] }
```

---

### `GET /scan/{scan_id}/raw/{tool_name}`

Get the raw JSON output from a specific agent.

**Response `200`**
```json
{
  "scan_id": "...",
  "tool_name": "trivy",
  "output": { ... }
}
```

**Errors**

| Status | Detail |
|--------|--------|
| `404` | Scan not found, or no raw output for the given tool |

---

### `GET /scan/{scan_id}/export/pdf`

Download a PDF report for the scan.

**Response `200`**
Content-Type: `application/pdf`
Content-Disposition: `attachment; filename="vulnreach-<scan_id[:8]>.pdf"`

---

## Finding Schema

Each entry in `correlation` has this shape:

```json
{
  "cve_id": "CVE-2024-1234",
  "package": "requests",
  "severity": "HIGH",
  "verdict": "CONFIRMED",
  "risk_score": 3.9,
  "priority": "P2",
  "confidence": 0.95,
  "reachability_class": "DYNAMICALLY_REACHABLE",
  "finding_type": "dynamic",
  "evidence": {
    "coverage_hit": true,
    "has_taint_flow": true,
    "call_chain_exists": true,
    "import_detected": true,
    "function": "requests.get",
    "file": "api/views.py",
    "files": ["api/views.py"],
    "line": 42,
    "evidence_type": "dynamic"
  }
}
```

**`reachability_class` values**

| Class | Meaning |
|-------|---------|
| `DYNAMICALLY_REACHABLE` | Runtime coverage confirmed execution |
| `STATICALLY_REACHABLE` | AST / taint analysis proves code path exists |
| `UNCERTAIN` | Weak taint signal only; no runtime confirmation |
| `NOT_REACHABLE` | No evidence the vulnerable code is ever called |

**`priority` values**

| Priority | Risk Score |
|----------|-----------|
| `P1` | ≥ 5.0 |
| `P2` | ≥ 4.0 |
| `P3` | ≥ 3.0 |
| `P4` | < 3.0 |
