# VulnReach — Usage & QA Test Guide

This file is structured for both human reference and automated agent QA testing.
Each section includes commands, expected outputs, and explicit PASS/FAIL criteria.

---

## Prerequisites

### Standalone mode
- Python 3.11+
- `trivy` installed (`brew install trivy` / `apt install trivy`)
- `git` installed
- VulnReach installed: `pip install vulnreach`

### Docker mode
- Docker + Docker Compose
- `.env.local` configured (copy from `.env.example`)

### Test target (used in all examples below)
```
labs/python_vuln_app/
```
This app has intentionally vulnerable packages (Flask 2.0.1, requests 2.25.1, PyJWT 1.7.1, etc.)
and is the canonical test target for all QA runs.

---

## 1. Installation

### 1.1 Install CLI
```bash
pip install vulnreach
```

**PASS:** `vulnreach --version` prints a version string
**FAIL:** `ModuleNotFoundError` or command not found

### 1.2 Verify commands are registered
```bash
vulnreach --help
```

**PASS:** Output contains all four commands: `scan`, `fix-plan`, `replay`, `explain`
**FAIL:** Any command is missing from the output

---

## 2. Standalone Mode (SQLite, no server)

### 2.1 Basic scan
```bash
vulnreach scan --repo-path ./labs/python_vuln_app
```

**PASS:**
- Exits with code 0 (or 1 only if `--fail-on` is set)
- Prints a summary table with `Scan ID`, `Status`, and at least one verdict row
- Final line of stdout is the scan ID (UUID format)
- `~/.vulnreach/vulnreach.db` is created

**FAIL:**
- Traceback or unhandled exception
- Status is `failed` with no findings
- No scan ID printed

### 2.2 Capture scan ID for subsequent tests
```bash
SCAN_ID=$(vulnreach scan --repo-path ./labs/python_vuln_app 2>/dev/null | tail -1)
echo "SCAN_ID=$SCAN_ID"
```

**PASS:** `SCAN_ID` is a non-empty UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### 2.3 Fix plan — table format
```bash
vulnreach fix-plan --scan-id "$SCAN_ID"
```

**PASS:**
- Prints a Rich table with columns: Package, Current, Upgrade to, Reachable CVEs removed, Risk score
- At least one row present (given the vulnerable packages in the test app)

**FAIL:**
- `Scan not found` error
- Empty table with no explanation

### 2.4 Fix plan — markdown format
```bash
vulnreach fix-plan --scan-id "$SCAN_ID" --format markdown
```

**PASS:**
- Output starts with `## VulnReach Fix Plan`
- Contains at least one line matching `- [ ] Upgrade \`<package>\``

**FAIL:**
- No markdown output
- Plain text with no checklist items

### 2.5 Fix plan — JSON format
```bash
vulnreach fix-plan --scan-id "$SCAN_ID" --format json
```

**PASS:**
- Output is valid JSON array (`[ ... ]`)
- Each item has keys: `package`, `current_version`, `upgrade_to`, `reachable_cves_removed`, `risk_score`

**FAIL:**
- Invalid JSON
- Empty array `[]` when test app has known reachable CVEs

### 2.6 Explain — offline (no API key)
```bash
vulnreach explain CVE-2021-33503 --scan-id "$SCAN_ID"
```
*(Replace CVE with one found in the scan output if CVE-2021-33503 is not present)*

**PASS:**
- Prints a Rich panel with the CVE ID as title
- Panel contains: package name, reachability class, recommended action
- Does NOT require `ANTHROPIC_API_KEY`

**FAIL:**
- `No finding found` when CVE is in the scan
- Traceback on missing API key

### 2.7 Replay — ASCII tree
```bash
vulnreach replay CVE-2021-33503 --scan-id "$SCAN_ID"
```

**PASS (call graph exists):**
- Prints indented tree of nodes connected by `└─` edges

**PASS (no call graph):**
- Prints a clear message: `No call graph found for ... The vulnerability may not have been statically analysed`

**FAIL:**
- Unhandled exception
- Silent empty output

### 2.8 Replay — raw Mermaid
```bash
vulnreach replay CVE-2021-33503 --scan-id "$SCAN_ID" --format mermaid
```

**PASS (call graph exists):** Output starts with `graph` or `flowchart`
**PASS (no call graph):** Same clear message as 2.7

### 2.9 --fail-on exit code
```bash
vulnreach scan --repo-path ./labs/python_vuln_app --fail-on CONFIRMED
echo "Exit: $?"
```

**PASS:** Exit code is `1` if any CONFIRMED findings exist, `0` otherwise
**FAIL:** Always exits `0` regardless of findings

### 2.10 SQLite DB path override
```bash
SQLITE_PATH=/tmp/vr_test.db vulnreach scan --repo-path ./labs/python_vuln_app
ls /tmp/vr_test.db
```

**PASS:** `/tmp/vr_test.db` is created
**FAIL:** File not created / written to default path instead

---

## 3. Docker Mode (server + CLI client)

### 3.1 Start the server
```bash
cp .env.example .env.local
# Set SECRET_KEY and SEED_ADMIN_USERNAME / SEED_ADMIN_PASSWORD in .env.local
docker compose up -d --build
```

**PASS:** `docker compose ps` shows both `vulnreach` and `db` as `running` / `healthy`
**FAIL:** Container exits immediately or db healthcheck never passes

### 3.2 Health check
```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

**PASS:** `{"status": "ok", "boot_id": "<hex>"}` — HTTP 200
**FAIL:** Connection refused or non-200 response

### 3.3 Authentication
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "TOKEN=$TOKEN"
```

**PASS:** `TOKEN` is a non-empty JWT string (three dot-separated base64 segments)
**FAIL:** `{"detail": "Invalid credentials"}` or missing `access_token` key

### 3.4 CLI client mode — scan
```bash
export VULNREACH_URL=http://localhost:8000
export VULNREACH_TOKEN="$TOKEN"

SCAN_ID=$(vulnreach scan --repo-path /absolute/path/to/labs/python_vuln_app --wait 2>/dev/null | tail -1)
echo "SCAN_ID=$SCAN_ID"
```

> **Note:** `--repo-path` must be the path as seen by the server container.
> For remote repos use `--repo-url` instead (no path resolution needed).

**PASS:** Scan ID returned, status is `completed` / `partial` / `blocked`
**FAIL:** `API error 401` or scan stuck in `started`

### 3.5 Remote repo scan (recommended for Docker testing)
```bash
export VULNREACH_URL=http://localhost:8000
export VULNREACH_TOKEN="$TOKEN"

SCAN_ID=$(vulnreach scan \
  --repo-url https://github.com/your-org/your-repo \
  --wait 2>/dev/null | tail -1)
```

**PASS:** Scan completes, scan ID printed
**FAIL:** Git clone failure or auth error

### 3.6 Fix plan via server
```bash
vulnreach fix-plan --scan-id "$SCAN_ID" --format markdown
```

**PASS:** Same as standalone 2.4 — markdown checklist
**FAIL:** `API error 404` — scan not found on server

### 3.7 New API endpoints — direct curl verification

```bash
AUTH="Authorization: Bearer $TOKEN"

# Fix plan
curl -s -H "$AUTH" http://localhost:8000/scan/$SCAN_ID/fix-plan | python3 -m json.tool
```
**PASS:** JSON with `fix_plan` array and `summary.reachable_cves_fixable` integer

```bash
# Call graph (replace CVE ID with one from your scan)
curl -s -H "$AUTH" http://localhost:8000/scan/$SCAN_ID/graph/CVE-2021-33503 | python3 -m json.tool
```
**PASS:** `{"scan_id": ..., "cve_id": ..., "call_chain_graph": "graph LR\n..."}`
**PASS (no graph):** HTTP 404 with `{"detail": "No call graph found for CVE '...'"}`

```bash
# Explain (offline)
curl -s -H "$AUTH" "http://localhost:8000/scan/$SCAN_ID/explain/CVE-2021-33503?provider=none" | python3 -m json.tool
```
**PASS:** `{"scan_id": ..., "cve_id": ..., "explanation": "<multi-line string>"}` — HTTP 200
**FAIL:** HTTP 500 or empty explanation string

### 3.8 Dashboard
Open `http://localhost:8000` in a browser.

**PASS:**
- Login page renders
- After login: Scan History table loads with at least one row
- Clicking a row opens the detail panel
- Recent Scans columns are drag-resizable

**FAIL:**
- Blank page / 404
- Console errors on load

---

## 4. Edge Cases

### 4.1 Missing repo path
```bash
vulnreach scan
```
**PASS:** `Error: Provide --repo-path or --repo-url.`
**FAIL:** Traceback

### 4.2 Invalid scan ID
```bash
vulnreach fix-plan --scan-id 00000000-0000-0000-0000-000000000000
```
**PASS:** `Error: Scan '00000000-...' not found.`
**FAIL:** Traceback or silent empty output

### 4.3 No findings (clean repo)
```bash
vulnreach fix-plan --scan-id "$SCAN_ID" --format markdown
# (using a scan of a repo with no vulnerabilities)
```
**PASS:** `_No reachable CVEs with available fixes found._`
**FAIL:** Exception or empty output with exit 1

### 4.4 Server unreachable (client mode)
```bash
vulnreach --url http://localhost:9999 scan --repo-path ./labs/python_vuln_app
```
**PASS:** `Error: ...Connection refused` (clean ClickException, no traceback)
**FAIL:** Unhandled `requests.exceptions.ConnectionError` traceback

---

## 5. Environment Variable Reference

| Variable | Required for | Default |
|---|---|---|
| `VULNREACH_URL` | Client mode | — |
| `VULNREACH_TOKEN` | Client mode | — |
| `VULNREACH_USERNAME` | Client mode auto-login | — |
| `VULNREACH_PASSWORD` | Client mode auto-login | — |
| `SQLITE_PATH` | Standalone | `~/.vulnreach/vulnreach.db` |
| `DATABASE_URL` | Docker / Postgres | — |
| `ANTHROPIC_API_KEY` | `--provider anthropic` | — |
| `SECRET_KEY` | Server (Docker) | **required** |
| `SEED_ADMIN_USERNAME` | Server first boot | — |
| `SEED_ADMIN_PASSWORD` | Server first boot | — |

> **Storage precedence:** `DATABASE_URL` takes priority over `SQLITE_PATH`. If both are set the
> Postgres backend is used and `SQLITE_PATH` is ignored. Unset `DATABASE_URL` (or remove it from
> `.env`) to force SQLite in local/standalone development.

---

## 6. Quick Smoke Test Script

Run this end-to-end to verify a working standalone installation:

```bash
#!/usr/bin/env bash
set -e

echo "=== VulnReach Smoke Test ==="

# Install
pip install vulnreach -q

# Verify CLI
vulnreach --help | grep -q "scan" && echo "PASS: CLI registered"

# Scan test app
SCAN_ID=$(vulnreach scan --repo-path ./labs/python_vuln_app 2>/dev/null | tail -1)
[[ "$SCAN_ID" =~ ^[0-9a-f-]{36}$ ]] && echo "PASS: scan completed, ID=$SCAN_ID" || (echo "FAIL: invalid scan ID"; exit 1)

# Fix plan
vulnreach fix-plan --scan-id "$SCAN_ID" --format json | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'PASS: fix-plan returned {len(d)} items')"

# Fix plan markdown
vulnreach fix-plan --scan-id "$SCAN_ID" --format markdown | grep -q "VulnReach Fix Plan" && echo "PASS: markdown fix plan"

# Explain (offline)
vulnreach explain --help | grep -q "provider" && echo "PASS: explain command registered"

echo "=== All smoke tests passed ==="
```
