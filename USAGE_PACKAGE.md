# VulnReach Package Usage

This guide is for the Python package/CLI workflow (`pip install vulnreach`).

---

## 1. Install

### 1.1 Prerequisites
- Python `3.11+`
- `git`
- `trivy` on PATH

Install Trivy:
- macOS: `brew install trivy`
- Debian/Ubuntu: `sudo apt-get install trivy`

### 1.2 Install package
```bash
pip install vulnreach
```

Verify:
```bash
vulnreach --version
vulnreach --help
```

Expected commands:
- `scan`
- `fix-plan`
- `replay`
- `explain`

---

## 2. Dependencies

### Required for package mode
- Python runtime + package deps (installed by `pip install vulnreach`)
- `trivy`

### Optional (graceful skip if missing)
- `semgrep`
- `tainter`

### Required only for dynamic runtime scanning
- Docker + Docker Compose
- Explicit opt-in env:
  - `VULNREACH_ALLOW_DOCKER_DAEMON=true`
- If running containerized runtime profile:
  - `DOCKER_HOST=tcp://docker-socket-proxy:2375` (set by runtime compose profile)

---

## 3. Startup Modes

### 3.1 Local standalone mode (default)
No server URL set:
```bash
vulnreach scan --repo-path ./labs/python_vuln_app
```

Storage:
- SQLite by default at `~/.vulnreach/vulnreach.db`

Override DB path:
```bash
SQLITE_PATH=/tmp/vulnreach.db vulnreach scan --repo-path ./labs/python_vuln_app
```

### 3.2 Client mode (talk to running server)
Set URL and token:
```bash
export VULNREACH_URL=http://localhost:8000
export VULNREACH_TOKEN=<jwt>
```

Then run:
```bash
vulnreach scan --repo-url https://github.com/your-org/your-repo --wait
```

---

## 4. Core Usage

### 4.1 Scan
```bash
vulnreach scan --repo-path ./labs/python_vuln_app
```

With policy-style exit behavior:
```bash
vulnreach scan --repo-path ./labs/python_vuln_app --fail-on CONFIRMED
```

### 4.2 Fix plan
```bash
vulnreach fix-plan --scan-id <scan_id>
vulnreach fix-plan --scan-id <scan_id> --format markdown
vulnreach fix-plan --scan-id <scan_id> --format json
```

### 4.3 Explain a CVE
```bash
vulnreach explain CVE-2021-33503 --scan-id <scan_id>
```

### 4.4 Replay call graph
```bash
vulnreach replay CVE-2021-33503 --scan-id <scan_id>
vulnreach replay CVE-2021-33503 --scan-id <scan_id> --format mermaid
```

---

## 5. Useful Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SQLITE_PATH` | Local standalone DB path | `~/.vulnreach/vulnreach.db` |
| `VULNREACH_URL` | Enable client mode | unset |
| `VULNREACH_TOKEN` | API auth token for client mode | unset |
| `VULNREACH_USERNAME` | Auto-login username (client mode) | unset |
| `VULNREACH_PASSWORD` | Auto-login password (client mode) | unset |
| `VULNREACH_ALLOW_DOCKER_DAEMON` | Explicit opt-in for dynamic Docker scanning | unset (`false`) |
| `DOCKER_HOST` | Docker endpoint (runtime profile) | unset |

---

## 6. Quick Troubleshooting

- `Error: Provide --repo-path or --repo-url`:
  - pass one of `--repo-path` or `--repo-url`.
- `trivy` not found:
  - install `trivy` and retry.
- `API error 401` in client mode:
  - refresh token or set correct `VULNREACH_TOKEN`.
- Dynamic scan skipped with daemon opt-in reason:
  - set `VULNREACH_ALLOW_DOCKER_DAEMON=true` intentionally.
