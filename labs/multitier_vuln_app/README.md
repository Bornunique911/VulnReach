# multitier_vuln_app

**3-tier vulnerable Django application for VulnReach testing.**

```
Nginx (80) → Django API (8000) → PostgreSQL (5432)
```

## Vulnerable Packages

| Package | Version | CVE | Vulnerable endpoint |
|---------|---------|-----|---------------------|
| Django | 3.2.0 | CVE-2021-44420, CVE-2022-22818 | all |
| PyYAML | 5.4.1 | CVE-2020-14343 | `POST /api/posts/import/` |
| Pillow | 8.3.1 | CVE-2021-34552 | `POST /api/images/upload/` |
| requests | 2.27.1 | CVE-2023-32681 | `GET /api/fetch-preview/` |
| PyJWT | 2.3.0 | CVE-2022-29217 | `POST /api/auth/token/` |
| bleach | 3.3.0 | CVE-2021-23980 | `POST /api/content/sanitize/` |
| lxml | 4.6.5 | CVE-2022-2309 | `POST /api/feed/parse/` |
| Markdown | 3.2.2 | XSS | `POST /api/posts/` |
| cryptography | 36.0.0 | CVE-2023-49083 | `GET /api/backup/export/` |

## Run Full Stack

```bash
cd labs/multitier_vuln_app
docker compose up --build
```

- Frontend: http://localhost:80
- API: http://localhost:8000/api/

## Scan with VulnReach

```bash
# From vulnreach-agent root
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "repo_path": "labs/multitier_vuln_app",
    "config_path": "labs/multitier_vuln_app/scan.yml"
  }'
```

Expected: ~9 packages with CVEs → 7–8 `DYNAMICALLY_REACHABLE` (all packages have routed endpoints that exercise them under Schemathesis fuzzing).
