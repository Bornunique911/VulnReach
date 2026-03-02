# VulnReach v2 (Phase 1 scaffold)

FastAPI skeleton for VulnReach v2 Phase 1 using Trivy (SCA) and Tainter (reachability) stubs with deterministic correlation logic.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# set your Postgres connection string
export DATABASE_URL="postgresql://user:pass@localhost:5432/vulnreach"
```

## Run API

```bash
uvicorn main:app --reload
```

POST `/scan` with `{"repo_path": "/path/to/repo", "config_path": "/path/to/config.yml"}` to start a scan. GET `/scan/{scan_id}` for status.

## Tests

```bash
pytest
```

## Notes

- Trivy and Tainter agents are stubbed; wire actual CLI/static analysis in follow-up.
- Postgres is now required (see `DATABASE_URL` above).
