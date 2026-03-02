# Dynamic Analysis — Implementation TODO

---

## Trigger Condition
- Read `scan.runtime.enabled` from config yaml
- If `False` → skip everything below, run static only
- If `True` → proceed with dynamic analysis flow

---

## Step 1 — Pre-flight Checks
- Check if `Dockerfile` exists in cloned repo
- Check if `openapi.json` (or `openapi.yaml`) exists in cloned repo
- If either is missing → log warning, skip dynamic, continue with static only
- If both exist → proceed

---

## Step 2 — Patch the Dockerfile
- Read the existing Dockerfile
- Find the CMD line
- If CMD already starts with `coverage` → skip (already patched)
- If CMD starts with `gunicorn` or `uvicorn` → inject coverage like:
  - FROM: `CMD ["uvicorn", "-w", "1", ...]`
  - TO:   `CMD ["coverage", "run", "--source=.", "-m", "uvicorn", "-w", "1", ...]`
- Write patched Dockerfile to a temp working dir (do NOT overwrite original)
- Build new Docker image from patched Dockerfile with tag `<original_name>:instrumented`
- Start the container, wait until healthy (poll the base URL or /health)

---

## Step 3 — Run Schemathesis (NOT IMPLEMENTED YET)
- TODO: implement schemathesis runner
- Command to run:
  ```
  schemathesis run http://localhost:<port>/openapi.json
  ```
- Wait for schemathesis to finish firing all requests
- Wait additional `coverage_wait` seconds (default 10) for coverage data to flush

---

## Step 4 — Collect Coverage Data
- Exec into container:
  ```
  cd /app && coverage json -o /tmp/coverage.json
  ```
- Copy out of container:
  ```
  docker cp <container>:/tmp/coverage.json ./coverage.json
  ```
- Tear down the instrumented container
- If coverage.json is empty or missing → log warning, skip correlation

---

## Step 5 — Correlate Static + Dynamic
- Load static findings from `python_reachability` output (already exists)
- Load dynamic hit set from `coverage.json` — extract executed `(file, function)` pairs
- For each vuln in static findings apply verdict:
  - `CONFIRMED_REACHABLE`   → function in static graph AND in dynamic hit set
  - `POTENTIALLY_REACHABLE` → function in static graph but NOT hit dynamically
  - `UNREACHABLE`           → not reachable in either
- Attach verdict to each finding in the final report output

---

## Config Fields Expected
```yaml
runtime:
  enabled: true
  timeout: 60           # max time to wait for container + schemathesis
  coverage_wait: 10     # seconds to wait after traffic before collecting
  container_port: 3000  # port the app runs on inside container
```

---

## Notes
- Always patch a COPY of the Dockerfile, never the original
- coverage.json must be collected while container is still running (process hasn't exited)
- schemathesis step is a stub for now — wire it in once implemented
- Correlation step depends on static findings already being complete before dynamic runs