# Threat Model

This document defines VulnReach trust boundaries, key threats, and current mitigations using STRIDE.

## Scope

In scope:
- API server (`api/server.py`)
- Scan agents (`agents/*`)
- Storage layer (PostgreSQL/SQLite)
- Dashboard UI (`dashboard/*`)
- Optional dynamic runtime path (`dynamic_reachability`, eBPF)

Out of scope:
- Third-party scanner internals (Trivy/Semgrep/etc.)
- Customer application code quality

## Trust Boundaries

1. User/CI client -> VulnReach API
- Authenticated requests, scan launch, report access.

2. VulnReach API -> Scanner execution environment
- Runs subprocesses and (optionally) Docker-runtime workflows.

3. VulnReach -> Data store
- Persists scan metadata, findings, raw outputs, API keys.

4. VulnReach -> External services
- Git providers, optional LLM provider, optional container registry pulls.

5. Dynamic runtime mode -> Host Docker daemon
- Highest privilege boundary; can affect host containers when enabled.

## Data Classification

- Sensitive:
  - Raw scan artifacts (may include paths, snippets, dependency inventory)
  - API keys/JWT secrets
  - Taint/dynamic evidence (can expose code structure)
- Moderate:
  - Scan metadata, correlation summaries
- Public:
  - Project docs, non-secret configuration templates

## STRIDE Analysis

## Spoofing
- Threat: Token/API key theft and reuse.
- Controls:
  - JWT auth with expiration.
  - API key hashing at rest.
  - Ownership checks on scan retrieval endpoints.
- Gaps:
  - Optional MFA/SSO not yet present.

## Tampering
- Threat: Malicious repository manipulates scan outputs/evidence.
- Controls:
  - Structured parsing and normalization in correlation pipeline.
  - Route-gate logic and package+CVE pairing reduce evidence spoofing.
- Gaps:
  - Artifact signing/attestation not yet implemented.

## Repudiation
- Threat: Unattributed scan starts/deletes or key use.
- Controls:
  - Audit logs for scan access/create/delete and key usage timestamps.
- Gaps:
  - Signed immutable audit trail not yet present.

## Information Disclosure
- Threat: Data leak via permissive CORS, broad raw output exposure.
- Controls:
  - CORS allowlist support.
  - Auth required for scan/raw endpoints.
- Gaps:
  - Fine-grained field-level redaction policy is limited.

## Denial of Service
- Threat: Oversized payloads, expensive scan submissions.
- Controls:
  - Request body size limit (`MAX_REQUEST_BODY_BYTES`).
  - Login rate limiting.
  - Timeouts in runtime scanning.
- Gaps:
  - Per-user scan concurrency quotas not yet strict.

## Elevation of Privilege
- Threat: Abuse Docker daemon access in dynamic mode.
- Controls:
  - Dynamic runtime now requires explicit opt-in (`VULNREACH_ALLOW_DOCKER_DAEMON=true`).
  - Base compose no longer mounts Docker socket by default.
  - Runtime profile routes Docker access via restricted `docker-socket-proxy` (`DOCKER_HOST=tcp://docker-socket-proxy:2375`).
  - eBPF mode requires separate explicit opt-in.
- Gaps:
  - Socket-proxy API policy still needs continuous review as runtime features evolve.

## Abuse Scenarios

1. Malicious repo tries to trigger host-level actions during dynamic scan.
- Risk: high when Docker daemon access is enabled.
- Mitigation: keep dynamic mode disabled unless needed; use isolated worker hosts and socket proxy.

2. Attacker with read-only token enumerates other users' scans.
- Mitigation: strict owner check returns 404 for unauthorized scan IDs.

3. Scanner/tool output poisoning to inflate/deflate reachability.
- Mitigation: correlation requires structured evidence chain and package+CVE matching.

## Hardening Baseline

- Keep `scan.runtime.enabled: false` by default.
- Use base `docker-compose.yml` for least privilege.
- Enable dynamic only with `docker-compose.runtime.yml` in isolated environments.
- Rotate JWT secret and admin bootstrap credentials.
- Restrict `CORS_ORIGINS` in production.

## Verification

- Contract tests for scan response shape (`summary` and reachability buckets).
- Deterministic multi-language fixture tests (Java/JavaScript/Go) in CI.
- Correlation unit tests for package+CVE pairing and route gate behavior.
