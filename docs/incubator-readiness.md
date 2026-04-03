# OSS / OWASP Incubator Readiness

This checklist tracks minimum readiness for an OWASP Incubator-quality OSS security tool.

Status legend:
- `[x]` complete
- `[~]` in progress
- `[ ]` not started

## P0 Security and Trust

- [x] Secure-by-default runtime boundary:
  - Dynamic daemon mode requires `VULNREACH_ALLOW_DOCKER_DAEMON=true`.
  - Base compose excludes Docker socket by default.
  - Runtime override file isolates high-privilege mode.
- [x] eBPF explicit opt-in (`VULNREACH_ALLOW_EBPF=true`).
- [~] Command execution hardening audit for all subprocess paths.
- [x] Docker socket proxy profile (`dev-images/docker-compose.runtime.yml`) for dynamic mode isolation.

## P0 Correctness and Determinism

- [x] Correlation keyed by `(package, CVE)` not CVE-only.
- [x] Route gate enforced for dynamic reachability.
- [x] Multi-language reachability path wired into runner.
- [x] `GET /scan/{id}` contract returns summary + classified buckets.
- [x] Deterministic Java/JavaScript/Go fixture tests in CI.

## P0 Threat Modeling and Documentation

- [x] Threat model document with trust boundaries and STRIDE analysis.
- [x] Deployment guidance distinguishes low-privilege vs high-privilege modes.
- [~] Data retention/redaction policy for raw findings.
- [ ] Architecture decision records (ADRs) for major security tradeoffs.

## OSS Governance

- [x] Apache 2.0 license, contribution guide, security policy.
- [~] Maintainer rotation/on-call + response SLA documented.
- [ ] Versioned support policy and deprecation windows.
- [ ] Signed release artifacts and provenance (SLSA-style).

## CI/CD Quality Gates

- [x] Lint + unit tests + coverage gate.
- [x] Deterministic multi-language fixture checks.
- [ ] End-to-end nightly scan suite with pinned vulnerable fixtures.
- [ ] Performance regression baseline (large monorepo fixture).

## Recommended Next 2 Weeks

1. Add artifact attestation/signing for scan outputs.
2. Add end-to-end nightly fixture scans with time budgets and flake tracking.
3. Publish maintainer/SLA policy in `CONTRIBUTING.md`.
4. Add ADRs for dynamic runtime trust-boundary decisions.
