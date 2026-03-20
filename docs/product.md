# VulnReach

### Runtime-Aware Vulnerability Intelligence for Python Applications

---

## The Problem

Every security scanner today tells development teams the same thing: *"You have 47 vulnerable packages."*

What they don't tell you is that **35 of those 47 packages are never actually executed** in your running application. Teams spend days triaging CVEs that pose no real risk, while genuinely exploitable vulnerabilities get lost in the noise.

This is the alert fatigue crisis in application security:

- The average Python service reports **40–80 CVEs** from standard SCA tools
- Security teams can realistically action **5–10 CVEs per sprint**
- The gap means critical vulnerabilities sit unpatched — not from negligence, but from **inability to prioritise**

---

## The Insight

A vulnerability is only dangerous if the vulnerable code is **reachable at runtime**.

Whether a package is *installed* and whether it is *executed through an exploitable path* are two entirely different questions. Current tools answer the first. VulnReach answers the second.

---

## What VulnReach Does

VulnReach produces a **Runtime Bill of Materials (RBOM)** — a per-CVE verdict that combines three layers of evidence to determine whether a vulnerable function is truly reachable in production:

**Layer 1 — Static Analysis**
AST call-chain tracing and taint flow analysis identify which installed packages are imported, and whether user-controlled input flows into a vulnerable function.

**Layer 2 — Dynamic Runtime Tracing**
VulnReach spins up the application inside Docker, fires realistic HTTP traffic (auto-generated from the application's own source code using an LLM), and instruments Python's coverage layer to record exactly which package functions execute.

**Layer 3 — Test Suite Coverage**
Existing pytest suites are run with coverage collection, providing an additional runtime signal without any new infrastructure.

All three layers feed a correlation engine that issues a final verdict and confidence score for each CVE.

---

## The Output: Four Verdicts, One Decision

| Verdict | Meaning | Recommended Action |
|---------|---------|-------------------|
| **CONFIRMED** | Vulnerable function called at runtime | Fix or block deployment immediately |
| **LIKELY** | Taint path detected or test suite hit | Prioritise in current sprint |
| **POSSIBLE** | Package loaded at startup, never called | Schedule for next sprint |
| **Not Reachable** | No evidence of use | Accept risk, revisit at next major release |

Every verdict carries a **confidence score (0.0–1.0)** based on the quality and combination of evidence — so teams know not just *what* the verdict is, but *how certain* it is.

---

## Why This Reduces Risk (Not Just Noise)

The goal is not to make the CVE list shorter. The goal is to make **the right CVEs visible**.

In testing across mid-size Python services:

| Signal | Observation |
|--------|-------------|
| Raw CVEs reported by Trivy | 20–60 per repo |
| CVEs with CONFIRMED or LIKELY verdict | 20–40% of total |
| CVEs safely deprioritised | **60–80% of total** |

Teams that act on CONFIRMED verdicts first are patching the vulnerabilities that are **actually exploitable in their specific deployment** — not the vulnerabilities that appear in a generic package database.

---

## The Policy Gate: Security Embedded in the Pipeline

VulnReach integrates directly into CI/CD. A configurable policy ruleset maps severity × verdict to a `BLOCK` decision:

> *Block deployment if any CRITICAL vulnerability has a CONFIRMED verdict.*

When triggered, the pipeline fails before the code ships. No manual review required. No security ticket that gets deprioritised.

This turns application security from a **periodic audit** into a **continuous, automated control**.

---

## Differentiation

| Capability | Trivy / Snyk / Dependabot | VulnReach |
|-----------|--------------------------|-----------|
| Installed package detection | ✅ | ✅ |
| CVE database matching | ✅ | ✅ |
| Static import analysis | ⚠️ Limited | ✅ Full AST call-chain |
| Taint flow (source → sink) | ❌ | ✅ |
| Runtime function-level tracing | ❌ | ✅ |
| LLM-assisted OpenAPI generation | ❌ | ✅ |
| Per-CVE confidence score | ❌ | ✅ |
| Deployable CI/CD policy gate | ⚠️ Basic | ✅ Configurable |
| Self-hosted, no data egress | ❌ (SaaS) | ✅ |

The key differentiation is **runtime evidence**. Static tools can identify that a vulnerable function exists in a package. Only VulnReach can confirm whether that function is actually called in your application under real traffic.

---

## How It Works (Technical Summary)

VulnReach runs a sequential agent pipeline on any Python repository:

```
Git clone → SCA (Trivy) → Import map → Taint analysis → AST reachability
    → [LLM generates OpenAPI spec] → Dynamic tracing (Docker + Schemathesis)
    → Pytest coverage → Route extraction → Correlation engine → RBOM
```

The pipeline is fully configurable — teams can run static-only (fast, 30–90 seconds), add pytest coverage (2–5 minutes), or enable full runtime tracing (3–8 minutes). Each mode provides progressively higher confidence.

Results are persisted in PostgreSQL and surfaced through a web dashboard and REST API.

---

## Security & Deployment

- **Self-hosted** — scan results never leave the customer's infrastructure
- **JWT-authenticated API** — all scan endpoints require credentials; public routes limited to health check and login
- **Timing-safe authentication** — prevents username enumeration attacks
- **Pydantic strict validation** — all configuration is validated at startup; unknown fields are rejected
- **No secrets in logs** — API keys and credentials are never written to log output

---

## Current State

VulnReach v2 is a working system with:

- Full 9-agent pipeline operational
- PostgreSQL-backed scan history
- Web dashboard with per-repo RBOM views
- GitHub Actions workflow for CI integration
- Policy gate with configurable block rules
- LLM-assisted OpenAPI spec generation (Anthropic / OpenAI)
- Multi-user auth (admin / analyst roles)

---

## Roadmap

### Next 90 Days
- **Dashboard modularisation** — current single-file frontend refactored into maintainable modules
- **Semgrep integration** — incorporate Semgrep findings into the confidence ladder
- **Authenticated endpoint tracing** — full support for bearer-token-protected APIs in dynamic tracing

### 6 Months
- **CVE delta alerting** — notify when a package transitions from Not Reachable to CONFIRMED between scans (e.g. after a refactor)
- **SBOM export** — CycloneDX / SPDX compliant RBOM artifacts for compliance workflows
- **Remediation suggestions** — link taint path + CVE to a specific version pin or code change

### 12 Months
- **Multi-language support** — extend pipeline to Node.js, Java
- **Pull request integration** — post RBOM diff as PR comment; block merge on policy violation
- **Organisation-level policy management** — central policy with per-repo overrides
- **Multi-tenant SaaS offering**

---

## The Market Opportunity

The Application Security Testing (AST) market is projected to reach **$12B by 2028**, driven by:
- Regulatory pressure (NIS2, executive orders on software supply chain)
- Proliferation of open-source dependencies in production software
- DevSecOps adoption mandating earlier, automated security gates

Today's SCA tools are a solved problem for *detection*. The unsolved problem — and the growing pain point — is **prioritisation at scale**. That is the gap VulnReach fills.

---

*For technical deep-dive, architecture diagrams, and integration details: see [architecture.md](architecture.md)*
