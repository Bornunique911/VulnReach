# VulnReach — Product & Architecture Document

> Version 1.0 · Generated 2026-03-22 · Confidential

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Product Overview](#3-product-overview)
4. [Core Features](#4-core-features)
5. [System Architecture](#5-system-architecture)
6. [Reachability Engine Deep Dive](#6-reachability-engine-deep-dive)
7. [Technical Design Breakdown](#7-technical-design-breakdown)
8. [Output & User Experience](#8-output--user-experience)
9. [Competitive Positioning](#9-competitive-positioning)
10. [Gaps & Risks](#10-gaps--risks)
11. [Product Roadmap](#11-product-roadmap)
12. [Monetization Strategy](#12-monetization-strategy)

---

## 1. Executive Summary

VulnReach is a **runtime-aware, AI-augmented application security platform** that solves the #1 problem in SCA (Software Composition Analysis): **alert fatigue from unreachable vulnerabilities**.

Where Snyk tells you "you have 200 CVEs," VulnReach tells you "3 of those CVEs are actually reachable from an HTTP endpoint, confirmed by runtime execution." It achieves this by chaining five evidence layers — SCA → taint analysis → static call-chain → runtime coverage → LLM-steered DAST — producing findings with confidence scores, risk scores, and a 4-tier reachability classification that directly maps to engineer effort required.

**Target audience:** AppSec engineers, DevSecOps teams, and platform security orgs at companies running Python-based services. The output is designed to feed CI/CD pipeline gates and security dashboards rather than replace them.

---

## 2. Problem Statement

Modern SCA tools (Snyk, Dependabot, OWASP Dependency-Check) have a fundamental accuracy problem:

> **They report every CVE in every dependency, regardless of whether the vulnerable code is ever called at runtime.**

In a typical Python service with 150 transitive dependencies, 80–95% of CVEs flagged are in packages that are either not imported, imported but never called, or called through paths that are never triggered at runtime. Engineers spend most of their time triaging noise.

The root cause is that SCA tools operate at the **package dependency graph level**, not the **application execution graph level**. They know what's installed; they don't know what's run.

VulnReach's hypothesis: if you can trace the path from an HTTP request to a vulnerable function in a dependency, and confirm that path is executed at runtime, you have a finding worth acting on immediately.

---

## 3. Product Overview

VulnReach is a **multi-layer reachability intelligence engine** that combines:

| Layer | What it does |
|-------|-------------|
| SCA (Trivy) | Finds CVE-bearing packages |
| Taint Analysis (tainter CLI) | Traces user input → vulnerable sink |
| Static Reachability (AST + call graph) | Confirms package is imported and called |
| Dynamic Reachability (Docker + schemathesis + coverage.py) | Confirms execution at runtime |
| LLM-Steered DAST | Confirms exploitability via actual HTTP probes |

The pipeline outputs a **4-tier reachability classification** per CVE:

- `DYNAMICALLY_REACHABLE` — confirmed by runtime execution evidence
- `STATICALLY_REACHABLE` — confirmed by code analysis (subtype: FUNCTION / FILE / IMPORT / TRANSITIVE)
- `UNCERTAIN` — taint flow exists but not confirmed
- `NOT_REACHABLE` — no evidence of usage

Each finding gets a **risk score** (`severity × reachability_multiplier × exposure_modifier`) and a **priority** (P1–P4).

---

## 4. Core Features

### 4.1 Multi-Strategy SCA

Trivy scans the repository for dependency manifests and produces CVE findings with package, version, severity, and fix version. VulnReach enriches these with reachability before surfacing them.

### 4.2 Taint Flow Analysis

Wraps the `tainter` CLI (`tainter scan --format json`) to trace data flow from HTTP sources (request parameters, headers, cookies) to vulnerable sinks (SQL queries, subprocess calls, YAML loads, pickle loads, etc.).

Handles PyPI-to-import name mismatches (`pyyaml` → `yaml`, `djangorestframework` → `rest_framework`) and DRF mis-attribution by reading imports directly from sink source files.

**Known PyPI → import name mappings:**

| PyPI name | Import name |
|-----------|------------|
| `pyyaml` | `yaml` |
| `pillow` | `PIL` |
| `beautifulsoup4` | `bs4` |
| `djangorestframework` | `rest_framework` |
| `pyjwt` | `jwt` |
| `psycopg2-binary` | `psycopg2` |
| `python-dateutil` | `dateutil` |

### 4.3 AST-Based Static Reachability

A purpose-built Python AST visitor (`UsageVisitor`) traverses every `.py` file in the repo. Per package, it tracks:

- `import` / `from_import` statements
- `function_call` usages (e.g., `requests.get(...)`)
- `attribute_access` usages (e.g., `yaml.load`)
- `return_value` usages
- `enclosing_function` — which function contains the usage

Optionally builds a call graph (`PythonCallGraphBuilder`) and generates a Mermaid diagram tracing entry points to vulnerable code. Risk levels (CRITICAL / HIGH / MEDIUM / LOW / NOT_REACHABLE) are assigned based on number of active calls and file spread.

### 4.4 Instrumented Docker Runtime

For repos with a `Dockerfile` or `docker-compose.yml`:

1. Patches the Dockerfile to inject `sitecustomize.py` that activates `coverage.process_startup()`
2. Optionally installs `runtime_hooks` (audit, imports, sinks) that flush taint events on process exit
3. Spins up the container and runs schemathesis against the OpenAPI spec to generate traffic
4. Extracts `coverage.json` and correlates executed lines back to vulnerable packages

**Three coverage correlation strategies:**

| Strategy | Signal | Confidence |
|----------|--------|-----------|
| Library source files in executed lines | `sink_reachable = True` | 0.95 |
| File importing library was executed | `import_time_hit = True` (weak; promoted only with taint + static) | 0.95 (promoted) |
| App-side caller in executed lines | `call_chain_exists = True` | 0.75 |

Supports **eBPF non-invasive tracing** (bpftrace / bcc, `openat` syscalls or USDT probes) as an alternative to coverage.py patching — no Dockerfile modification required.

### 4.5 Intelligent DAST

An LLM-steered exploit confirmation loop:

1. Tainter flows (source → sink paths) written to a temp JSON file
2. `intelligent_dast.runner.run_dast()` called with taint file, target URL, OpenAPI spec, and LLM config
3. Per flow: HTTP context built (method, endpoint, parameter location) from OpenAPI spec
4. `PayloadSession` runs up to N iterations: LLM generates payload → HTTP request → LLM analyzes response → CONFIRMED / MUTATE / STOP
5. Confirmed findings carry exact payload, iteration count, and evidence string

**Supported LLM providers:** Anthropic (Claude), OpenAI, Ollama (local models)

### 4.6 Correlation Engine

```
Risk Score = base_severity × reachability_multiplier × exposure_modifier
```

| Severity | Base |
|----------|------|
| CRITICAL | 4 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 1 |

| Verdict | Multiplier |
|---------|-----------|
| CONFIRMED | 1.5× |
| LIKELY | 1.2× |
| POSSIBLE | 1.0× |
| NOT_OBSERVED | 0.5× |

| Exposure | Modifier |
|----------|---------|
| public | 1.3× |
| internal / private | 1.0× |

**Example:** CRITICAL + CONFIRMED + public = `4 × 1.5 × 1.3 = 7.8` → **P1**

**Priority thresholds:** P1 ≥ 5.0 · P2 ≥ 4.0 · P3 ≥ 3.0 · P4 = everything else

### 4.7 Policy-Driven CI Gate

`scan.yaml` `policy.block_if` rules set the pipeline to `BLOCK` when any finding matches a severity + verdict combination. Scan status returns `blocked` instead of `completed`, enabling CI/CD to fail the build.

```yaml
policy:
  block_if:
    - severity: CRITICAL
      verdict: CONFIRMED
    - severity: HIGH
      verdict: CONFIRMED
```

### 4.8 OpenAPI Auto-Generation

For repos without an OpenAPI spec, an LLM reads the route definitions and generates a valid OpenAPI 3.0 JSON document before the dynamic agent runs — dramatically improving schemathesis coverage.

---

## 5. System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│              REST API  (/scan, /scans, /scan/{id}, ...)              │
│              JWT Auth  (admin | analyst roles)                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ background task
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                          Orchestrator                                 │
│  ScanContext (mutable shared state passed through all agents)         │
│  Builds: static_reach_map → taint_cves → coverage_evidence           │
│          → dynamic_reach_map → DAST findings                         │
│  Gating:  5-link evidence chain required for DYNAMICALLY_REACHABLE   │
└───────┬──────────────────────────────────────────────┬───────────────┘
        │                                              │
        ▼                                              ▼
┌──────────────────┐                        ┌──────────────────────────┐
│   Agent Runner   │                        │   Correlation Service    │
│  Sequential:     │                        │   4-tier classification  │
│  1.  git         │                        │   risk_score()           │
│  2.  trivy       │                        │   priority assignment    │
│  3.  metadata    │                        │   policy gate            │
│  4.  tainter     │                        └──────────────────────────┘
│  5.  python_reach│
│  6.  semgrep     │
│  7.  route_extr  │
│  8.  openapi_gen │
│  9.  dynamic_reach│
│  10. pytest_cov  │
│  11. intell_dast │
└──────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    PostgreSQL  (JSONB-heavy schema)                   │
│  scans | vulnerabilities | reachability_evidence | correlation_results│
│  raw_outputs | semgrep_findings | routes_extracted | users            │
└──────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Dashboard  (Vanilla JS SPA)                        │
│  Scan list → Repo drilldown → Scan detail panel                       │
│  Tabs: Overview | Findings (4-tier cards) | Raw JSON                  │
│  Export: CSV (client-side) | PDF (server-side reportlab)              │
│  Theme: system/dark/light | JWT session                               │
└──────────────────────────────────────────────────────────────────────┘
```

### Execution Lifecycle (one scan)

1. `POST /scan` → creates DB row, fires background task
2. **GitAgent** (optional) → clones to `tempfile.mkdtemp()`, auto-discovers `vulnreach.yaml`
3. **TrivyAgent** → runs `trivy fs --format json`, populates `context.vulnerabilities`
4. **MetadataAgent** → builds import map via `importlib.metadata`, populates `context.import_map`
5. **TainterAgent** → runs `tainter scan --format json`, parses flows, correlates to CVEs, populates `context.taint_flows`
6. **PythonReachabilityAgent** → AST visitor across all `.py` files, optional call graph, emits CONFIRMED/LIKELY/NOT_OBSERVED per CVE
7. **SemgrepAgent** → runs `semgrep --config auto`, stores rule hits
8. **RouteExtractorAgent** → parses Flask/FastAPI/Django routes, populates `context.routes`
9. **OpenAPIGeneratorAgent** → LLM generates `openapi.json` if missing
10. **DynamicReachabilityAgent** → Dockerises app, runs schemathesis, extracts coverage, correlates
11. **PytestCoverageAgent** → runs test suite with `pytest --cov-report json`, correlates coverage
12. **IntelligentDastAgent** → writes taint flows to temp file, calls `run_dast()` in thread executor, LLM confirms exploitation
13. **Orchestrator** → builds final maps, calls `CorrelationService.correlate()`, updates scan status

### Database Schema

| Table | Purpose |
|-------|---------|
| `scans` | Scan lifecycle (id, status, metadata JSONB, created_at) |
| `vulnerabilities` | Trivy CVE output (package, cve_id JSONB array, severity, fix_version) |
| `reachability_evidence` | Per-CVE evidence from all agents (import_detected, call_chain_exists, sink_reachable, confidence, files JSONB) |
| `correlation_results` | Final classified findings (reachability_class, risk_score, priority, evidence JSONB) |
| `raw_outputs` | Full raw JSON output from each tool, keyed by (scan_id, tool_name) |
| `semgrep_findings` | Semgrep rule hits (check_id, path, start, finish, severity) |
| `routes_extracted` | HTTP routes (method, path, handler, file, framework, prefix) |
| `users` | Auth (username, password_hash bcrypt, role admin|analyst) |

---

## 6. Reachability Engine Deep Dive

### The 5-Link Evidence Chain

The core innovation is requiring all five links before awarding `DYNAMICALLY_REACHABLE`:

```
SCA (CVE exists in installed package)
    └─► Taint flow exists
         (tainter confirms user input reaches vulnerable sink)
              └─► Route exposure
                   (app has HTTP endpoints — route_extractor found routes)
                        └─► Static reachability
                             (AST confirms the code path exists)
                                  └─► Coverage confirmation
                                       (runtime execution confirmed via coverage.json)
                                            └─► DYNAMICALLY_REACHABLE ✓
```

### Gating Conditions (from `core/orchestrator.py`)

```python
if import_time_only:
    # Import-time hit is WEAK — only promote with full chain
    if not (has_taint and has_static):
        continue
    verdict = "CONFIRMED", confidence = 0.95

elif has_coverage and has_taint:
    # Direct library coverage + taint → CONFIRMED
    verdict = "CONFIRMED", confidence = 0.95

elif has_coverage and has_static:
    # Coverage + static without taint → LIKELY
    verdict = "LIKELY", confidence = 0.75

elif has_coverage:
    # Coverage alone → weak
    verdict = "POSSIBLE", confidence = 0.55

else:
    continue  # No coverage → not dynamically reachable
```

### False Positive Reduction

| Mechanism | What it prevents |
|-----------|-----------------|
| 5-link chain requirement | Promotions based on weak single-signal evidence |
| Import-time gating | Coverage hits at module load time inflating confidence |
| `NOT_OBSERVED` gets 0.5× risk multiplier | Unreachable CVEs buried in scoring |
| Framework packages → `TRANSITIVE` subtype | Django/Flask bootstrap imports inflating FUNCTION count |
| Short package names excluded (< 4 chars) | `os`, `re` false substring matches in sink matching |
| Taint-only findings → `UNCERTAIN` (not `STATICALLY_REACHABLE`) | Flows without coverage confirmation over-promoted |

### Confidence Calibration

| Evidence combination | Confidence |
|---------------------|-----------|
| Coverage + taint (direct library hit) | 0.95 |
| Import-time + taint + static (full chain) | 0.95 |
| Coverage + static (no taint) | 0.75 |
| Taint with call chain | 0.90 |
| Static AST only | 0.60 |

---

## 7. Technical Design Breakdown

### Key Modules

| File | Role |
|------|------|
| `core/orchestrator.py` | Evidence chain assembly, dynamic gating, scan lifecycle management |
| `core/models.py` | `ScanContext` (shared mutable state), `ReachabilityFinding`, `AgentResult` |
| `correlation/engine.py` | `reachability_verdict()`, `classify_reachability()`, risk scoring, priority thresholds |
| `correlation/service.py` | `CorrelationService.correlate()` — merges all evidence, applies policy |
| `agents/runner.py` | Sequential agent execution, context mutation, storage writes after each agent |
| `agents/agent_trivy.py` | Trivy CLI wrapper, CVE normalisation |
| `agents/agent_tainter.py` | `tainter` CLI wrapper, flow parsing, PyPI→import mapping, sink file import scanning |
| `agents/utils/python_reachability_analyzer.py` | AST visitor, call graph, per-package risk assessment |
| `agents/agent_dynamic_reachability.py` | Dockerfile patching, Docker orchestration, coverage extraction, 3-strategy correlation |
| `agents/agent_intelligent_dast.py` | Bridge to `intelligent_dast.runner.run_dast()` via thread executor |
| `intelligent_dast/runner.py` | LLM steering loop, per-flow `PayloadSession` orchestration |
| `intelligent_dast/flow_parser.py` | Tainter JSON → `AttackFlow` objects, confidence filtering, sink-based vuln class refinement |
| `intelligent_dast/llm_client.py` | Multi-provider LLM client (Anthropic/Ollama), per-session conversation history |
| `config/schema.py` | Pydantic config schema, `default_config()` for URL-only scans |
| `api/server.py` | FastAPI endpoints, JWT auth middleware, background task dispatch |
| `api/export.py` | reportlab PDF builder (4-section structured report) |
| `storage/repository.py` | Abstract `StorageRepository` + `PostgresRepository` with connection pooling |

### Design Patterns

| Pattern | Where used |
|---------|-----------|
| Pipeline / Chain of Responsibility | Agent sequence — each enriches `ScanContext` |
| Strategy | 3 Docker modes (eBPF / Compose / Dockerfile patch), 3 coverage strategies |
| Template Method | `BaseAgent.run()` abstract; each agent implements |
| Repository | `StorageRepository` abstract; `PostgresRepository` concrete |
| Policy Object | `PolicyRule` + `block_if` decoupled from scoring |
| Observer (via context mutation) | Agents write to `ScanContext`; downstream agents read |

### Extensibility

New agents: implement `BaseAgent`, add to `AgentRunner.__init__()`, add tool name to `AVAILABLE_TOOLS` in `server.py`. The `ScanContext` dataclass is the shared bus — agents read from it and write to it. No registration framework required.

### API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/login` | None | Exchange credentials for JWT |
| POST | `/scan` | User | Start a new scan |
| GET | `/scan/{id}` | User | Get full scan result |
| GET | `/scan/{id}/raw` | User | List tools with raw output |
| GET | `/scan/{id}/raw/{tool}` | User | Get raw tool output |
| GET | `/scan/{id}/export/pdf` | User | Download PDF report |
| GET | `/scans` | User | List all scans |
| GET | `/health` | None | Health check + boot_id |
| GET | `/tools` | None | List available tools |

### Config Knobs

```yaml
scan:
  static_reachability: true
  tools: [git, trivy, tainter, python_reachability, route_extractor, ...]
  runtime:
    enabled: false          # Enable Docker-based dynamic analysis
    timeout: 60             # Container + schemathesis timeout (seconds)
    coverage_wait: 10       # Wait after traffic before collecting coverage
    container_port: 3000    # App port inside container
    ebpf:
      enabled: false        # Non-invasive eBPF tracing (Linux only)
      mode: openat          # openat (portable) | usdt (requires Python+dtrace)
      tracer: bpftrace      # bpftrace | bcc
  openapi_generator:
    enabled: false          # LLM-generate OpenAPI spec if missing
    provider: anthropic     # anthropic | openai | ollama
    model: claude-sonnet-4-20250514
    max_tokens: 4096
  intelligent_dast:
    enabled: false          # LLM-steered DAST
    provider: anthropic     # anthropic | openai | ollama
    model: claude-sonnet-4-20250514
    base_url: ""            # Empty = auto-detect from container_port
    ollama_base_url: http://localhost:11434
    max_iter: 5
    auth_credentials: ""    # user:pass for target app auth

risk:
  exposure: private         # public | internal | private (affects risk multiplier)
  data_sensitivity: low     # low | medium | high

policy:
  block_if: []              # Empty = never block; add rules to gate CI
    # - severity: CRITICAL
    #   verdict: CONFIRMED
```

---

## 8. Output & User Experience

### Dashboard

A single-page Vanilla JS app with three main views:

**Scan History**
- Table grouped by repository
- Package count with severity breakdown (CRITICAL / HIGH / MEDIUM / LOW chips)
- Confirmed (DYNAMICALLY_REACHABLE) and Likely (STATICALLY_REACHABLE) counts
- Live status badges (running / completed / blocked / partial)
- Stat cards: total repos, confirmed vulns, likely vulns, running scans

**Scan Detail Panel** (slide-in)
Three tabs:

*Overview* — metadata grid: scan ID, repo, tools, status, package summary

*Findings* — 4-tier sorted cards (DYNAMICALLY_REACHABLE first, then by severity). Per package card shows:
- Evidence chain flags: import ✓ / call-chain ✓ / sink ✓ / taint ✓ / coverage ✓
- Static subtype badge: FUNCTION / FILE / IMPORT / TRANSITIVE
- CVE list (expandable)
- Files and functions involved
- Fix version ("Upgrade → X.Y.Z")

*Raw JSON* — full API response for the scan

**Export**
- **CSV** — client-side generation, per-package rows: package, CVEs, severity, reachability, verdict, priority, risk score, fix version, files, functions
- **PDF** — server-side reportlab, dark-themed, 4 sections: header + summary stats table + findings table + evidence details cards

### Scan Configuration

YAML-driven config file (`scan.yaml` / `vulnreach.yaml`) auto-discovered from cloned repo root. For URL-only scans with no config file, a sensible default is used (trivy + tainter + python_reachability + route_extractor, public exposure, no blocking).

### Finding Structure

Each finding in the API response carries:

```json
{
  "cve_id": "CVE-2023-XXXX",
  "package": "requests",
  "severity": "HIGH",
  "reachability_class": "DYNAMICALLY_REACHABLE",
  "static_subtype": null,
  "finding_type": "dynamic",
  "verdict": "CONFIRMED",
  "risk_score": 5.85,
  "priority": "P1",
  "confidence": 0.95,
  "evidence": {
    "import_detected": true,
    "call_chain_exists": true,
    "sink_reachable": true,
    "has_taint_flow": true,
    "has_coverage_hit": true,
    "files": ["app/views.py", "app/utils.py"],
    "function": "send_request, fetch_url"
  }
}
```

---

## 9. Competitive Positioning

| Dimension | Snyk | Semgrep | CodeQL | Endor Labs | VulnReach |
|-----------|------|---------|--------|------------|-----------|
| Primary category | SCA | SAST | SAST | SCA + Reachability | SCA + Reachability + DAST |
| Reachability | Call-graph (limited) | No | No | Call-graph (Java/Go/JS) | AST + taint + runtime coverage + LLM DAST |
| Runtime confirmation | No | No | No | No | ✅ (coverage.py + eBPF) |
| LLM exploit confirmation | No | No | No | No | ✅ (Anthropic / Ollama) |
| Dynamic traffic testing | No | No | No | No | ✅ (schemathesis) |
| Self-hostable | Partial | ✅ | No | No | ✅ (full) |
| Local LLM support | No | No | No | No | ✅ (Ollama) |
| Language support | Multi | Multi | Multi | Multi | Python (v1) |
| CI gate mechanism | PR status | `--error` flag | SARIF upload | Policy | `policy.block_if` + scan status |
| False positive strategy | CVSS filter | Rule precision | Query precision | Call-graph pruning | 5-link evidence chain |

### Where VulnReach wins

1. **Runtime coverage as first-class evidence** — the only tool where `coverage.json` directly gates the highest reachability tier
2. **LLM-steered exploit confirmation** — not just detection; the system attempts exploitation and reports whether it worked, which payload, and at which iteration
3. **Taint + coverage + DAST in a single pipeline** — no other tool combines all three
4. **Local LLM support** — Ollama integration means the DAST reasoning loop can run fully air-gapped; no data leaves the network
5. **eBPF non-invasive tracing** — test running containers without modifying them
6. **Policy-driven CI blocking** at the finding level — fine-grained severity × verdict combinations

### Where VulnReach is currently weaker

1. Python-only (Endor Labs supports Java, Go, JS, Rust, Python)
2. Requires Docker for dynamic analysis (not available in all CI environments)
3. `tainter` CLI is a hard external dependency
4. No SBOM export in standardized format (CycloneDX / SPDX)
5. No IDE plugins (VS Code, JetBrains)
6. No VEX (Vulnerability Exploitability eXchange) output

### Unique differentiator

> **VulnReach is the only tool that closes the loop from "this CVE exists" to "this CVE is exploitable" — using runtime coverage to confirm execution and LLM-steered HTTP probes to confirm exploitation.**

No existing tool in the market — Snyk, Endor Labs, Semgrep, CodeQL, or Oxeye — does all three: static reachability + runtime coverage confirmation + LLM exploit attempt.

---

## 10. Gaps & Risks

### Technical Gaps

| Gap | Severity | Path to fix |
|-----|----------|-------------|
| Hardcoded `tainter` binary path (`/Library/Frameworks/...`) | High | Full `shutil.which("tainter")` resolution |
| Pre-existing container not supported | High | Add `url` field to `RuntimeSettings`; skip Docker build when set |
| `cve_id` stored as JSONB array but correlation joins on TEXT | Medium | Normalise vulnerabilities table to TEXT `cve_id` |
| No multi-language support | High (market) | Language-specific taint + coverage agents for JS/Java |
| Coverage fails on multi-stage / distroless Dockerfiles | Medium | eBPF mode as automatic fallback |
| No SBOM in standardized format | Medium | CycloneDX generator from Trivy JSON output |
| Settings page not implemented | Low | Build with localStorage persistence |
| Google SSO / OIDC missing | Medium | Authlib OIDC middleware |
| `run_dast()` is synchronous in thread executor | Low | Full async rewrite |

### Accuracy Risks

- **Coverage false negatives:** schemathesis may not exercise all code paths → some reachable CVEs remain `STATICALLY_REACHABLE`
- **Taint false negatives:** `tainter` may miss flows through dynamic dispatch, decorators, or monkey-patching
- **LLM DAST false positives:** LLM may hallucinate confirmation from opaque 500 errors or generic error messages
- **Import-time hits:** Strategy 2 (import-in-executed-file) is promoted aggressively — may over-confirm

### Scalability Risks

- Single PostgreSQL connection pool (max=5) — fine for single-tenant; needs PgBouncer for multi-tenant
- Docker builds are sequential per scan — concurrent scanning requires container orchestration
- No scan queue / rate limiting — unbounded background tasks could exhaust resources

---

## 11. Product Roadmap

### Phase 1 — Current State (MVP Complete)

- ✅ Full Python pipeline: SCA → taint → static → dynamic → DAST
- ✅ Instrumented Docker runtime with coverage.py (+ eBPF mode)
- ✅ LLM-steered DAST (Anthropic + Ollama)
- ✅ 4-tier classification with risk scoring and policy gates
- ✅ JWT-authenticated REST API with role-based access
- ✅ Dashboard with findings panel, 4-tier cards, evidence chain display
- ✅ Export: CSV (client-side) + PDF (server-side reportlab)
- ✅ GitHub URL clone + auto-scan with config auto-discovery
- ✅ Docker-Compose mode

### Phase 2 — Production-Hardening (next 60 days)

- **Pre-existing container support** — `runtime.url` config key; skip Docker build if set
- **Settings page** — API URL, default tools, theme, LLM config surfaced in UI
- **Overview findings table** — quick wins visible before opening detail panel
- **SBOM export** — CycloneDX JSON from Trivy output
- **Improved transitive detection** — wire `dependency_tree_analyzer.py` fully into classification
- **Build.gradle / package.json manifest support** — extend Trivy agent
- **Fix `tainter` binary resolution** — full `PATH`-based resolution
- **Async DAST loop** — replace `ThreadPoolExecutor` with `asyncio`

### Phase 3 — Enterprise-Ready (3–6 months)

- **Multi-language support** — JavaScript (Node.js) + Java as primary targets
- **Google SSO / OIDC** — Authlib OIDC middleware, role mapping
- **CI/CD native integrations** — GitHub Actions, GitLab CI, Jenkins plugins
- **VS Code extension** — inline findings in editor
- **Multi-repo / org-level dashboard** — aggregate findings across repositories
- **Kubernetes-native scanning** — scan running pods via eBPF, no source code required
- **VEX export** — machine-readable exploitability assertions
- **AI fix suggestions** — patch generation via LLM for confirmed findings

### Phase 4 — SaaS Platform (6–12 months)

- Multi-tenant SaaS with per-org isolation
- Scan scheduling (nightly, PR-triggered)
- Findings trending and regression detection
- Dependabot PR correlation — detect if a fix PR already exists
- CNAPP integration (Wiz, Orca, Prisma) via SARIF/SPDX export
- Self-serve onboarding with usage-based billing

---

## 12. Monetization Strategy

### Who Pays

| Persona | Pain point addressed |
|---------|---------------------|
| Platform security teams (Series B+) | Too many CVEs, not enough signal; need CI gates that don't block every deploy |
| AppSec engineers at mid-market companies | Manual triage of SCA alerts is unsustainable; need runtime-confirmed prioritisation |
| DevSecOps platform teams | Need developer-friendly findings with evidence and fix version, not raw CVE lists |
| AppSec consultancies | Assessment-grade exploit confirmation without manual Burp Suite sessions |

### Pricing Model

| Tier | Target | Price | Limits |
|------|--------|-------|--------|
| **Open Source** | Individual devs, research | Free | Self-hosted, community edition |
| **Team** | Startups, small AppSec teams | $300–500/mo | Up to 10 repos, API access |
| **Business** | Mid-market, CI/CD integration | $1,500–3,000/mo | Unlimited repos, SSO, SBOM export, SLA |
| **Enterprise** | Large orgs, on-prem | Custom ($50K–200K ARR) | Self-hosted, Kubernetes, multi-tenancy, SIEM |

Key pricing lever: **per-repository** (simpler to sell) or **per-developer seat** (higher ACV at enterprise). Per-repository is better for the current stage.

### Market Positioning

VulnReach sits at the intersection of **ASPM** (Application Security Posture Management) and **DAST**, filling a gap between:

- SCA tools (Snyk, Dependabot) — know what's installed, not what's executed
- SAST tools (Semgrep, CodeQL) — know about code patterns, not runtime behaviour
- DAST tools (Burp, ZAP) — find runtime vulnerabilities, don't trace to dependencies

**Target market:** ASPM ($1.5B, 28% CAGR) and the emerging "reachability analysis" category being pioneered by Endor Labs and Socket.dev — but with a stronger evidence chain via runtime confirmation and LLM-assisted exploit verification.

**Positioning statement:**

> *"VulnReach is the only security tool that confirms CVE reachability at runtime — telling you which 3% of your dependency vulnerabilities actually matter, with proof."*

---

*VulnReach v2 · Internal Document · Not for distribution*
