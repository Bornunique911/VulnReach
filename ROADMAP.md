# VulnReach Roadmap

This document tracks planned improvements, known limitations, and the current state of multi-language support.

## Language Support

| Language   | Status          | Analysis depth |
|------------|-----------------|----------------|
| Python     | Production-ready | Taint-flow, AST call graph, route exposure, runtime coverage (coverage.py + eBPF USDT) |
| Java       | Functional      | Call graph (Maven/Gradle parsing, method scope tracking), import detection, **eBPF runtime coverage** (`hotspot:method__entry` USDT); no taint-flow |
| JavaScript | Functional (experimental) | Call graph (route entry points, BFS path tracing), import + `package.json` detection; no taint-flow |
| Go         | Roadmap         | Planned |
| C#         | Roadmap         | Planned |
| PHP        | Roadmap         | Planned |

> Taint-flow analysis (user-input-to-sink tracing) is currently Python-only via the `tainter` tool. Java findings now support **dynamic confirmation** via eBPF `hotspot:method__entry` USDT probes — a Java CVE can reach `DYNAMICALLY_REACHABLE` when the vulnerable method is observed at runtime. JavaScript findings reflect call graph reachability only.

---

## API Surface

| Endpoint family | Status | Notes |
|---|---|---|
| `POST /scan`, `GET /scan/{id}`, `POST /scan/{id}/cancel`, `DELETE /scan/{id}` | Production-ready | Scan lifecycle |
| `GET /scan/{id}/raw[/{tool}]`, `GET /scans` | Production-ready | Inspection |
| `GET /scan/{id}/export/pdf` | Production-ready | PDF report |
| `GET /scan/{id}/graph/{cve_id}` | Production-ready | Mermaid call-chain graph |
| `POST /scan/{id}/explain/{cve_id}` | Production-ready | Human-readable summary (LLM-optional, offline default) |
| `POST /findings/{id}/next-steps` | **Production-ready (new)** | Analyst augmentation: deterministic verdict + LLM-generated next steps. Lazy / on-demand; LLM failures degrade gracefully. See [docs/api.md](docs/api.md#post-findingsfinding_idnext-steps). |
| `POST /login`, `/api-keys/*` | Production-ready | Auth |

The "API interface" milestone originally slated for proposal-Phase 3 is complete and operating. Subsequent AI-augmentation siblings (`/explain`, `/validate`, `/remediate`) reuse the same `EvidenceGraphBuilder` + `NextStepsReasoner` plumbing.

---

## Near-term (next 1–2 releases)

- **Taint-flow for Java** — extend tainter or add a standalone Java taint analyzer; current call graph + eBPF runtime coverage is solid, gap is source-to-sink tracing
- **Taint-flow for JavaScript** — same gap; call graph and route detection are in place
- **SBOM ingestion** — accept CycloneDX / SPDX SBOMs as scan input alongside live repos; currently only Trivy output is supported
- **Workspace isolation** — restructure `GitAgent` so clones land in `{workdir}/clone/` and VulnReach-generated files (patched compose, coverage) live in `{workdir}/` alongside; eliminates the DooD path-resolution constraint for local path scans
- **`POST /findings/{id}/explain`** — narrative-style finding explanation (deeper than `/scan/{id}/explain/{cve_id}`'s offline summary), built on the same `EvidenceGraph` contract used by `/next-steps`
- **`POST /findings/{id}/validate`** — synthesise a runtime probe (HTTP request, payload skeleton, expected signal) the user can fire against a target to confirm reachability for a non-confirmed finding
- **`POST /findings/{id}/remediate`** — focused upgrade-and-patch plan; isolates upgrade logic from the broader next-steps surface so it can be wired into CI / PR automation

## Medium-term

- **Java class hierarchy resolution** — add inheritance and polymorphism tracking to Java call graph (currently exact method name matching only)
- **JavaScript eBPF coverage** — wire Node.js USDT probes (`node:method__entry` or V8 coverage) through the existing `java_method`-style parser path; static call graph already in place
- **Go, C#, PHP reachability** — extend multi-language framework to remaining languages
- **Coverage flush configurability** — `runtime.coverage_flush_retries` and `runtime.coverage_flush_retry_wait` are implemented internally; expose as config schema keys
- **EvidenceGraph schema stabilisation** — promote `EVIDENCE_GRAPH_VERSION` to a published contract once the AI sibling endpoints have shaken out the field set
- **AI evaluation harness** — pinned-fixture eval set + scoring for `/next-steps` (and siblings) output quality, before this layer moves from lazy/on-demand to eager-per-scan
- **Persistent next-steps cache** — current LRU is in-memory and bounded to 512 entries; promote to disk-backed storage once cache hit rate + cost profile justify it

## Longer-term

- **SaaS offering** — hosted version alongside the open-source self-hosted option
- **IDE integrations** — VS Code / IntelliJ plugin for inline CVE reachability hints
- **SARIF export** — output compatible with GitHub Code Scanning and other SARIF consumers

---

## Known Limitations

These are understood limitations that don't block current use cases but are worth knowing:

- Dynamic scans require explicit Docker daemon opt-in (`VULNREACH_ALLOW_DOCKER_DAEMON=true`) via a restricted `docker-socket-proxy`
- Java call graph is functional and eBPF runtime confirmation works on Linux; taint-flow (source-to-sink) is not yet supported for Java
- JavaScript call graph analysis is functional but does not include taint-flow or eBPF runtime coverage
- PyPI → import name mapping covers ~50 packages; runtime fallback via `importlib.metadata` handles the rest
- eBPF tracing requires Linux kernel ≥ 4.9 and `bpftrace` or BCC; Java USDT probes additionally require JVM flag `-XX:+ExtendedDTraceProbes`
- Local path scans with DooD require the target directory to be under `VULNREACH_WORK_DIR` (default `/tmp/vulnreach`) so paths are identical on host and inside the VulnReach container; use `repo_url` for GitHub repos to avoid this constraint

---

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.
