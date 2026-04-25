# VulnReach Roadmap

This document tracks planned improvements, known limitations, and the current state of multi-language support.

## Language Support

| Language   | Status          | Analysis depth |
|------------|-----------------|----------------|
| Python     | Production-ready | Taint-flow, AST call graph, route exposure, runtime coverage |
| Java       | Functional (experimental) | Call graph (Maven/Gradle parsing, method scope tracking), import detection; no taint-flow |
| JavaScript | Functional (experimental) | Call graph (route entry points, BFS path tracing), import + `package.json` detection; no taint-flow |
| Go         | Roadmap         | Planned |
| C#         | Roadmap         | Planned |
| PHP        | Roadmap         | Planned |

> Taint-flow analysis (user-input-to-sink tracing) is currently Python-only via the `tainter` tool. Java and JavaScript findings reflect call graph reachability, not confirmed taint propagation.

---

## Near-term (next 1–2 releases)

- **Taint-flow for Java** — extend tainter or add a standalone Java taint analyzer; current call graph is solid, gap is source-to-sink tracing
- **Taint-flow for JavaScript** — same gap; call graph and route detection are in place
- **SBOM ingestion** — accept CycloneDX / SPDX SBOMs as scan input alongside live repos; currently only Trivy output is supported

## Medium-term

- **Java class hierarchy resolution** — add inheritance and polymorphism tracking to Java call graph (currently exact method name matching only)
- **Go, C#, PHP reachability** — extend multi-language framework to remaining languages
- **Coverage flush configurability** — `runtime.coverage_flush_retries` and `runtime.coverage_flush_retry_wait` are implemented internally; expose as config schema keys

## Longer-term

- **SaaS offering** — hosted version alongside the open-source self-hosted option
- **IDE integrations** — VS Code / IntelliJ plugin for inline CVE reachability hints
- **SARIF export** — output compatible with GitHub Code Scanning and other SARIF consumers

---

## Known Limitations

These are understood limitations that don't block current use cases but are worth knowing:

- Dynamic scans require explicit Docker daemon opt-in (`VULNREACH_ALLOW_DOCKER_DAEMON=true`) via a restricted `docker-socket-proxy`
- Java and JavaScript call graph analysis is functional but does not include taint-flow — findings are based on call path reachability, not confirmed source-to-sink propagation
- PyPI → import name mapping covers ~50 packages; runtime fallback via `importlib.metadata` handles the rest
- eBPF tracing mode is Linux-only and explicitly marked experimental

---

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.
