# VulnReach — Executive Summary

> Confidential · March 2026

---

## The Problem

Modern Python services carry hundreds of transitive dependencies. Standard software composition analysis (SCA) tools — Snyk, Dependabot, OWASP Dependency-Check — report every CVE in every installed package. In a typical service, **80–95% of those findings are in code that is never called at runtime.** Security teams spend most of their time triaging noise, and developers learn to ignore vulnerability alerts entirely.

The core failure: existing tools know what is *installed*. None of them know what is *reachable* — let alone what is *exploitable*.

---

## What VulnReach Does

VulnReach is a **runtime-aware application security platform** that tells you exactly which CVEs in your dependencies can be reached from a live HTTP endpoint — and, for confirmed paths, whether they are actively exploitable.

Every finding is ranked across four evidence tiers:

| Tier | What it means |
|---|---|
| **Dynamically Reachable** | Runtime execution confirmed — this code ran during live traffic |
| **Statically Reachable** | AST call graph proves a code path exists to the vulnerable function |
| **Uncertain** | Taint flow exists but runtime confirmation is incomplete |
| **Not Reachable** | No evidence the vulnerable code is ever called |

A five-link evidence chain gates the highest tier: CVE confirmed → user input reaches the sink → HTTP route exposes the endpoint → call path proven by static analysis → runtime coverage confirms execution. Only findings that pass all five gates reach the top tier.

---

## How It Works

1. **Scan** — Trivy surfaces CVEs in installed dependencies
2. **Trace** — Taint analysis tracks user-controlled input to vulnerable sinks (SQL, subprocess, YAML deserialization, pickle, etc.)
3. **Map** — AST analysis builds a call graph from every HTTP route to every vulnerable function
4. **Confirm** — The target app is containerized and exercised; coverage.py or eBPF tracing records which code paths actually execute
5. **Prove** — An LLM-steered DAST loop generates targeted exploit payloads, fires them against the live container, and evaluates responses — producing a `CONFIRMED` or `NOT_CONFIRMED` verdict with the exact payload as evidence

Risk scores are weighted by reachability tier and endpoint exposure, giving teams a prioritized, actionable list instead of a flat CVE dump.

---

## How We Are Different

| Capability | Snyk | Endor Labs | VulnReach |
|---|---|---|---|
| Dependency CVE detection | Yes | Yes | Yes |
| Call-graph reachability | Partial | Yes | Yes |
| Runtime coverage confirmation | No | No | **Yes** |
| Active exploit confirmation (DAST) | No | No | **Yes** |
| LLM-adaptive payload generation | No | No | **Yes** |
| eBPF non-invasive tracing | No | No | **Yes** |
| CI/CD policy gate on confirmed findings | No | Partial | **Yes** |

Endor Labs and Snyk can tell you a code path *might* exist. VulnReach is the only tool that **proves** the path executes at runtime and then attempts to exploit it — delivering a finding with a working payload, a request/response snapshot, and a confidence score.

---

## Who It Is For

- **AppSec and DevSecOps teams** at Python-based product companies who are drowning in SCA noise and need a defensible signal for prioritization
- **Platform security orgs** that need CI/CD gates that block confirmed critical vulnerabilities without halting every deploy
- **Security consultancies** that need assessment-grade exploit confirmation without manual Burp Suite sessions

---

## Current State

VulnReach is at functional MVP. The full pipeline — SCA, taint analysis, static call graph, dynamic coverage, and LLM-steered DAST — is operational against Python/Flask and Python/FastAPI targets. A REST API with JWT auth, a web dashboard, and PDF report export are production-ready. Air-gapped deployment is supported via local LLMs (Ollama).

The immediate roadmap targets Node.js and Java language support, cloud-native SBOM ingestion, and a SaaS offering alongside the self-hosted open-source distribution.
