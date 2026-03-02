Love it. You’re thinking correctly — before adding complexity, you want a structured code audit.

Below is a **TPM + Senior Dev level prompt** you can give to an LLM (or even a senior engineer) to review VulnReach’s current codebase and provide:

* Functional understanding
* Architecture breakdown
* Gaps vs intended v2 design
* Technical debt risks
* Refactor recommendations

This is written in a way that forces structured, actionable output.

---

# 📌 Codebase Audit Prompt (TPM + Senior Engineer Style)

You can paste this into Ollama or any LLM.

---

## 🔎 Prompt

You are acting as:

* A Technical Program Manager (TPM)
* A Senior Backend Security Engineer
* An Architecture Reviewer

Your task is to analyze the provided VulnReach codebase and produce a structured technical review.

This project aims to be:

> An agent-based vulnerability reachability and risk prioritization engine.

Currently, Phase 1 includes:

* Trivy integration (SCA)
* Custom static taint engine
* Deterministic correlation logic
* PostgreSQL persistence
* FastAPI API layer

Your review must include the following sections:

---

## 1️⃣ High-Level Understanding

* What does the codebase currently do?
* What is the scan lifecycle?
* What are the core execution flows?
* Which components are tightly coupled?
* Is this pipeline-style or agent-style?

Be explicit.

---

## 2️⃣ Architecture Analysis

Break down:

* API Layer
* Agent Layer
* Correlation Layer
* Storage Layer
* Config Parsing
* Error Handling
* Execution Flow

Answer:

* Is separation of concerns clear?
* Are modules well bounded?
* Any circular dependencies?
* Any leaky abstractions?

---

## 3️⃣ Data Flow Mapping

Describe:

1. How input enters system
2. How tools are invoked
3. How results are normalized
4. How correlation is applied
5. How output is constructed
6. Where data is persisted

Identify weak points.

---

## 4️⃣ Code Quality Assessment

Evaluate:

* Readability
* Modularity
* Testability
* Extensibility
* Logging strategy
* Exception handling
* Configuration safety
* Determinism

Flag:

* Hidden complexity
* Technical debt
* Future scaling risks

---

## 5️⃣ Gap Analysis (vs Intended Architecture)

Target architecture includes:

* Agent-based modular execution
* Deterministic risk scoring
* Coverage-aware scoring (future)
* Policy enforcement
* JSONB storage
* Clean repository pattern
* Scan state machine

Compare current implementation to target.

For each missing capability:

* Severity: High / Medium / Low
* Impact
* Suggested refactor

---

## 6️⃣ Security Review

Assess:

* CLI execution safety
* Path traversal risks
* Injection risks
* Untrusted repo execution risks
* DB connection handling
* Secrets management
* Logging of sensitive data

Highlight dangerous patterns.

---

## 7️⃣ Scalability & Production Readiness

Evaluate:

* Thread safety
* Async correctness
* DB connection pooling
* Blocking operations
* Large JSON handling
* Failure isolation

Would this survive:

* 100 concurrent scans?
* 1M CVE entries?

---

## 8️⃣ Refactoring Recommendations (Prioritized)

Provide:

### Immediate Refactors (must fix before adding features)

### Medium-Term Improvements

### Long-Term Architecture Improvements

Be concrete.

---

## 9️⃣ Risk Assessment Score

Rate:

* Architecture maturity (1–10)
* Production readiness (1–10)
* Security robustness (1–10)
* Maintainability (1–10)

Explain scores.

---

## 🔟 Final Summary

Answer:

If this project were presented to a CISO:

* What would impress them?
* What would concern them?
* What must be fixed before enterprise usage?

---

Important:

* Do not summarize vaguely.
* Provide direct technical reasoning.
* Call out code smells explicitly.
* If patterns are dangerous, say so clearly.
* Assume this system may execute untrusted code.

