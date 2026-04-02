# Configuration Reference

VulnReach scans are configured via a YAML file. A fully annotated example is at [`config/scan.sample.yml`](../config/scan.sample.yml).

Pass the config when starting a scan:

```bash
curl -X POST /scan \
  -d '{"repo_path": "/path/to/app", "config_path": "/path/to/scan.yml"}'
```

When `repo_url` is provided instead of `repo_path`, a config file is optional. VulnReach auto-discovers `vulnreach.yaml`, `vulnreach.yml`, `scan.yml`, or `scan.yaml` inside the cloned repo, or falls back to sensible defaults.

---

## Top-level structure

```yaml
scan:   # what to run and how
risk:   # exposure context for risk scoring
policy: # CI gate rules
```

---

## `scan`

### `scan.static_reachability`

| Type | Default |
|------|---------|
| `bool` | `true` |

Enable AST-based static call-chain analysis. Disable only for pure SCA-mode scans.

---

### `scan.tools`

| Type | Default |
|------|---------|
| `list[str]` | `["trivy", "tainter"]` |

Ordered list of agents to run. Available values:

| Tool | Description | Optional |
|------|-------------|----------|
| `git` | Clone repo from `repo_url` | Auto-injected |
| `trivy` | SCA — finds CVEs in dependencies | Recommended |
| `tainter` | Static taint flow analysis | Yes — see [tainter.md](tainter.md) |
| `python_reachability` | AST call-chain analysis | Yes |
| `java_reachability` | Java reachability analysis (imports + pom/build declarations) | Yes |
| `multi_language_reachability` | Cross-language reachability (Python/Java/JS/Go/C#/PHP; monorepo-aware) | Yes |
| `route_extractor` | HTTP route map extraction | Yes |
| `metadata` | PyPI → import name resolver | Yes |
| `dynamic_reachability` | Docker-based runtime coverage | Yes |
| `pytest_coverage` | Run target app's own test suite | Yes |
| `semgrep` | SAST pattern scanning | Yes |
| `openapi_generator` | LLM-generated OpenAPI spec | Yes |
| `intelligent_dast` | LLM-steered exploit confirmation | Yes |

---

### `scan.runtime`

Controls Docker-based dynamic reachability analysis.

#### `scan.runtime.enabled`

| Type | Default |
|------|---------|
| `bool` | `false` |

Set to `true` to enable dynamic analysis. Requires Docker and a `Dockerfile` or `docker-compose.yml` in the target repo.

#### `scan.runtime.timeout`

| Type | Default | Unit |
|------|---------|------|
| `int` | `60` | seconds |

Total time allowed for container startup + Schemathesis traffic generation + coverage flush.

#### `scan.runtime.coverage_wait`

| Type | Default | Unit |
|------|---------|------|
| `int` | `10` | seconds |

Seconds to wait after traffic completes before flushing `coverage.json` from the container.

#### `scan.runtime.container_port`

| Type | Default |
|------|---------|
| `int` | `3000` |

Port the target application exposes inside its container. Used for health checks and Schemathesis traffic.

#### `scan.runtime.container_workdir`

| Type | Default |
|------|---------|
| `str` | `""` (auto-detect) |

Override the container `WORKDIR` used for coverage path resolution. When empty (the default), VulnReach auto-detects the `WORKDIR` from the final stage of the target's Dockerfile. Set this explicitly when auto-detection fails (e.g. `WORKDIR` is set dynamically via a shell variable) or when using a custom path not in the built-in fallback list.

Example: if your app uses `WORKDIR /workspace`, set:

```yaml
scan:
  runtime:
    container_workdir: "/workspace"
```

---

#### `scan.runtime.ebpf`

Non-invasive kernel-level tracing. **Experimental — Linux only.**
Requires explicit runtime opt-in with `VULNREACH_ALLOW_EBPF=true`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable eBPF tracing |
| `mode` | `str` | `"openat"` | `"openat"` (portable) or `"usdt"` (requires Python+dtrace) |
| `tracer` | `str` | `"bpftrace"` | `"bpftrace"` or `"bcc"` — must be installed on the host |

---

### `scan.openapi_generator`

Auto-generates an OpenAPI 3.0 spec via LLM when no spec exists in the repo. Required for Schemathesis-based dynamic analysis.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable the generator |
| `provider` | `str` | `"none"` | `"none"` \| `"anthropic"` \| `"openai"` \| `"ollama"` |
| `model` | `str` | `"claude-sonnet-4-20250514"` | Model name for the chosen provider |
| `api_key_env` | `str` | `"ANTHROPIC_API_KEY"` | Env var holding the API key |
| `max_tokens` | `int` | `4096` | Max tokens in the generated spec |

`provider: none` (the default) disables LLM calls even when `enabled: true`. VulnReach is fully functional without any LLM provider.

---

### `scan.intelligent_dast`

LLM-steered DAST that generates and validates exploit payloads for confirmed taint flows.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable intelligent DAST |
| `provider` | `str` | `"none"` | `"none"` \| `"anthropic"` \| `"openai"` \| `"ollama"` |
| `model` | `str` | `"claude-sonnet-4-20250514"` | Model name |
| `api_key_env` | `str` | `"ANTHROPIC_API_KEY"` | Env var holding the API key |
| `base_url` | `str` | `""` | Override target URL; empty = auto-detect from `container_port` |
| `ollama_base_url` | `str` | `"http://localhost:11434"` | Ollama server URL |
| `max_iter` | `int` | `5` | Max exploit iterations per taint flow |
| `auth_credentials` | `str` | `""` | `"user:pass"` for target app authentication |

`provider: none` (the default) disables LLM calls even when `enabled: true`.

---

## `risk`

Affects the risk score formula: `severity_base × reachability_multiplier × exposure_modifier`.

### `risk.exposure`

| Type | Default | Options |
|------|---------|---------|
| `str` | `"private"` | `"public"` `"internal"` `"private"` |

- `public` — internet-facing; exposure modifier ×1.3
- `internal` / `private` — internal only; exposure modifier ×1.0

### `risk.data_sensitivity`

| Type | Default | Options |
|------|---------|---------|
| `str` | `"low"` | `"low"` `"medium"` `"high"` |

Informational only in the current release. Will influence risk scoring in a future version.

---

## `policy`

### `policy.block_if`

| Type | Default |
|------|---------|
| `list[{severity, verdict}]` | `[]` |

Rules that cause a scan to return `pipeline_status: BLOCK`. Useful as a CI gate.

```yaml
policy:
  block_if:
    - severity: CRITICAL
      verdict: CONFIRMED
    - severity: HIGH
      verdict: CONFIRMED
```

Valid `severity` values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
Valid `verdict` values: `CONFIRMED`, `LIKELY`, `POSSIBLE`, `NOT_OBSERVED`
