Good. Python + LCOV/coverage.json output gives a clear baseline to validate against.

Here's the concrete e2e verification plan:

---

## The Core Idea

Run the same Python app twice — once with standard `coverage.py` (ground truth), once with your eBPF agent. Compare the two outputs. If eBPF coverage ≈ coverage.py coverage, the agent is working.

---

## Step 1 — Pick the Right eBPF Approach for Python

For Python, your realistic options are:

**uprobes on `PyEval_EvalFrameEx`** — fires on every frame evaluation. You can extract filename + line number from the PyFrameObject. Most common approach but requires reading CPython internals from the probe.

**USDT tracepoints** — CPython has built-in DTrace/USDT probes (`python:line`, `python:function__entry`). Cleanest option if your target Python is compiled with `--with-dtrace` (most distro Pythons are). The `python:line` probe fires on every line executed — directly maps to LCOV line coverage.

**Recommendation: start with USDT `python:line`** — it gives you file + line number directly, no PyFrameObject parsing needed, and maps cleanly to LCOV format.

---

## Step 2 — The Target App

You need a small Python app with known, predictable coverage. Something like:

```python
# app.py
from flask import Flask, request, jsonify

app = Flask(__name__)

def add(a, b):
    return a + b          # line 6 — should be hit

def unused():
    return "never called" # line 9 — should NOT be hit

@app.route("/add")
def handle_add():
    a = int(request.args.get("a", 0))
    b = int(request.args.get("b", 0))
    result = add(a, b)
    return jsonify(result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

The point: you know exactly which lines should be hit when you call `/add`, and which shouldn't. This makes the eBPF output verifiable by inspection, not just by diffing.

---

## Step 3 — Ground Truth First

Before touching eBPF, get a clean coverage.py baseline:

```bash
pip install coverage flask
coverage run app.py &
sleep 1
curl "http://localhost:5000/add?a=2&b=3"
coverage stop
coverage json -o ground_truth.json
```

Pin this output. Your eBPF agent must produce something that agrees with it on covered lines.

---

## Step 4 — Docker Compose Setup

```yaml
# docker-compose.yml
services:
  target:
    build: ./target        # Python app
    privileged: true       # required for eBPF/USDT from inside container
    cap_add:
      - SYS_ADMIN
      - SYS_PTRACE
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug:ro
      - ./coverage-out:/coverage

  agent:
    build: ./agent         # your eBPF coverage agent
    privileged: true
    pid: "service:target"  # share PID namespace — critical for uprobes/USDT
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug:ro
      - ./coverage-out:/coverage
    depends_on:
      - target
```

The `pid: "service:target"` line is the key detail — your agent needs to be in the same PID namespace to attach probes to the Python process.

---

## Step 5 — Verification Script

```bash
#!/bin/bash
# verify_ebpf_coverage.sh

set -e

echo "=== Starting stack ==="
docker compose up -d

echo "=== Waiting for app ==="
sleep 3

echo "=== Sending test traffic ==="
curl -sf "http://localhost:5000/add?a=2&b=3"

echo "=== Stopping stack and collecting output ==="
docker compose down

echo "=== Comparing outputs ==="
python3 compare_coverage.py ground_truth.json coverage-out/ebpf_coverage.json
```

```python
# compare_coverage.py
import json, sys

ground = json.load(open(sys.argv[1]))
ebpf   = json.load(open(sys.argv[2]))

# Extract covered lines per file from both
# Adjust key paths to match your agent's actual output schema

ground_lines = set(
    (f, ln)
    for f, data in ground["files"].items()
    for ln in data["executed_lines"]
)

ebpf_lines = set(
    (f, ln)
    for f, data in ebpf["files"].items()
    for ln in data["executed_lines"]
)

missed = ground_lines - ebpf_lines
extra  = ebpf_lines - ground_lines

print(f"Ground truth lines:  {len(ground_lines)}")
print(f"eBPF covered lines:  {len(ebpf_lines)}")
print(f"Missed by eBPF:      {len(missed)}")
print(f"Extra in eBPF:       {len(extra)}")

if missed:
    print("\nMISSED LINES (in ground truth but not eBPF):")
    for f, ln in sorted(missed):
        print(f"  {f}:{ln}")

if len(missed) > 0:
    sys.exit(1)

print("\n✓ eBPF coverage matches ground truth")
```

---

## What "Passing" Means

| Check | Pass condition |
|---|---|
| Agent attaches | No error on startup, probe visible in `/sys/kernel/debug/tracing/uprobe_events` |
| Events captured | `coverage-out/ebpf_coverage.json` exists and is non-empty after traffic |
| Line accuracy | Zero lines in ground truth missing from eBPF output |
| No false positives | `unused()` at line 9 does NOT appear as covered |
| CI repeatability | Same result across 3 consecutive runs |

---

The biggest unknown right now is whether your target Python binary has USDT probes compiled in. Worth checking first: `readelf -n $(which python3) | grep -i stap` — if you see stap notes, you're good to use USDT. If not, you'll fall back to uprobes on `PyEval_EvalFrameEx`, which needs a bit more probe logic. Let me know what you see and we can go deeper on the agent-side implementation.