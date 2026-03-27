#!/usr/bin/env python3
"""eBPF line-coverage collector and verifier.

Orchestrates the full verification pipeline in a single container run:

  Phase 1 — Ground truth
    Run app.py under coverage.py locally (port 5001), drive test traffic,
    save /coverage/ground_truth.json.

  Phase 2 — Wait for target health
    Poll http://TARGET_HOST:TARGET_PORT/health until the target container
    is ready.

  Phase 3 — Attach bpftrace python:line probe
    Discover the target Python process PID via pgrep (works because this
    container runs with pid: "service:target"), write a bpftrace script,
    and start bpftrace as a background subprocess.

  Phase 4 — Drive traffic through the target
    Send GET /health and GET /add?a=2&b=3 to the target container three
    times each so the python:line probe captures the relevant lines.

  Phase 5 — Collect and format coverage
    Terminate bpftrace, parse output lines of the form "line:/path:NN"
    into the coverage.py JSON schema, save /coverage/ebpf_coverage.json.

  Phase 6 — Compare
    Run compare_coverage.py; propagate its exit code.

Pass conditions (from TASK.md):
  • /coverage/ebpf_coverage.json exists and is non-empty
  • compare_coverage.py reports 0 missed lines and 0 false positives
  • unused() lines (see compare_coverage.py) are absent from eBPF output
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

TARGET_HOST = os.environ.get("TARGET_HOST", "target")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "5000"))
TARGET_URL  = f"http://{TARGET_HOST}:{TARGET_PORT}"

COVERAGE_DIR    = Path(os.environ.get("COVERAGE_DIR", "/coverage"))
GROUND_TRUTH    = COVERAGE_DIR / "ground_truth.json"
EBPF_COVERAGE   = COVERAGE_DIR / "ebpf_coverage.json"
BPFTRACE_SCRIPT = Path("/tmp/line_probe.bt")

SCRIPT_DIR = Path(__file__).resolve().parent


# ── Phase 1: Ground truth via coverage.py ────────────────────────────────────

def generate_ground_truth() -> None:
    """Run app.py under coverage.py locally on port 5001 and save JSON."""
    print("=== Phase 1: Generating ground truth with coverage.py ===")

    app_path = SCRIPT_DIR / "app.py"
    if not app_path.exists():
        sys.exit(f"FATAL: {app_path} not found in agent container")

    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)

    # Start the Flask app under coverage on a different port (5001) so it
    # doesn't conflict with the target container on 5000.
    env = {**os.environ, "PORT": "5001", "FLASK_ENV": "development"}
    server = subprocess.Popen(
        [sys.executable, "-m", "coverage", "run", "--source=.", str(app_path)],
        cwd=str(SCRIPT_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for the local server to be ready
    for _ in range(30):
        try:
            urllib.request.urlopen("http://localhost:5001/health", timeout=2)
            break
        except Exception:
            time.sleep(0.3)
    else:
        server.terminate()
        sys.exit("FATAL: Local Flask server (ground truth) did not start")

    # Drive the same traffic that will be sent to the eBPF target
    for _ in range(3):
        for path in ["/health", "/add?a=2&b=3"]:
            try:
                urllib.request.urlopen(f"http://localhost:5001{path}", timeout=3)
            except Exception:
                pass

    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()

    # Export coverage data as JSON
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "-o", str(GROUND_TRUTH)],
        cwd=str(SCRIPT_DIR),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(f"FATAL: coverage json failed:\n{result.stderr}")

    data = json.loads(GROUND_TRUTH.read_text())
    total_lines = sum(
        len(f["executed_lines"]) for f in data.get("files", {}).values()
    )
    print(f"  Ground truth saved to {GROUND_TRUTH} ({total_lines} executed lines)")


# ── Phase 2: Wait for target health ──────────────────────────────────────────

def wait_for_target(retries: int = 40, delay: float = 1.5) -> None:
    """Poll TARGET_URL/health until the target app is ready."""
    print(f"=== Phase 2: Waiting for target at {TARGET_URL}/health ===")
    for attempt in range(retries):
        try:
            urllib.request.urlopen(f"{TARGET_URL}/health", timeout=3)
            print(f"  Target healthy after {attempt + 1} attempt(s)")
            return
        except Exception:
            time.sleep(delay)
    sys.exit(f"FATAL: Target did not become healthy after {retries * delay:.0f}s")


# ── Phase 3: Discover PID and start bpftrace ─────────────────────────────────

def find_target_pid(retries: int = 20, delay: float = 0.5) -> int:
    """Find the Python PID via pgrep in the shared PID namespace."""
    print("=== Phase 3: Discovering target Python PID ===")
    for attempt in range(retries):
        result = subprocess.run(
            ["pgrep", "-f", "python3 app.py"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            pids = result.stdout.strip().splitlines()
            if pids:
                pid = int(pids[0])
                print(f"  Found PID {pid} (attempt {attempt + 1})")
                return pid
        time.sleep(delay)

    # Diagnostics on failure
    ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    print("  ps aux output:")
    for line in ps.stdout.splitlines()[:20]:
        print(f"    {line}")
    sys.exit(
        "FATAL: Could not find 'python3 app.py' in PID namespace.\n"
        "Is 'pid: service:target' set in docker-compose.ebpf-verify.yml?"
    )


def write_bpftrace_script(pid: int) -> None:
    """Write the python:line bpftrace probe to /tmp/line_probe.bt."""
    # arg0 = filename (char*), arg1 = funcname (char*), arg2 = lineno (int)
    # (int64) cast is required: without it some bpftrace versions print hex.
    script = (
        f"usdt:/proc/{pid}/exe:python:line\n"
        "{{\n"
        '  printf("line:%s:%d\\n", str(arg0), (int64)arg2);\n'
        "}}\n"
    )
    BPFTRACE_SCRIPT.write_text(script, encoding="utf-8")
    print(f"  bpftrace script written to {BPFTRACE_SCRIPT}")


def start_bpftrace() -> subprocess.Popen:
    """Launch bpftrace and return the subprocess handle."""
    proc = subprocess.Popen(
        ["bpftrace", str(BPFTRACE_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Give bpftrace a moment to attach the probe before sending traffic
    time.sleep(1.5)
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode("utf-8", errors="replace")
        sys.exit(f"FATAL: bpftrace exited immediately:\n{stderr}")
    print(f"  bpftrace started (pid={proc.pid})")
    return proc


# ── Phase 4: Drive traffic ────────────────────────────────────────────────────

def drive_traffic(repeat: int = 3) -> None:
    """Send test requests to the target container."""
    print(f"=== Phase 4: Driving traffic ({repeat}× per endpoint) ===")
    for i in range(repeat):
        for path in ["/health", "/add?a=2&b=3"]:
            url = f"{TARGET_URL}{path}"
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    print(f"  GET {path} → {resp.status}")
            except Exception as exc:
                print(f"  GET {path} → ERROR: {exc}")
    # Extra pause so bpftrace captures all events before we terminate it
    time.sleep(0.5)


# ── Phase 5: Collect and format output ───────────────────────────────────────

def collect_bpftrace_output(proc: subprocess.Popen) -> str:
    """Terminate bpftrace and return its stdout."""
    print("=== Phase 5: Collecting bpftrace output ===")
    proc.terminate()
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    raw = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")

    line_count = sum(1 for l in raw.splitlines() if l.startswith("line:"))
    print(f"  bpftrace emitted {line_count} line: events")
    if err.strip():
        # Print stderr for diagnostics but don't fail — bpftrace sometimes
        # emits warnings (e.g. "WARNING: could not open debugfs") that are
        # harmless in BTF-capable kernels.
        for line in err.strip().splitlines()[:10]:
            print(f"  [bpftrace stderr] {line}")

    return raw


def parse_bpftrace_output(raw: str) -> dict:
    """Parse 'line:filepath:lineno' lines into coverage.py JSON schema."""
    hits: dict[str, set[int]] = defaultdict(set)
    pattern = re.compile(r"^line:(.+):(\d+)$")
    for raw_line in raw.splitlines():
        m = pattern.match(raw_line.strip())
        if m:
            filepath, lineno = m.group(1), int(m.group(2))
            hits[filepath].add(lineno)

    return {
        "files": {
            fp: {"executed_lines": sorted(lines), "functions": {}}
            for fp, lines in hits.items()
        }
    }


def write_ebpf_coverage(data: dict) -> None:
    """Write the eBPF coverage JSON to the shared volume."""
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    EBPF_COVERAGE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    total = sum(len(f["executed_lines"]) for f in data["files"].values())
    print(f"  eBPF coverage saved to {EBPF_COVERAGE} ({total} executed lines)")
    if total == 0:
        print(
            "  WARNING: No line events captured.\n"
            "  Possible causes:\n"
            "    • python3 in target has no USDT probes (check readelf assertion)\n"
            "    • bpftrace probe did not attach (check stderr above)\n"
            "    • kernel < 4.9 or BTF unavailable"
        )


# ── Phase 6: Compare ──────────────────────────────────────────────────────────

def run_comparison() -> int:
    """Run compare_coverage.py and return its exit code."""
    print("=== Phase 6: Comparing ground truth vs eBPF coverage ===")
    compare_script = SCRIPT_DIR / "compare_coverage.py"
    result = subprocess.run(
        [sys.executable, str(compare_script), str(GROUND_TRUTH), str(EBPF_COVERAGE)],
        text=True,
    )
    return result.returncode


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    generate_ground_truth()
    wait_for_target()

    pid = find_target_pid()
    write_bpftrace_script(pid)
    tracer = start_bpftrace()

    drive_traffic()

    raw_output = collect_bpftrace_output(tracer)
    coverage_data = parse_bpftrace_output(raw_output)
    write_ebpf_coverage(coverage_data)

    exit_code = run_comparison()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
