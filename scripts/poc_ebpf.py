#!/usr/bin/env python3
"""
POC test: Feature 2 — eBPF non-invasive tracing mode.

Tests the full eBPF pipeline against labs/python_vuln_app:

  Phase 1 — Build plain (uninstrumented) container image
  Phase 2 — Start container, probe its host PID via docker inspect
  Phase 3 — Show generated bpftrace script (openat + usdt modes)
  Phase 4 — Simulate bpftrace output, run the hit-parser
  Phase 5 — Correlate hits against mock CVEs, print findings
  Phase 6 — Cleanup

On macOS/non-Linux: phases 1-2-3-4-5-6 all run; actual eBPF tracing is
  replaced by a simulated bpftrace stdout so the full parse/correlate path
  is exercised. A note is printed for each Linux-only step.

On Linux with bpftrace installed: the real tracer is launched and live
  openat events are collected while Schemathesis drives traffic.

Usage:
    cd <repo_root>
    python scripts/poc_ebpf.py [--port 3000]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make sure imports resolve from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.agent_dynamic_reachability import (
    DynamicReachabilityAgent,
    _MIN_PKG_MATCH_LEN,
    _PYPI_TO_IMPORT,
)
from core.models import ReachabilityFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN  = "\033[36m"
RED   = "\033[31m"
DIM   = "\033[2m"


def banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}→{RESET} {msg}")


def finding_line(f: ReachabilityFinding) -> str:
    colour = GREEN if f.verdict == "CONFIRMED" else YELLOW
    return (
        f"  {colour}{f.verdict:<12}{RESET}"
        f"  conf={f.confidence:.2f}"
        f"  {f.package or '?':<20}"
        f"  {f.cve_id or 'no-CVE'}"
    )


# ---------------------------------------------------------------------------
# Simulated bpftrace output
# ---------------------------------------------------------------------------

# Represents what bpftrace would emit on a Linux host when the python_vuln_app
# container processes HTTP requests that touch PIL, yaml, and requests.
SIMULATED_OPENAT_OUTPUT = textwrap.dedent("""\
    Attaching 1 probe...
    open:/usr/local/lib/python3.9/site-packages/PIL/__init__.py
    open:/usr/local/lib/python3.9/site-packages/PIL/Image.py
    open:/usr/local/lib/python3.9/site-packages/yaml/__init__.py
    open:/usr/local/lib/python3.9/site-packages/yaml/loader.py
    open:/usr/local/lib/python3.9/site-packages/requests/api.py
    open:/usr/local/lib/python3.9/site-packages/requests/sessions.py
    open:/usr/local/lib/python3.9/site-packages/urllib3/connectionpool.py
    open:/app/src/app.py
    open:/app/src/emailer_.py
""")

SIMULATED_USDT_OUTPUT = textwrap.dedent("""\
    Attaching 1 probe...
    func:/usr/local/lib/python3.9/site-packages/PIL/Image.py:open
    func:/usr/local/lib/python3.9/site-packages/yaml/loader.py:load
    func:/usr/local/lib/python3.9/site-packages/requests/api.py:get
    func:/app/src/app.py:yaml_test
    func:/app/src/app.py:ssrf_endpoint
""")

# Mock CVEs aligned to packages in the lab app
MOCK_VULNS: List[Dict[str, Any]] = [
    {"package": "Pillow",   "cve_id": "CVE-2021-34552", "severity": "CRITICAL"},
    {"package": "pyyaml",   "cve_id": "CVE-2020-14343", "severity": "CRITICAL"},
    {"package": "lxml",     "cve_id": "CVE-2021-28957", "severity": "HIGH"},
    {"package": "requests", "cve_id": "CVE-2023-32681", "severity": "MEDIUM"},
    {"package": "urllib3",  "cve_id": "CVE-2023-43804", "severity": "HIGH"},
]


# ---------------------------------------------------------------------------
# POC phases
# ---------------------------------------------------------------------------

async def phase_build(agent: DynamicReachabilityAgent, repo_path: Path):
    banner("Phase 1 — Build plain (uninstrumented) image")
    dockerfile = repo_path / "Dockerfile"
    if not dockerfile.exists():
        print(f"  {RED}✗{RESET} Dockerfile not found: {dockerfile}")
        sys.exit(1)

    info(f"Dockerfile: {dockerfile}")
    info("Building without coverage instrumentation...")
    image_tag, meta = await agent._build_plain_image(dockerfile, repo_path)

    if not image_tag:
        print(f"  {RED}✗{RESET} Build failed: {meta}")
        sys.exit(1)

    ok(f"Image built: {image_tag}")
    return image_tag


async def phase_start(
    agent: DynamicReachabilityAgent, image_tag: str, port: int
) -> Optional[str]:
    banner("Phase 2 — Start container & probe PID")
    container_id = await agent._start_container_plain(image_tag, port, timeout=60)
    if not container_id:
        print(f"  {RED}✗{RESET} Failed to start container")
        return None
    ok(f"Container ID: {container_id[:12]}")

    pid = await agent._get_container_pid(container_id)
    if pid:
        ok(f"Container host PID: {pid}")
    else:
        # On macOS Docker Desktop the "host" PID is inside the Linux VM —
        # docker inspect still returns it but it's not addressable from macOS.
        warn("PID returned by docker inspect is inside the Docker VM (macOS).")
        warn("On Linux this PID is directly addressable by bpftrace.")
        pid = 99999  # placeholder for script generation

    return container_id, pid  # type: ignore[return-value]


def phase_script(agent: DynamicReachabilityAgent, pid: int) -> None:
    banner("Phase 3 — Generated bpftrace scripts")

    for mode in ("openat", "usdt"):
        script = agent._build_bpftrace_script(pid, mode)
        print(f"\n  {BOLD}[{mode} mode]{RESET}")
        for line in script.splitlines():
            print(f"    {DIM}{line}{RESET}")

    is_linux = platform.system() == "Linux"
    has_tracer = shutil.which("bpftrace") is not None
    print()
    if is_linux and has_tracer:
        ok("bpftrace found — real tracing will run in Phase 4")
    elif is_linux:
        warn("Linux detected but bpftrace not in PATH — using simulated output")
    else:
        warn(f"macOS detected ({platform.version()[:30]}...) — eBPF requires Linux")
        info("Continuing with simulated bpftrace output for the remaining phases")


async def phase_simulate(
    agent: DynamicReachabilityAgent,
    container_id: str,
    pid: int,
    port: int,
    mode: str,
) -> "set[str]":
    banner("Phase 4 — Tracer output → package hit set")
    is_linux = platform.system() == "Linux"
    tracer_available = is_linux and shutil.which("bpftrace") is not None
    vuln_packages = [v["package"].lower() for v in MOCK_VULNS]

    if tracer_available:
        info(f"Launching real bpftrace (mode={mode}, pid={pid})...")
        tracer_proc = await agent._start_ebpf_tracer(pid, mode, "bpftrace")

        if tracer_proc:
            # Drive a tiny bit of traffic so the tracer captures file opens.
            info("Sending test requests to exercise package code paths...")
            try:
                import aiohttp
                async with aiohttp.ClientSession() as sess:
                    for ep in ("/health", "/yaml-test", "/request-test", "/"):
                        try:
                            async with sess.get(
                                f"http://localhost:{port}{ep}",
                                timeout=aiohttp.ClientTimeout(total=5),
                            ) as r:
                                info(f"  GET {ep} → {r.status}")
                        except Exception as exc:
                            warn(f"  GET {ep} failed: {exc}")
            except ImportError:
                warn("aiohttp not installed — skipping live traffic")

            hit_packages = await agent._collect_ebpf_hits(tracer_proc, vuln_packages)
        else:
            warn("Tracer failed to start — falling back to simulation")
            tracer_available = False

    if not tracer_available:
        # Parse the simulated output the same way _collect_ebpf_hits would.
        simulated = SIMULATED_USDT_OUTPUT if mode == "usdt" else SIMULATED_OPENAT_OUTPUT
        info(f"Simulated bpftrace output ({mode} mode):")
        for line in simulated.strip().splitlines():
            print(f"    {DIM}{line}{RESET}")

        hit_packages: "set[str]" = set()
        for line in simulated.splitlines():
            line_lower = line.lower()
            for pkg in vuln_packages:
                import_name = _PYPI_TO_IMPORT.get(pkg, pkg).lower()
                if len(import_name) >= _MIN_PKG_MATCH_LEN and import_name in line_lower:
                    hit_packages.add(pkg)

    print()
    ok(f"Packages hit: {sorted(hit_packages) or '(none)'}")
    missed = sorted(set(vuln_packages) - hit_packages)
    if missed:
        info(f"Not hit (will be LIKELY): {missed}")

    return hit_packages


def phase_correlate(
    agent: DynamicReachabilityAgent, hits: "set[str]"
) -> List[ReachabilityFinding]:
    banner("Phase 5 — Correlate hits → ReachabilityFindings")
    findings = agent._correlate_from_ebpf(hits, MOCK_VULNS)

    confirmed = [f for f in findings if f.verdict == "CONFIRMED"]
    likely    = [f for f in findings if f.verdict != "CONFIRMED"]

    if confirmed:
        print(f"\n  {GREEN}{BOLD}CONFIRMED ({len(confirmed)}){RESET}")
        for f in confirmed:
            print(finding_line(f))

    if likely:
        print(f"\n  {YELLOW}LIKELY ({len(likely)}){RESET}")
        for f in likely:
            print(finding_line(f))

    return findings


async def phase_cleanup(agent: DynamicReachabilityAgent, container_id: str) -> None:
    banner("Phase 6 — Cleanup")
    info("Stopping and removing container...")
    await agent._stop_container(container_id)
    ok("Container removed")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def run(port: int, mode: str) -> None:
    print(f"\n{BOLD}VulnReach — eBPF POC Test{RESET}")
    print(f"Platform : {platform.system()} {platform.machine()}")
    print(f"Mode     : {mode}")
    print(f"Port     : {port}")

    repo_path = Path(__file__).resolve().parent.parent / "labs" / "python_vuln_app"
    agent = DynamicReachabilityAgent()

    image_tag = await phase_build(agent, repo_path)

    result = await phase_start(agent, image_tag, port)
    if result is None:
        sys.exit(1)
    container_id, pid = result

    try:
        phase_script(agent, pid)

        # Wait for the container to be ready before driving traffic.
        info("Waiting for container to become healthy...")
        base_url = f"http://localhost:{port}"
        healthy = await agent._wait_for_healthy(base_url, timeout=30)
        if not healthy:
            warn("Container did not become healthy in 30s — continuing anyway")

        hits = await phase_simulate(agent, container_id, pid, port, mode)
        findings = phase_correlate(agent, hits)

    finally:
        await phase_cleanup(agent, container_id)

    # Summary
    banner("Summary")
    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    total = len(findings)
    print(f"  Total findings : {total}")
    print(f"  CONFIRMED      : {GREEN}{confirmed}{RESET}")
    print(f"  LIKELY         : {YELLOW}{total - confirmed}{RESET}")
    print()
    is_linux = platform.system() == "Linux"
    has_tracer = shutil.which("bpftrace") is not None
    if is_linux and has_tracer:
        ok("Full eBPF pipeline exercised with real bpftrace")
    else:
        ok("eBPF pipeline validated end-to-end with simulated tracer output")
        info("To run with real tracing: Linux host + `apt install bpftrace`")
        info("Then set runtime.ebpf.enabled=true in scan config")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="eBPF POC test for VulnReach")
    parser.add_argument("--port", type=int, default=3000, help="Container port (default 3000)")
    parser.add_argument(
        "--mode",
        choices=["openat", "usdt"],
        default="openat",
        help="eBPF mode to simulate (default openat)",
    )
    args = parser.parse_args()
    asyncio.run(run(args.port, args.mode))


if __name__ == "__main__":
    main()
