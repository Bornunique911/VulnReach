"""eBPF probe router.

Given a detected runtime and a target PID, selects the best available
eBPF mechanism (USDT, uprobe, openat tracepoint) and returns a fully
rendered bpftrace script plus metadata the normaliser needs.

Degradation chain per runtime
------------------------------
python  → usdt:python:line  →  usdt:python:function__entry  →  uprobe PyEval_EvalFrameEx  →  skip
java    → usdt:hotspot:method__entry  →  skip (uprobe too complex for general use)
node    → openat (V8 USDT not widely available; uprobe deferred)
go      → openat  (DWARF uprobe deferred to future implementation)
ruby    → usdt:ruby:method__entry  →  skip
generic → openat  (always succeeds)

Public API
----------
select_probe(runtime, pid) → ProbeConfig
resolve_pid_binary(pid)    → str   (absolute path of /proc/{pid}/exe)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Literal

from agents.ebpf.runtime_detector import has_usdt_probe

logger = logging.getLogger(__name__)

Mechanism = Literal[
    "usdt_line",    # python:line — per-line USDT
    "usdt_func",    # python:function__entry or ruby:method__entry — per-function USDT
    "usdt_method",  # hotspot:method__entry — per-method USDT (Java)
    "uprobe_sym",   # uprobe on a named symbol
    "openat",       # tracepoint:syscalls:sys_enter_openat — file-open only
]

OutputParser = Literal[
    "python_line",
    "python_func",
    "java_method",
    "go_uprobe",
    "ruby_method",
    "openat",
]


@dataclass
class ProbeConfig:
    """Everything the sidecar needs to run bpftrace and parse its output."""

    runtime: str
    mechanism: Mechanism
    bpftrace_script: str   # complete script; PID already substituted
    output_parser: OutputParser
    degraded: bool         # True = fell back from preferred probe
    skip: bool = False     # True = no viable probe; caller should emit warning + skip
    skip_reason: str = ""  # machine-readable reason when skip=True
    notes: list[str] = field(default_factory=list)  # human-readable diagnostics


# ── Script templates ──────────────────────────────────────────────────────────

def _python_line_script(pid: int) -> str:
    # arg0 = filename (char*), arg1 = funcname (char*), arg2 = lineno (int)
    # (int64) cast required: some bpftrace versions print lineno as hex without it
    return (
        f"usdt:/proc/{pid}/exe:python:line\n"
        "{{\n"
        '  printf("line:%s:%d\\n", str(arg0), (int64)arg2);\n'
        "}}\n"
    )


def _python_func_entry_script(pid: int) -> str:
    # arg0 = filename (char*), arg1 = funcname (char*)
    return (
        f"usdt:/proc/{pid}/exe:python:function__entry\n"
        "{{\n"
        '  printf("func:%s:%s\\n", str(arg0), str(arg1));\n'
        "}}\n"
    )


def _python_uprobe_script(pid: int, binary_path: str) -> str:
    # Uprobe on PyEval_EvalFrameEx — fires on every Python frame entry.
    # arg0 = PyFrameObject* — we can't safely read the filename from bpftrace
    # without deep CPython struct offsets, so we emit a marker per call only.
    return (
        f"uprobe:{binary_path}:PyEval_EvalFrameEx\n"
        f"/pid == {pid}/\n"
        "{{\n"
        '  printf("func:unknown:frame_entry\\n");\n'
        "}}\n"
    )


def _java_method_script(libjvm_path: str) -> str:
    # hotspot:method__entry args (OpenJDK):
    #   arg0 = thread (uintptr_t)
    #   arg1 = class name  (char*, slash-separated, e.g. "com/example/Foo")
    #   arg2 = method name (char*)
    #   arg3 = signature   (char*)
    return (
        f"usdt:{libjvm_path}:hotspot:method__entry\n"
        "{{\n"
        '  printf("method:%s:%s\\n", str(arg1), str(arg2));\n'
        "}}\n"
    )


def _ruby_method_script(pid: int) -> str:
    # ruby:method__entry args:
    #   arg0 = classname (char*)
    #   arg1 = methodname (char*)
    #   arg2 = filename (char*)
    #   arg3 = lineno (int)
    return (
        f"usdt:/proc/{pid}/exe:ruby:method__entry\n"
        "{{\n"
        '  printf("ruby_method:%s:%s\\n", str(arg0), str(arg1));\n'
        "}}\n"
    )


def _openat_script(pid: int) -> str:
    return (
        "tracepoint:syscalls:sys_enter_openat\n"
        f"/pid == {pid}/\n"
        "{{\n"
        '  printf("open:%s\\n", str(args->filename));\n'
        "}}\n"
    )


# ── libjvm path resolution ────────────────────────────────────────────────────

def _find_libjvm_path(pid: int) -> str | None:
    """Return the absolute path of libjvm.so from /proc/{pid}/maps, or None."""
    maps_path = f"/proc/{pid}/maps"
    try:
        for line in open(maps_path, encoding="utf-8", errors="replace"):
            if "libjvm.so" in line:
                parts = line.split()
                if len(parts) >= 6:
                    candidate = parts[-1]
                    if os.path.exists(candidate):
                        return candidate
    except OSError:
        pass
    return None


# ── Public helpers ────────────────────────────────────────────────────────────

def resolve_pid_binary(pid: int) -> str:
    """Return the absolute path of /proc/{pid}/exe (follows the symlink)."""
    return os.readlink(f"/proc/{pid}/exe")


# ── Per-runtime probe selectors ───────────────────────────────────────────────

def _probe_python(pid: int, binary_path: str) -> ProbeConfig:
    # Tier 1: python:line USDT — highest fidelity (line-level)
    if has_usdt_probe(pid, "python", "line"):
        return ProbeConfig(
            runtime="python",
            mechanism="usdt_line",
            bpftrace_script=_python_line_script(pid),
            output_parser="python_line",
            degraded=False,
            notes=["USDT python:line — line-level coverage"],
        )

    # Tier 2: python:function__entry USDT — function-level
    if has_usdt_probe(pid, "python", "function__entry"):
        logger.warning(
            "[ebpf][probe] python:line probe absent — falling back to "
            "function__entry (function-level only). "
            "Use ubuntu:22.04 or a dtrace-enabled Python for line coverage."
        )
        return ProbeConfig(
            runtime="python",
            mechanism="usdt_func",
            bpftrace_script=_python_func_entry_script(pid),
            output_parser="python_func",
            degraded=True,
            notes=["USDT python:function__entry — function-level only"],
        )

    # Tier 3: uprobe on PyEval_EvalFrameEx — very coarse (frame entry only)
    try:
        script = _python_uprobe_script(pid, binary_path)
        logger.warning(
            "[ebpf][probe] Python USDT probes absent — falling back to "
            "uprobe on PyEval_EvalFrameEx. Coverage will be frame-level only. "
            "Install a dtrace-enabled Python (e.g. ubuntu:22.04) for better fidelity."
        )
        return ProbeConfig(
            runtime="python",
            mechanism="uprobe_sym",
            bpftrace_script=script,
            output_parser="python_func",
            degraded=True,
            notes=["uprobe PyEval_EvalFrameEx — frame-level only, no filename/lineno"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ebpf][probe] uprobe fallback failed: %s", exc)

    return ProbeConfig(
        runtime="python",
        mechanism="uprobe_sym",
        bpftrace_script="",
        output_parser="python_func",
        degraded=True,
        skip=True,
        skip_reason="no_python_probes",
        notes=["No viable Python eBPF probe found"],
    )


def _probe_java(pid: int) -> ProbeConfig:
    libjvm_path = _find_libjvm_path(pid)
    if libjvm_path is None:
        return ProbeConfig(
            runtime="java",
            mechanism="uprobe_sym",
            bpftrace_script="",
            output_parser="java_method",
            degraded=True,
            skip=True,
            skip_reason="libjvm_not_found",
            notes=["libjvm.so not found in /proc/{pid}/maps"],
        )

    # Check for hotspot USDT probes in libjvm (not in the exe)
    import subprocess
    try:
        result = subprocess.run(
            ["readelf", "-n", libjvm_path],
            capture_output=True,
            timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace").lower()
        has_hotspot = "hotspot" in output and "method__entry" in output
    except Exception:  # noqa: BLE001
        has_hotspot = False

    if has_hotspot:
        return ProbeConfig(
            runtime="java",
            mechanism="usdt_method",
            bpftrace_script=_java_method_script(libjvm_path),
            output_parser="java_method",
            degraded=False,
            notes=[
                f"USDT hotspot:method__entry from {libjvm_path}",
                "Tip: if no events fire, add -XX:+ExtendedDTraceProbes to JVM flags",
            ],
        )

    logger.warning(
        "[ebpf][probe] hotspot:method__entry USDT unavailable in %s. "
        "Ensure OpenJDK 8+ and add -XX:+ExtendedDTraceProbes to JVM startup flags. "
        "Java eBPF coverage will be skipped.",
        libjvm_path,
    )
    return ProbeConfig(
        runtime="java",
        mechanism="usdt_method",
        bpftrace_script="",
        output_parser="java_method",
        degraded=True,
        skip=True,
        skip_reason="hotspot_usdt_unavailable",
        notes=[
            f"libjvm found at {libjvm_path} but hotspot USDT probes absent",
            "Add -XX:+ExtendedDTraceProbes to JVM flags and retry",
        ],
    )


def _probe_node(pid: int) -> ProbeConfig:
    # V8 USDT probes are not available in most Node.js distributions.
    # Fall back to openat — gives file-open evidence (package-level only).
    logger.info(
        "[ebpf][probe] Node.js: V8 USDT not widely available — using openat "
        "tracepoint (package-level coverage only). "
        "uprobe-based function coverage is planned for a future release."
    )
    return ProbeConfig(
        runtime="node",
        mechanism="openat",
        bpftrace_script=_openat_script(pid),
        output_parser="openat",
        degraded=True,
        notes=["openat tracepoint — package file-open evidence only"],
    )


def _probe_go(pid: int) -> ProbeConfig:
    # Go has no USDT. uprobe-per-function requires symbol table enumeration
    # (not yet implemented). Use openat as the practical fallback.
    logger.info(
        "[ebpf][probe] Go: USDT unavailable; DWARF uprobe resolution not yet "
        "implemented — using openat tracepoint (package-level coverage only)."
    )
    return ProbeConfig(
        runtime="go",
        mechanism="openat",
        bpftrace_script=_openat_script(pid),
        output_parser="openat",
        degraded=True,
        notes=[
            "openat tracepoint — package file-open evidence only",
            "DWARF uprobe resolution planned for future release",
        ],
    )


def _probe_ruby(pid: int) -> ProbeConfig:
    if has_usdt_probe(pid, "ruby", "method__entry"):
        return ProbeConfig(
            runtime="ruby",
            mechanism="usdt_func",
            bpftrace_script=_ruby_method_script(pid),
            output_parser="ruby_method",
            degraded=False,
            notes=["USDT ruby:method__entry — method-level coverage"],
        )

    logger.warning(
        "[ebpf][probe] ruby:method__entry USDT unavailable. "
        "Ruby 3.x built with SystemTap/DTrace support is required. "
        "Ruby eBPF coverage will be skipped."
    )
    return ProbeConfig(
        runtime="ruby",
        mechanism="usdt_func",
        bpftrace_script="",
        output_parser="ruby_method",
        degraded=True,
        skip=True,
        skip_reason="ruby_usdt_unavailable",
        notes=["ruby:method__entry USDT absent — rebuild Ruby with --enable-dtrace"],
    )


def _probe_generic(pid: int) -> ProbeConfig:
    return ProbeConfig(
        runtime="generic",
        mechanism="openat",
        bpftrace_script=_openat_script(pid),
        output_parser="openat",
        degraded=True,
        notes=["openat tracepoint — file-open evidence only (runtime unknown)"],
    )


# ── Public API ────────────────────────────────────────────────────────────────

def select_probe(runtime: str, pid: int) -> ProbeConfig:
    """Return the best available ProbeConfig for *runtime* and *pid*.

    Falls back gracefully at each tier.  When no viable probe exists,
    returns a ProbeConfig with ``skip=True`` — callers must check this
    and emit an appropriate warning rather than launching bpftrace.
    """
    try:
        binary_path = resolve_pid_binary(pid)
    except OSError as exc:
        logger.warning("[ebpf][probe] Cannot resolve binary for pid=%d: %s", pid, exc)
        binary_path = f"/proc/{pid}/exe"

    dispatch = {
        "python":  lambda: _probe_python(pid, binary_path),
        "java":    lambda: _probe_java(pid),
        "node":    lambda: _probe_node(pid),
        "go":      lambda: _probe_go(pid),
        "ruby":    lambda: _probe_ruby(pid),
        "generic": lambda: _probe_generic(pid),
    }

    fn = dispatch.get(runtime, lambda: _probe_generic(pid))
    config = fn()

    if config.skip:
        logger.warning(
            "[ebpf][probe] pid=%d runtime=%s → SKIP (%s). Notes: %s",
            pid, runtime, config.skip_reason, "; ".join(config.notes),
        )
    else:
        logger.info(
            "[ebpf][probe] pid=%d runtime=%s → mechanism=%s parser=%s degraded=%s",
            pid, runtime, config.mechanism, config.output_parser, config.degraded,
        )
        for note in config.notes:
            logger.debug("[ebpf][probe]   note: %s", note)

    return config
