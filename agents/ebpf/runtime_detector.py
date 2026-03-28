"""eBPF runtime language detector.

Inspects a running process to determine which language runtime it uses,
so the probe router can select the correct eBPF mechanism.

Designed to run inside the eBPF sidecar container (which shares the target's
PID namespace via ``pid: "service:target"``) OR from the VulnReach host using
the host-namespace PID obtained from ``docker inspect``.

In both cases /proc/{pid}/... is directly readable.

Public API
----------
detect_runtime(pid)   → "python" | "java" | "node" | "go" | "ruby" | "generic"
has_usdt_probe(pid, provider, probe) → bool
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Literal

logger = logging.getLogger(__name__)

Runtime = Literal["python", "java", "node", "go", "ruby", "generic"]

# ── USDT probe fingerprints ───────────────────────────────────────────────────

# Maps (provider_substring, probe_substring) → runtime
_USDT_SIGNATURES: list[tuple[str, str, Runtime]] = [
    ("python", "line",           "python"),
    ("python", "function__entry","python"),
    ("hotspot", "method__entry", "java"),
    ("ruby",   "method__entry",  "ruby"),
]

# ── /proc/{pid}/maps substrings → runtime ────────────────────────────────────

_MAPS_SIGNATURES: list[tuple[str, Runtime]] = [
    ("libjvm.so",   "java"),
    ("libnode.so",  "node"),
    ("libruby",     "ruby"),
]

# ── /proc/{pid}/cmdline basename substrings → runtime ────────────────────────

_CMDLINE_SIGNATURES: list[tuple[str, Runtime]] = [
    ("python3",  "python"),
    ("python",   "python"),
    ("java",     "java"),
    ("node",     "node"),
    ("nodejs",   "node"),
    ("ruby",     "ruby"),
]


# ── Public helpers ────────────────────────────────────────────────────────────

def has_usdt_probe(pid: int, provider: str, probe: str) -> bool:
    """Return True if /proc/{pid}/exe has a USDT stapsdt note for provider:probe.

    Uses ``readelf -n`` to read ELF notes.  Both *provider* and *probe* are
    matched case-insensitively as substrings of the readelf output.

    Returns False (never raises) on any error — readelf missing, permission
    denied, PID gone, etc.
    """
    exe = f"/proc/{pid}/exe"
    try:
        result = subprocess.run(
            ["readelf", "-n", exe],
            capture_output=True,
            timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace").lower()
        return provider.lower() in output and probe.lower() in output
    except FileNotFoundError:
        logger.debug("[ebpf][detect] readelf not found — USDT probe check skipped")
    except PermissionError:
        logger.debug("[ebpf][detect] permission denied reading %s for USDT check", exe)
    except subprocess.TimeoutExpired:
        logger.debug("[ebpf][detect] readelf timed out for pid=%d", pid)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[ebpf][detect] USDT check failed for pid=%d: %s", pid, exc)
    return False


# ── Private strategy helpers ──────────────────────────────────────────────────

def _strategy_usdt(pid: int) -> Runtime | None:
    """Strategy 1: inspect ELF USDT notes."""
    exe = f"/proc/{pid}/exe"
    try:
        result = subprocess.run(
            ["readelf", "-n", exe],
            capture_output=True,
            timeout=10,
        )
        output = result.stdout.decode("utf-8", errors="replace").lower()
    except Exception:  # noqa: BLE001
        return None

    for provider, probe, runtime in _USDT_SIGNATURES:
        if provider in output and probe in output:
            return runtime
    return None


def _strategy_maps(pid: int) -> Runtime | None:
    """Strategy 2: scan /proc/{pid}/maps for known shared library names."""
    maps_path = f"/proc/{pid}/maps"
    try:
        text = open(maps_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None

    for fragment, runtime in _MAPS_SIGNATURES:
        if fragment in text:
            return runtime

    # Node.js may appear as the executable itself (no libnode.so)
    # e.g. /usr/bin/node  or  /usr/local/bin/node
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            path = parts[-1]
            basename = os.path.basename(path)
            if basename in ("node", "nodejs"):
                return "node"

    return None


def _strategy_cmdline(pid: int) -> Runtime | None:
    """Strategy 3: read /proc/{pid}/cmdline and match known runtime names."""
    cmdline_path = f"/proc/{pid}/cmdline"
    try:
        raw = open(cmdline_path, "rb").read()
    except OSError:
        return None

    args = [seg.decode("utf-8", errors="replace") for seg in raw.split(b"\x00") if seg]
    if not args:
        return None

    # Check first argument (the executable)
    first_basename = os.path.basename(args[0]).lower()
    for fragment, runtime in _CMDLINE_SIGNATURES:
        if fragment in first_basename:
            return runtime

    # No script interpreter matched — check if the exe is a standalone ELF
    # (no known interpreter = likely a compiled Go binary)
    exe_path = f"/proc/{pid}/exe"
    try:
        real_exe = os.readlink(exe_path)
        # Go binaries are self-contained ELF; detect by absence of any known runtime
        # and presence of a "go" build ID or just the fallback heuristic.
        if os.path.isfile(real_exe):
            return "go"
    except OSError:
        pass

    return None


# ── Public API ────────────────────────────────────────────────────────────────

def detect_runtime(pid: int) -> Runtime:
    """Detect the language runtime of process *pid*.

    Tries three strategies in order, returning on the first match:
      1. USDT probe names via ``readelf -n /proc/{pid}/exe``
      2. Shared library names in ``/proc/{pid}/maps``
      3. Executable name in ``/proc/{pid}/cmdline``

    Returns ``"generic"`` if no strategy matches.

    Never raises — all errors are caught and logged at DEBUG level.
    """
    strategies = [
        ("usdt",    _strategy_usdt),
        ("maps",    _strategy_maps),
        ("cmdline", _strategy_cmdline),
    ]
    for strategy_name, fn in strategies:
        try:
            result = fn(pid)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "[ebpf][detect] strategy=%s pid=%d error: %s",
                strategy_name, pid, exc,
            )
            result = None

        if result is not None:
            logger.info(
                "[ebpf][detect] pid=%d → %s (strategy=%s)",
                pid, result, strategy_name,
            )
            return result

    logger.info("[ebpf][detect] pid=%d → generic (no strategy matched)", pid)
    return "generic"
