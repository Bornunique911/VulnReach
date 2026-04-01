"""eBPF coverage output normaliser.

Parses raw bpftrace stdout (from any runtime probe) into a unified
NormalisedCoverage schema, then optionally converts it to the
coverage.py JSON format so it can be fed directly into the existing
``coverage_correlator.correlate_coverage()`` without modification.

NormalisedCoverage schema
--------------------------
{
  "runtime": str,
  "files": {
    "<source_file_path>": {
      "executed_lines": [int, ...],      # sorted, deduped; empty if unavailable
      "executed_functions": [str, ...]   # sorted, deduped; empty if unavailable
    }
  }
}

Public API
----------
normalise(raw_output, probe_config, pid) → NormalisedCoverage
to_coverage_py_format(normalised)        → dict  (coverage.py JSON schema)
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from collections import defaultdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents.ebpf.probe_router import ProbeConfig

logger = logging.getLogger(__name__)

# Type alias (plain dict for JSON-serialisability)
NormalisedCoverage = dict[str, Any]

# Warn once per process about missing post-processing tools
_javap_warned = False
_addr2line_warned = False


# ── Line parsers ──────────────────────────────────────────────────────────────

def _parse_python_line(raw: str) -> NormalisedCoverage:
    """Parse ``line:{filepath}:{lineno}`` bpftrace output."""
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    pattern = re.compile(r"^line:(.+):(\d+)$")
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            hits[m.group(1)]["lines"].add(int(m.group(2)))
    return _hits_to_normalised("python", hits)


def _parse_python_func(raw: str) -> NormalisedCoverage:
    """Parse ``func:{filepath}:{funcname}`` bpftrace output."""
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    pattern = re.compile(r"^func:(.+):(.+)$")
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            hits[m.group(1)]["funcs"].add(m.group(2))
    return _hits_to_normalised("python", hits)


def _parse_java_method(raw: str, pid: int) -> NormalisedCoverage:
    """Parse ``method:{class_slash}:{method_name}`` bpftrace output.

    Attempts to resolve class/method → source lines via ``javap -l``.
    Falls back to function-level only when javap is unavailable.
    """
    # Collect unique (class_slash, method_name) pairs
    seen: set[tuple[str, str]] = set()
    pattern = re.compile(r"^method:(.+):(.+)$")
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            seen.add((m.group(1), m.group(2)))

    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    for class_slash, method_name in seen:
        source_file, line_numbers = _java_method_to_source(class_slash, method_name, pid)
        hits[source_file]["funcs"].add(method_name)
        hits[source_file]["lines"].update(line_numbers)

    return _hits_to_normalised("java", hits)


def _parse_go_uprobe(raw: str, pid: int) -> NormalisedCoverage:
    """Parse ``addr:{hex_addr}`` bpftrace output, resolve via addr2line."""
    addrs: list[str] = []
    pattern = re.compile(r"^addr:(0x[0-9a-f]+)$", re.IGNORECASE)
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            addrs.append(m.group(1))

    if not addrs:
        return {"runtime": "go", "files": {}}

    try:
        binary_path = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        binary_path = ""

    resolved = _go_addrs_to_lines(binary_path, addrs) if binary_path else {}
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    for addr, (filepath, func_name, lineno) in resolved.items():
        if filepath and filepath != "??":
            if lineno > 0:
                hits[filepath]["lines"].add(lineno)
            if func_name and func_name != "??":
                hits[filepath]["funcs"].add(func_name)

    return _hits_to_normalised("go", hits)


def _parse_ruby_method(raw: str) -> NormalisedCoverage:
    """Parse ``ruby_method:{classname}:{methodname}`` bpftrace output."""
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    pattern = re.compile(r"^ruby_method:(.+):(.+)$")
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            class_name, method_name = m.group(1), m.group(2)
            # Best-effort path: Foo::Bar → foo/bar.rb
            source_path = _ruby_class_to_path(class_name)
            hits[source_path]["funcs"].add(method_name)
    return _hits_to_normalised("ruby", hits)


def _parse_openat(raw: str, runtime: str) -> NormalisedCoverage:
    """Parse ``open:{filepath}`` bpftrace output — file-open evidence only."""
    hits: dict[str, dict] = defaultdict(lambda: {"lines": set(), "funcs": set()})
    pattern = re.compile(r"^open:(.+)$")
    for row in raw.splitlines():
        m = pattern.match(row.strip())
        if m:
            path = m.group(1)
            # Only include source-like paths (filter out /proc, /sys, /dev, etc.)
            if _is_source_path(path):
                hits[path]  # touch the default entry
    return _hits_to_normalised(runtime, hits)


# ── Post-processing helpers ───────────────────────────────────────────────────

def _java_method_to_source(
    class_slash: str, method_name: str, pid: int
) -> tuple[str, list[int]]:
    """Map a Java class+method to (source_file_path, [line_numbers]).

    Searches /proc/{pid}/root for the .class file, runs ``javap -l``
    and parses the LineNumberTable for the method.

    Returns a best-effort path with empty lines on any failure.
    """
    global _javap_warned

    fallback_path = class_slash.replace("/", ".") + ".java"

    # Locate .class file under /proc/{pid}/root
    class_filename = class_slash.split("/")[-1] + ".class"
    root = f"/proc/{pid}/root"
    class_file: str | None = None

    try:
        for dirpath, _dirs, files in os.walk(root):
            # Limit depth to avoid runaway searches in large images
            depth = dirpath[len(root):].count(os.sep)
            if depth > 12:
                continue
            if class_filename in files:
                candidate = os.path.join(dirpath, class_filename)
                # Prefer path that contains the full class_slash hint
                if class_slash.replace("/", os.sep) in candidate:
                    class_file = candidate
                    break
                class_file = candidate  # keep best-effort match
    except OSError:
        pass

    if not class_file:
        logger.debug("[ebpf][java] .class not found for %s", class_slash)
        return fallback_path, []

    if not shutil.which("javap"):
        if not _javap_warned:
            logger.warning(
                "[ebpf][java] javap not found — Java line number resolution unavailable. "
                "Install default-jdk-headless for line-level Java coverage."
            )
            _javap_warned = True
        return fallback_path, []

    try:
        result = subprocess.run(
            ["javap", "-l", "-verbose", class_file],
            capture_output=True,
            timeout=15,
            text=True,
        )
        return _parse_javap_output(result.stdout, class_slash, method_name)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[ebpf][java] javap failed for %s: %s", class_file, exc)
        return fallback_path, []


def _parse_javap_output(
    javap_out: str, class_slash: str, method_name: str
) -> tuple[str, list[int]]:
    """Extract source filename and line numbers from javap -l -verbose output."""
    source_file = class_slash.rsplit("/", 1)[0] + "/" if "/" in class_slash else ""
    lines: list[int] = []

    # Extract SourceFile attribute: "SourceFile: \"Foo.java\""
    sf_match = re.search(r'SourceFile:\s+"([^"]+)"', javap_out)
    if sf_match:
        pkg_prefix = "/".join(class_slash.split("/")[:-1])
        raw_sf = sf_match.group(1)
        source_file = f"{pkg_prefix}/{raw_sf}" if pkg_prefix else raw_sf

    # Find the method section then its LineNumberTable
    # javap -l output format:
    #   public void myMethod(...)
    #      line NNN: offset
    in_method = False
    in_line_table = False

    for line in javap_out.splitlines():
        stripped = line.strip()

        # Detect method signature containing our method name
        if method_name in stripped and ("(" in stripped):
            in_method = True
            in_line_table = False
            lines = []  # reset — we want THIS method's lines
            continue

        if in_method:
            if "LineNumberTable:" in stripped:
                in_line_table = True
                continue
            if in_line_table:
                # Format: "line NN: offset"
                lm = re.match(r"line\s+(\d+):\s+\d+", stripped)
                if lm:
                    lines.append(int(lm.group(1)))
                    continue
                # End of LineNumberTable when we hit something else
                if stripped and not stripped.startswith("line "):
                    in_line_table = False
                    # Don't break — there may be overloaded methods

    return source_file, sorted(set(lines))


def _go_addrs_to_lines(
    binary_path: str, addrs: list[str]
) -> dict[str, tuple[str, str, int]]:
    """Resolve hex addresses to (filepath, function_name, lineno) via addr2line.

    Returns {addr_str: (filepath, func_name, lineno)}.
    Skips unresolvable addresses (filepath == "??").
    """
    global _addr2line_warned

    if not shutil.which("addr2line"):
        if not _addr2line_warned:
            logger.warning(
                "[ebpf][go] addr2line not found — Go line number resolution unavailable. "
                "Install binutils for line-level Go coverage."
            )
            _addr2line_warned = True
        return {}

    try:
        result = subprocess.run(
            ["addr2line", "-e", binary_path, "-f", "-i"] + addrs,
            capture_output=True,
            timeout=30,
            text=True,
        )
        if result.returncode != 0:
            logger.debug("[ebpf][go] addr2line non-zero exit: %s", result.stderr[:200])
            return {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ebpf][go] addr2line failed: %s", exc)
        return {}

    resolved: dict[str, tuple[str, str, int]] = {}
    output_lines = result.stdout.splitlines()

    # addr2line -f output: pairs of (function_name, filepath:lineno) per address
    it = iter(output_lines)
    for addr in addrs:
        try:
            func_name = next(it).strip()
            loc = next(it).strip()
        except StopIteration:
            break

        if ":" in loc:
            parts = loc.rsplit(":", 1)
            filepath = parts[0]
            try:
                lineno = int(parts[1])
            except ValueError:
                lineno = 0
        else:
            filepath, lineno = loc, 0

        resolved[addr] = (filepath, func_name, lineno)

    return resolved


def _ruby_class_to_path(class_name: str) -> str:
    """Best-effort: convert Ruby class name to a relative file path.

    E.g. ``Foo::BarBaz`` → ``foo/bar_baz.rb``
    """
    # Convert CamelCase to snake_case per Ruby convention
    def camel_to_snake(name: str) -> str:
        s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
        s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
        return s.lower()

    parts = [camel_to_snake(p) for p in class_name.split("::")]
    return "/".join(parts) + ".rb"


def _is_source_path(path: str) -> bool:
    """Return True if path looks like application source rather than system noise."""
    noise_prefixes = ("/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/etc/")
    if any(path.startswith(p) for p in noise_prefixes):
        return False
    _, ext = os.path.splitext(path)
    source_exts = {
        ".py", ".rb", ".js", ".ts", ".java", ".go", ".php",
        ".rs", ".cs", ".cpp", ".c", ".h",
    }
    return ext in source_exts or not ext  # include extensionless (e.g. Go binaries)


# ── Internal aggregation ──────────────────────────────────────────────────────

def _hits_to_normalised(runtime: str, hits: dict[str, dict]) -> NormalisedCoverage:
    files: dict[str, dict] = {}
    for filepath, data in hits.items():
        files[filepath] = {
            "executed_lines": sorted(data.get("lines", set())),
            "executed_functions": sorted(data.get("funcs", set())),
        }
    return {"runtime": runtime, "files": files}


# ── Public API ────────────────────────────────────────────────────────────────

def normalise(raw_output: str, probe_config: "ProbeConfig", pid: int) -> NormalisedCoverage:
    """Parse raw bpftrace stdout into NormalisedCoverage.

    Dispatches to the correct parser based on ``probe_config.output_parser``.
    Returns an empty-files dict on any unexpected error (never raises).
    """
    parser = probe_config.output_parser
    runtime = probe_config.runtime

    try:
        if parser == "python_line":
            result = _parse_python_line(raw_output)
        elif parser == "python_func":
            result = _parse_python_func(raw_output)
        elif parser == "java_method":
            result = _parse_java_method(raw_output, pid)
        elif parser == "go_uprobe":
            result = _parse_go_uprobe(raw_output, pid)
        elif parser == "ruby_method":
            result = _parse_ruby_method(raw_output)
        elif parser == "openat":
            result = _parse_openat(raw_output, runtime)
        else:
            logger.warning("[ebpf][normalise] Unknown parser %r — returning empty", parser)
            return {"runtime": runtime, "files": {}}

        # Count raw tracer events (exclude bpftrace startup banner lines).
        raw_event_count = sum(
            1 for row in raw_output.splitlines()
            if row.strip() and not row.startswith("Attaching")
        )
        file_count = len(result.get("files", {}))
        total_lines = sum(
            len(f.get("executed_lines", [])) for f in result.get("files", {}).values()
        )
        total_funcs = sum(
            len(f.get("executed_functions", [])) for f in result.get("files", {}).values()
        )
        logger.info(
            "[ebpf][normalise] parser=%s raw_events=%d → files=%d lines=%d functions=%d",
            parser, raw_event_count, file_count, total_lines, total_funcs,
        )

        if file_count == 0:
            logger.warning(
                "[ebpf][normalise] Zero coverage captured (parser=%s). Possible causes: "
                "(1) bpftrace probe did not attach — check [bpftrace stderr] lines above; "
                "(2) no traffic reached the container; "
                "(3) USDT probes absent — python:line requires CPython built with "
                "--with-dtrace (ubuntu:22.04 has it; python:3.x-slim does not); "
                "(4) /sys/kernel/debug not bind-mounted into the container; "
                "(5) kernel < 4.9 or BTF unavailable.",
                parser,
            )

        return result
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[ebpf][normalise] Unexpected error in parser=%s: %s", parser, exc,
            exc_info=True,
        )
        return {"runtime": runtime, "files": {}}


def to_coverage_py_format(normalised: NormalisedCoverage) -> dict:
    """Convert NormalisedCoverage to the coverage.py JSON schema.

    Enables NormalisedCoverage to flow directly into the existing
    ``coverage_correlator.correlate_coverage()`` without any modification.

    The ``functions`` sub-dict uses a synthetic ``"executed_lines": [1]``
    for each eBPF-observed function — this satisfies the check in
    ``build_hit_sets()`` (``if func_data.get("executed_lines")``) so the
    function is classified as a *call hit* rather than an import-time hit.
    That is correct: eBPF observation at function-entry IS a call hit.
    """
    out_files: dict[str, dict] = {}

    for filepath, data in normalised.get("files", {}).items():
        executed_lines: list[int] = data.get("executed_lines", [])
        executed_functions: list[str] = data.get("executed_functions", [])

        functions: dict[str, dict] = {}
        for func_name in executed_functions:
            # Synthetic executed_lines=[1] marks the function as called.
            functions[func_name] = {"executed_lines": [1]}

        out_files[filepath] = {
            "executed_lines": executed_lines,
            "functions": functions,
        }

    return {"files": out_files}
