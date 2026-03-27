"""Compare ground_truth.json (coverage.py) vs ebpf_coverage.json (bpftrace).

Both files use the coverage.py JSON schema:
  {"files": {filepath: {"executed_lines": [...], "functions": {}}}}

Path normalization: bpftrace emits absolute paths (/app/app.py) while
coverage.py may emit relative paths (app.py).  We compare by basename only.

Negative-control check: unused() in app.py must NOT appear in eBPF output.
These are the lines of the unused() function body in target/app.py.

Usage:
    python3 compare_coverage.py <ground_truth.json> <ebpf_coverage.json>

Exit codes:
    0 — all ground-truth lines present in eBPF output, no false positives
    1 — missed lines or false positives detected
"""
from __future__ import annotations

import json
import os
import sys

# Lines that must NOT appear in eBPF output.
# def unused() / return "never called" in target/app.py
UNUSED_LINES: frozenset[tuple[str, int]] = frozenset({
    ("app.py", 33),
    ("app.py", 34),
})


def load_lines(path: str) -> set[tuple[str, int]]:
    """Load (basename, lineno) pairs from a coverage JSON file."""
    data = json.loads(open(path, encoding="utf-8").read())
    result: set[tuple[str, int]] = set()
    for filepath, info in data.get("files", {}).items():
        base = os.path.basename(filepath)
        for ln in info.get("executed_lines", []):
            result.add((base, int(ln)))
    return result


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} <ground_truth.json> <ebpf_coverage.json>")

    ground_path, ebpf_path = sys.argv[1], sys.argv[2]

    try:
        ground_lines = load_lines(ground_path)
    except FileNotFoundError:
        sys.exit(f"FATAL: ground truth not found: {ground_path}")
    except (json.JSONDecodeError, KeyError) as exc:
        sys.exit(f"FATAL: malformed ground truth JSON: {exc}")

    try:
        ebpf_lines = load_lines(ebpf_path)
    except FileNotFoundError:
        sys.exit(f"FATAL: eBPF coverage not found: {ebpf_path}")
    except (json.JSONDecodeError, KeyError) as exc:
        sys.exit(f"FATAL: malformed eBPF coverage JSON: {exc}")

    # Scope comparison to app.py only — eBPF captures Flask/stdlib lines too
    ground_app = {pair for pair in ground_lines if pair[0] == "app.py"}
    ebpf_app   = {pair for pair in ebpf_lines   if pair[0] == "app.py"}

    missed          = ground_app - ebpf_app
    false_positives = UNUSED_LINES & ebpf_app

    print(f"Ground truth lines (app.py):  {len(ground_app)}")
    print(f"eBPF covered lines (app.py):  {len(ebpf_app)}")
    print(f"Missed by eBPF:               {len(missed)}")
    print(f"False positives (unused()):   {len(false_positives)}")

    if missed:
        print("\nMISSED LINES (in ground truth but not eBPF):")
        for f, ln in sorted(missed):
            print(f"  {f}:{ln}")

    if false_positives:
        print("\nFALSE POSITIVES (unused() lines seen by eBPF):")
        for f, ln in sorted(false_positives):
            print(f"  {f}:{ln}")

    if missed or false_positives:
        sys.exit(1)

    print("\n✓ eBPF coverage matches ground truth (0 missed, 0 false positives)")


if __name__ == "__main__":
    main()
