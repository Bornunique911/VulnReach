#!/usr/bin/env bash
# run_ebpf_ci.sh — Build and run the eBPF e2e test suite in Docker.
#
# Prerequisites (Linux only):
#   • Docker with --privileged support
#   • Kernel ≥ 4.9 with CONFIG_BPF=y
#   • BTF-enabled kernel (≥ 5.8) for headerless bpftrace (recommended)
#
# On non-Linux hosts the unit + failure-mode tests still run without Docker:
#   pytest tests/test_ebpf.py -m "not integration"
#
# Exit codes:
#   0  all tests passed
#   1  one or more tests failed
#   2  environment not suitable (non-Linux or Docker unavailable)
#
# Usage:
#   ./scripts/run_ebpf_ci.sh
#   ./scripts/run_ebpf_ci.sh --no-cleanup   # keep containers for inspection

set -euo pipefail

COMPOSE_FILE="docker-compose.ebpf-test.yml"
RUNNER_SERVICE="ebpf-runner"
CLEANUP=true

# ── Argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --no-cleanup) CLEANUP=false ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# ── Environment checks ────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  eBPF e2e tests require a Linux host (detected: $(uname -s))  ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Unit and failure-mode tests run on any OS without Docker:"
    echo "  pytest tests/test_ebpf.py -m 'not integration'"
    exit 2
fi

if ! docker info &>/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not available." >&2
    exit 2
fi

# Warn if kernel may not support BPF (best-effort check)
KERNEL_VER=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)
if (( KERNEL_MAJOR < 4 )) || (( KERNEL_MAJOR == 4 && KERNEL_MINOR < 9 )); then
    echo "WARNING: kernel $KERNEL_VER may not support eBPF (need ≥ 4.9)." >&2
fi

# ── Build phase ───────────────────────────────────────────────────────────────
echo ""
echo "═══ Building images ════════════════════════════════════════════════"
docker compose -f "$COMPOSE_FILE" build

# ── Test phase ────────────────────────────────────────────────────────────────
echo ""
echo "═══ Running eBPF e2e tests ═════════════════════════════════════════"

# --abort-on-container-exit  stops all services when any service exits
# --exit-code-from            propagates the runner's exit code to the shell
set +e
docker compose -f "$COMPOSE_FILE" up \
    --no-build \
    --abort-on-container-exit \
    --exit-code-from "$RUNNER_SERVICE"
TEST_EXIT=$?
set -e

# ── Cleanup phase ─────────────────────────────────────────────────────────────
if $CLEANUP; then
    echo ""
    echo "═══ Cleaning up ════════════════════════════════════════════════════"
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [[ $TEST_EXIT -eq 0 ]]; then
    echo "✓ All eBPF tests passed."
else
    echo "✗ eBPF tests FAILED (exit code $TEST_EXIT)." >&2
fi

exit $TEST_EXIT
