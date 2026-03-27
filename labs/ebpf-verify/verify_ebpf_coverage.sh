#!/usr/bin/env bash
# verify_ebpf_coverage.sh — Run the eBPF line-coverage verification pipeline.
#
# Usage:
#   ./labs/ebpf-verify/verify_ebpf_coverage.sh [--runs=N] [--no-cleanup]
#
# Options:
#   --runs=N       Number of consecutive runs (default: 1).  Use 3 for CI
#                  repeatability checks.
#   --no-cleanup   Leave containers and images after each run (for debugging).
#
# Exit codes:
#   0 — all runs passed
#   1 — one or more runs failed
#   2 — environment unsuitable (not Linux, no Docker, kernel too old)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.ebpf-verify.yml"

# ── Defaults ────────────────────────────────────────────────────────────────
RUNS=1
CLEANUP=true

for arg in "$@"; do
  case "${arg}" in
    --runs=*)   RUNS="${arg#--runs=}" ;;
    --no-cleanup) CLEANUP=false ;;
    *) echo "Unknown option: ${arg}" >&2; exit 2 ;;
  esac
done

# ── Environment checks ───────────────────────────────────────────────────────
fail_env() { echo "ERROR: $*" >&2; exit 2; }
warn()      { echo "WARN:  $*" >&2; }

if [[ "$(uname -s)" != "Linux" ]]; then
  fail_env "eBPF requires Linux.  Current OS: $(uname -s)"
fi

if ! command -v docker &>/dev/null; then
  fail_env "docker not found in PATH"
fi

if ! docker compose version &>/dev/null 2>&1; then
  fail_env "'docker compose' (v2) not available.  Install the Docker Compose plugin."
fi

# Check kernel version (USDT/BTF works well on 5.8+; warn on older kernels)
KERNEL_VER="$(uname -r)"
KERNEL_MAJOR="${KERNEL_VER%%.*}"
KERNEL_MINOR="${KERNEL_VER#*.}"; KERNEL_MINOR="${KERNEL_MINOR%%.*}"
if (( KERNEL_MAJOR < 5 || ( KERNEL_MAJOR == 5 && KERNEL_MINOR < 8 ) )); then
  warn "Kernel ${KERNEL_VER} is older than 5.8 — BTF/USDT support may be limited."
  warn "bpftrace python:line probe requires BTF-capable kernel (≥ 5.8 recommended)."
fi

echo "Environment OK: Linux ${KERNEL_VER}, Docker $(docker --version | awk '{print $3}' | tr -d ',')"
echo "Compose file: ${COMPOSE_FILE}"
echo "Runs: ${RUNS}"
echo ""

# ── Run loop ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

for (( i=1; i<=RUNS; i++ )); do
  echo "══════════════════════════════════════════════════════"
  echo "  Run ${i} / ${RUNS}"
  echo "══════════════════════════════════════════════════════"

  # Ensure output directory exists
  mkdir -p "${SCRIPT_DIR}/coverage-out"

  # Clean up previous outputs so stale JSON doesn't mask a new failure
  rm -f "${SCRIPT_DIR}/coverage-out/ground_truth.json" \
        "${SCRIPT_DIR}/coverage-out/ebpf_coverage.json"

  set +e
  docker compose \
    -f "${COMPOSE_FILE}" \
    up \
    --build \
    --abort-on-container-exit \
    --exit-code-from agent \
    2>&1
  RUN_EXIT=$?
  set -e

  if [[ ${CLEANUP} == true ]]; then
    docker compose -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true
  fi

  if [[ ${RUN_EXIT} -eq 0 ]]; then
    echo "  ✓ Run ${i} PASSED"
    (( PASS++ )) || true
  else
    echo "  ✗ Run ${i} FAILED (exit code ${RUN_EXIT})"
    (( FAIL++ )) || true
    if [[ ${CLEANUP} == false ]]; then
      echo "  Containers left running for inspection (--no-cleanup)."
      echo "  To inspect: docker compose -f ${COMPOSE_FILE} logs"
    fi
  fi

  echo ""
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo "══════════════════════════════════════════════════════"
echo "  Results: ${PASS}/${RUNS} passed, ${FAIL}/${RUNS} failed"
echo "══════════════════════════════════════════════════════"

if [[ -f "${SCRIPT_DIR}/coverage-out/ebpf_coverage.json" ]]; then
  echo ""
  echo "Last eBPF coverage output:"
  python3 -m json.tool "${SCRIPT_DIR}/coverage-out/ebpf_coverage.json" 2>/dev/null || \
    cat "${SCRIPT_DIR}/coverage-out/ebpf_coverage.json"
fi

if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
