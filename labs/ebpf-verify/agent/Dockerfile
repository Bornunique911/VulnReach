# Agent container for eBPF line-coverage verification.
#
# Build context: labs/ebpf-verify/  (parent of this directory)
# The agent needs target/app.py to generate the ground truth locally
# before attaching bpftrace probes to the target container.

FROM python:3.11-slim

ARG DEBIAN_FRONTEND=noninteractive

# bpftrace  — the eBPF tracer
# procps    — provides pgrep (PID discovery via shared PID namespace)
# curl      — optional diagnostics
RUN apt-get update && apt-get install -y --no-install-recommends \
    bpftrace \
    procps \
    curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the agent scripts
COPY agent/ebpf_line_collector.py agent/compare_coverage.py ./

# Copy target app — needed by Phase 1 to generate coverage.py ground truth
# locally inside the agent container (on port 5001).
COPY target/app.py ./

# flask — required by app.py; coverage — generates ground_truth.json
RUN pip install --no-cache-dir flask coverage

CMD ["python3", "ebpf_line_collector.py"]
