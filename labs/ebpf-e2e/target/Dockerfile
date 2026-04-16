# ubuntu:22.04 ships Python 3.10 compiled with --enable-dtrace (USDT probes).
# This is required for line-level and function-level eBPF tracing via bpftrace.
# DO NOT switch to python:3.x-slim — those images lack USDT probes.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    binutils \
  && rm -rf /var/lib/apt/lists/*

# Advisory USDT check — warns if USDT probes are absent but does not fail the build.
# USDT line/function tracing requires Python compiled with --enable-dtrace.
# ubuntu:22.04 system Python satisfies this on a real Linux host.
# On Docker Desktop (macOS/Windows) the check may warn — eBPF falls back to openat mode.
RUN python3 -c "import sys; print('Python:', sys.version)" && \
    { readelf -n $(which python3) 2>/dev/null | grep -q stapsdt \
        && echo "USDT probes: present (line/function tracing available)" \
        || echo "USDT probes: absent — eBPF will use openat (file-level) mode"; }

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5001

CMD ["python3", "-m", "flask", "--app", "app", "run", "--host=0.0.0.0", "--port=5001"]
