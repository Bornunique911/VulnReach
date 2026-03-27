# Target container for eBPF line-coverage verification.
#
# Must use ubuntu:22.04 — its Python 3.10 is compiled with --enable-dtrace,
# providing USDT probes that bpftrace's python:line probe can attach to.
# python:3.x-slim (Debian) does NOT have USDT probes.

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-flask \
    binutils \
  && rm -rf /var/lib/apt/lists/*

# Build-time assertion: fail immediately if python3 has no USDT stapsdt notes.
# This surfaces immediately if the base image is ever changed to one without
# dtrace support, rather than silently producing empty coverage data at runtime.
RUN readelf -n "$(which python3)" | grep -q stapsdt \
    || (echo "ERROR: python3 at $(which python3) has no USDT probes — bpftrace python:line will not fire" && exit 1)

WORKDIR /app
COPY app.py .

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python3", "app.py"]
