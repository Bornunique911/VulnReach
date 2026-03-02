# Dockerfile for python_vuln_app
# Builds a minimal container that installs required system packages
# needed to compile some Python packages (lxml, Pillow, cryptography, etc.)
# and runs the Flask app with gunicorn for production-like behavior.

FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies required by some packages in requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libffi-dev \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only requirements first to leverage Docker cache
COPY requirements.txt ./

# Upgrade pip and install Python dependencies, then install gunicorn
# Use pip's legacy resolver to allow installing intentionally pinned (and
# potentially conflicting) vulnerable versions present in requirements.txt.
RUN pip install --upgrade pip setuptools wheel \
 && pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt \
 && pip install --no-cache-dir "coverage>=7.4.0" gunicorn

# Write .coveragerc
RUN printf '[run]\nsource = .\ndata_file = /tmp/.coverage\nparallel = true\nconcurrency = multiprocessing\n\n[json]\noutput = /tmp/coverage.json\n' > /app/.coveragerc

# Inject sitecustomize.py so every gunicorn worker subprocess auto-starts coverage
RUN python -c "import sysconfig; print(sysconfig.get_path('purelib'))" > /tmp/sp.txt \
 && printf 'import coverage\ncoverage.process_startup()\n' > "$(cat /tmp/sp.txt)/sitecustomize.py"

ENV COVERAGE_PROCESS_START=/app/.coveragerc

# Copy application source
COPY src/ ./src

EXPOSE 3000

# Plain gunicorn — sitecustomize.py handles coverage in every worker
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:3000", "src.app:app"]
