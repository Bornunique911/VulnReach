# DevBlog backend — intentionally vulnerable Django app
# Mirrors the coverage-instrumentation pattern used by VulnReach dynamic analysis.

FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=devblog.settings

# System deps for Pillow, lxml, psycopg2, cryptography
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

COPY requirements.txt ./
RUN pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt \
 && pip install --no-cache-dir "setuptools>=68" "coverage>=7.4.0" gunicorn

# Write .coveragerc — same format as python_vuln_app for VulnReach compatibility
RUN printf '[run]\nsource = .\nomit = */migrations/*,manage.py\ndata_file = /tmp/.coverage\nparallel = true\nconcurrency = multiprocessing\n\n[json]\noutput = /tmp/coverage.json\n' > /app/.coveragerc

# Inject sitecustomize.py so every gunicorn worker auto-starts coverage
RUN python -c "import sysconfig; print(sysconfig.get_path('purelib'))" > /tmp/sp.txt \
 && printf 'import coverage\ncoverage.process_startup()\n' > "$(cat /tmp/sp.txt)/sitecustomize.py"

ENV COVERAGE_PROCESS_START=/app/.coveragerc

COPY . .

# Run migrations against the SQLite DB, then start gunicorn
RUN python manage.py migrate --run-syncdb 2>/dev/null || true

EXPOSE 3000

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:3000", "devblog.wsgi:application"]
