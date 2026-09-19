# SentinelGuard AI — one image, two commands (API or dashboard).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# Sample IaC files (safe + intentionally vulnerable) for demos.
COPY samples ./samples
COPY scripts ./scripts
COPY .streamlit ./.streamlit

# Run as an unprivileged user; /data holds the SQLite file.
RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown sentinel /data
USER sentinel
ENV SENTINELGUARD_DATABASE_URL=sqlite:////data/sentinelguard.db \
    SENTINELGUARD_API_BASE_URL=http://localhost:8000

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).status == 200 else 1)"

# Default: the API. The dashboard service overrides the command in docker-compose.yml.
CMD ["uvicorn", "sentinelguard.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
