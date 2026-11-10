# One image serves both the API and the web UI from the same origin.
#   docker build -t scamcheck .
#   docker run -p 8000:8000 scamcheck            # http://localhost:8000

# --- 1. Build the web UI as a static site ------------------------------------------------------
FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# Same-origin API: the UI calls /api/* on whatever host serves it.
ENV STATIC_EXPORT=1 NEXT_PUBLIC_API_URL="" NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# --- 2. Python runtime --------------------------------------------------------------------------
FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install . && rm -rf /root/.cache

COPY --from=web /web/out /app/static

RUN useradd --create-home --uid 10001 app
USER app

# Defaults for a public deployment. Override any of them at runtime.
ENV SCAMCHECK_STATIC_DIR=/app/static \
    SCAMCHECK_ENGINE=auto \
    PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/api/health', timeout=4)"

# One worker: follow-up sessions and the rate limiter live in process memory.
CMD ["sh", "-c", "exec uvicorn scamcheck.api:create_app --factory --host 0.0.0.0 --port ${PORT} --workers 1 --no-server-header"]
