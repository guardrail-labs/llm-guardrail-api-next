# syntax=docker/dockerfile:1.6

# -------- build stage --------
FROM python:3.11-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Copy repo (avoid fragile globs)
COPY . /app

# Create venv, install requirements.txt if present, then app + runtime deps
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install -U pip && \
    if [ -f requirements.txt ]; then \
      /opt/venv/bin/pip install -r requirements.txt; \
    fi && \
    /opt/venv/bin/pip install -e . && \
    /opt/venv/bin/pip install fastapi uvicorn && \
    python -m compileall -q /app || true

# -------- runtime stage --------
FROM python:3.11-slim AS runtime

# Security posture: non-root, read-only rootfs compatible
RUN useradd -u 65532 -r -s /usr/sbin/nologin nonroot
USER nonroot:nonroot

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app
VOLUME ["/tmp"]
EXPOSE 8000

# Copy the venv and app code from build
COPY --chown=65532:65532 --from=build /opt/venv /opt/venv
COPY --chown=65532:65532 --from=build /app /app

# Healthcheck without shell; use python -c
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python","-c","import urllib.request as u,os;u.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/healthz',timeout=2)"]

# Default CMD: your real app (smoke CI overrides this to run the health app)
CMD ["python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","2"]
