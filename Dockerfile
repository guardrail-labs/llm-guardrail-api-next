# syntax=docker/dockerfile:1.6

# ---- build stage ----
FROM python:3.11-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Copy entire repo to avoid missing-glob failures
COPY . /app

# Install project + ensure FastAPI/Uvicorn available for health app + runtime
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install -U pip && \
    pip install -e . && \
    pip install fastapi uvicorn

# Precompile bytecode (optional)
RUN python -m compileall -q /app || true

# ---- runtime stage ----
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime
USER nonroot:nonroot
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /app
VOLUME ["/tmp"]
EXPOSE 8000

# Copy runtime deps + app
COPY --from=build /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=build /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=build /app /app

# Healthcheck (no /bin/sh in distroless)
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/python3","-c","import urllib.request as u,os;u.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/healthz',timeout=2)"]

# Default command uses python -m to avoid console-script shebang issues
CMD ["/usr/local/bin/python3","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","2"]
