# syntax=docker/dockerfile:1.6

# ---- build stage ----
FROM python:3.11-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Copy full repo to avoid missing-glob failures (no poetry.lock required)
COPY . /app

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -U pip && pip install -e .
RUN python -m compileall -q /app || true

# ---- runtime stage ----
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime
ARG APP_VERSION=dev
ARG GIT_SHA=unknown
ARG BUILD_TS=unknown
LABEL org.opencontainers.image.title="LLM Guardrail API" \
      org.opencontainers.image.description="Guardrail API service" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_TS}"
USER nonroot:nonroot
ENV APP_VERSION=${APP_VERSION} GIT_SHA=${GIT_SHA} BUILD_TS=${BUILD_TS} \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /app
VOLUME ["/tmp"]
EXPOSE 8000

# App + runtime bits
COPY --from=build /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=build /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=build /app /app

# Healthcheck using python (distroless has no /bin/sh)
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/python3","/app/ops/healthcheck.py"]

# No custom entrypoint; run uvicorn directly
CMD ["/usr/local/bin/uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","2"]
