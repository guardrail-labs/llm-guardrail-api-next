# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Build args for OCI labels
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE

# OCI labels
LABEL org.opencontainers.image.title="llm-guardrail-api-next" \
      org.opencontainers.image.description="LLM Guardrail API (FastAPI) with policy, redaction, limits, metrics, and admin endpoints." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}"

# Prevents Python from writing pyc files / unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Workdir
WORKDIR /app

# System deps (curl for health checks in containers, tini as init)
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    curl tini \
 && rm -rf /var/lib/apt/lists/*

# Install deps
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Non-root user for runtime
RUN useradd -u 10001 -ms /bin/bash appuser
USER appuser

EXPOSE 8000

# Use tini as PID 1 for signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command: uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
