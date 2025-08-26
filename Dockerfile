# syntax=docker/dockerfile:1

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Optional build metadata (from release workflow)
ARG BUILD_VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=dev

LABEL org.opencontainers.image.source="https://github.com/${GITHUB_REPOSITORY}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.title="llm-guardrail-api-next"

WORKDIR /app

# Install runtime dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy application code (only what's needed at runtime)
COPY app /app/app

# Non-root user (best practice)
RUN set -eux; \
    groupadd -r appuser && useradd -r -g appuser appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8080
ENV PORT=8080

# Start the API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
