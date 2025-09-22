FROM python:3.11-slim

# --- Build metadata (OCI labels) ---
ARG APP_VERSION=1.0.0-rc1
ARG GIT_SHA=unknown
ARG BUILD_TS=unknown

ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA} \
    BUILD_TS=${BUILD_TS} \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

LABEL org.opencontainers.image.title="LLM Guardrail API" \
      org.opencontainers.image.description="Guardrail API service" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_TS}" \
      org.opencontainers.image.source="https://github.com/<your-org>/llm-guardrail-api-next" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
