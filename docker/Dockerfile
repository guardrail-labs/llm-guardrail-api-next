# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_NO_CACHE_DIR=on

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml poetry.lock* requirements*.txt* ./
# Prefer requirements.txt; fallback to pyproject if needed
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; \
    else pip install .; fi

COPY . .

FROM python:3.11-slim AS runtime
WORKDIR /app
ENV PORT=8000 HOST=0.0.0.0 \
    RULES_PATH=/etc/guardrail/rules.yaml

RUN useradd -m guardrail
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Non-root
USER guardrail
EXPOSE 8000
CMD ["python", "-m", "app.run"]
