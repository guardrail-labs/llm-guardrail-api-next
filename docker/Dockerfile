# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=on

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && rm -rf /var/lib/apt/lists/*

# --- Hardened pip config ---
ARG PIP_DEFAULT_TIMEOUT=60
ARG PIP_RETRIES=6
RUN --mount=type=cache,target=/root/.cache/pip python -m pip install --upgrade pip

# Bring in dependency manifests
COPY requirements*.txt* pyproject.toml poetry.lock* ./

# Optionally bring in a prebuilt wheelhouse (created by CI). The workflow ensures the
# directory exists, even if empty, so COPY won't fail.
COPY .docker_wheelhouse/ /tmp/wheelhouse/

# Download all wheels with retries, then install offline from the wheelhouse.
# Falls back to building wheels for the local project if requirements.txt is absent.
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ -f requirements.txt ]; then \
      python -m pip download -r requirements.txt -d /tmp/wheelhouse --retries ${PIP_RETRIES} --timeout ${PIP_DEFAULT_TIMEOUT} && \
      python -m pip install --no-index --find-links /tmp/wheelhouse -r requirements.txt ; \
    else \
      python -m pip wheel --wheel-dir /tmp/wheelhouse . && \
      python -m pip install --no-index --find-links /tmp/wheelhouse . ; \
    fi

COPY . .

FROM python:3.11-slim AS runtime
WORKDIR /app
# Install curl for container healthcheck
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
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
