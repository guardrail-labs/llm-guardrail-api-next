# syntax=docker/dockerfile:1.6

# ---- build stage ----
FROM python:3.11-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml poetry.lock* requirements*.txt* /app/
# Prefer requirements; fall back to pip install -e .
RUN --mount=type=cache,target=/root/.cache/pip \
    bash -lc 'if [ -f requirements.txt ]; then \
      pip install -r requirements.txt; \
    else \
      pip install -e .; \
    fi'

COPY . /app
RUN python -m compileall -q /app || true

# ---- runtime stage ----
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

# Create nonroot user/group explicitly (distroless has nonroot uid=65532)
USER nonroot:nonroot

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app
# Writable tmp for read-only FS
VOLUME ["/tmp"]

COPY --from=build /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=build /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=build /app /app
COPY --chmod=0555 docker/entrypoint.sh /entrypoint.sh

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python3","-c", \
  "import urllib.request as u; \
   import os; \
   u.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/healthz',timeout=2)"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","2"]
