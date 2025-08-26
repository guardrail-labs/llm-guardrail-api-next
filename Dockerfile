FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install runtime deps via requirements
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy source
COPY app ./app
COPY README.md ./README.md

EXPOSE 8080
CMD ["uvicorn", "app.main:build_app", "--host", "0.0.0.0", "--port", "8080"]
