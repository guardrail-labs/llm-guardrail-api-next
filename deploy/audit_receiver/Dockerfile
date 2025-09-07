FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /srv
RUN pip install fastapi==0.112.0 uvicorn==0.30.0 prometheus-client==0.20.0
COPY main.py /srv/main.py
EXPOSE 8079
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8079"]
