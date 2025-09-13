from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Dict

from fastapi import FastAPI, Request, Response


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "time": int(time.time() * 1000),
        }
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)

def install_json_logging(app: FastAPI) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Clean handlers so we don't duplicate on reloads
    root.handlers = []

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    # Attach a simple request log (optional; respects RequestID if present)
    @app.middleware("http")
    async def _json_access_log(request: Request, call_next):
        start = time.perf_counter()
        response: Response = await call_next(request)
        dur_ms = (time.perf_counter() - start) * 1000
        logging.getLogger("access").info(
            json.dumps(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round(dur_ms, 2),
                }
            )
        )
        return response
