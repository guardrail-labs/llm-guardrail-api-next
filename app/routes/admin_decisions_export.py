from __future__ import annotations

import csv
import importlib
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

try:  # pragma: no cover - fallback handled in tests via monkeypatch
    deps = importlib.import_module("app.routes.admin_decisions_api")
    _get_provider = deps._get_provider
    _require_admin_dep = deps._require_admin_dep
except Exception as exc:  # pragma: no cover - import error reported when endpoint hit
    raise ImportError("admin decisions dependencies unavailable") from exc


router = APIRouter()


def _parse_since(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO8601 timestamp into UTC datetime."""
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iter_rows(
    since: Optional[datetime],
    tenant: Optional[str],
    bot: Optional[str],
    outcome: Optional[str],
    page_size: int,
) -> Iterator[Dict[str, Any]]:
    provider = _get_provider()
    offset = 0
    while True:
        items, _total = provider(since, tenant, bot, outcome, page_size, offset)
        if not items:
            break
        for row in items:
            yield row
        offset += len(items)
        if len(items) < page_size:
            break


def _normalize_row(row: Dict[str, Any], *, dump_details: bool) -> Dict[str, Any]:
    out = dict(row)

    ts = out.get("ts")
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        out["ts"] = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    details = out.get("details", None)
    if dump_details:
        if details is not None and not isinstance(details, str):
            out["details"] = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
    else:
        if isinstance(details, str):
            try:
                out["details"] = json.loads(details)
            except Exception:
                pass

    return out


def _csv_stream(rows: Iterable[Dict[str, Any]]) -> Iterable[bytes]:
    header = [
        "id",
        "ts",
        "tenant",
        "bot",
        "outcome",
        "policy_version",
        "rule_id",
        "incident_id",
        "mode",
        "details",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=header, extrasaction="ignore")
    writer.writeheader()
    yield buffer.getvalue().encode("utf-8")
    buffer.seek(0)
    buffer.truncate(0)
    for row in rows:
        writer.writerow(_normalize_row(row, dump_details=True))
        yield buffer.getvalue().encode("utf-8")
        buffer.seek(0)
        buffer.truncate(0)


def _ndjson_stream(rows: Iterable[Dict[str, Any]]) -> Iterator[bytes]:
    for row in rows:
        yield (
            json.dumps(
                _normalize_row(row, dump_details=False),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")


@router.get(
    "/admin/api/decisions/export.csv",
    dependencies=[Depends(_require_admin_dep)],
)
async def export_csv(
    request: Request,
    since: Optional[str] = Query(default=None),
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    outcome: Optional[str] = Query(default=None),
    page_size: int = Query(default=1000, ge=100, le=5000),
) -> StreamingResponse:
    rows = _iter_rows(_parse_since(since), tenant, bot, outcome, page_size)
    return StreamingResponse(_csv_stream(rows), media_type="text/csv")


@router.get(
    "/admin/api/decisions/export.ndjson",
    dependencies=[Depends(_require_admin_dep)],
)
async def export_ndjson(
    request: Request,
    since: Optional[str] = Query(default=None),
    tenant: Optional[str] = Query(default=None),
    bot: Optional[str] = Query(default=None),
    outcome: Optional[str] = Query(default=None),
    page_size: int = Query(default=1000, ge=100, le=5000),
) -> StreamingResponse:
    rows = _iter_rows(_parse_since(since), tenant, bot, outcome, page_size)
    return StreamingResponse(_ndjson_stream(rows), media_type="application/x-ndjson")
