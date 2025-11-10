from __future__ import annotations

import json
import os
import random
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, cast

from redis.asyncio import Redis

RedisHashMapping = Mapping[str | bytes, bytes | float | int | str]


@dataclass(slots=True)
class DLQMessage:
    id: str
    tenant: str
    topic: str
    payload: Any
    tries: int
    created_ts: float
    first_failure_ts: float
    last_attempt_ts: Optional[float]
    next_attempt_ts: float
    last_error: Optional[str]


class DLQService:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        self.max_tries = self._parse_int("DLQ_MAX_TRIES", 8, minimum=1)
        self.base_delay = self._parse_float("DLQ_BASE_DELAY_SEC", 5.0, minimum=0.0)
        self.backoff_mult = self._parse_float("DLQ_BACKOFF_MULT", 6.0, minimum=1.0)
        self.max_delay = self._parse_float("DLQ_MAX_DELAY_SEC", 900.0, minimum=0.0)
        self.jitter_frac = self._parse_float("DLQ_JITTER_FRAC", 0.15, minimum=0.0, maximum=1.0)

    async def enqueue(
        self, tenant: str, topic: str, payload: Any, error: Optional[str] = None
    ) -> DLQMessage:
        now = self._now()
        msg_id = uuid.uuid4().hex
        payload_json = json.dumps(payload, default=str, separators=(",", ":"))
        error_text = str(error) if error else ""
        record = {
            "id": msg_id,
            "tenant": tenant,
            "topic": topic,
            "payload": payload_json,
            "tries": "0",
            "created_ts": str(now),
            "first_failure_ts": str(now),
            "last_attempt_ts": "",
            "next_attempt_ts": str(now),
            "last_error": error_text,
        }
        key = self._msg_key(msg_id)
        zset_key = self._zset_key(tenant, topic)
        await self._redis.hset(key, mapping=cast(RedisHashMapping, record))
        await self._redis.zadd(zset_key, {msg_id: now})
        if error_text:
            await self._redis.hset(key, mapping=cast(RedisHashMapping, {"last_error": error_text}))
        message = DLQMessage(
            id=msg_id,
            tenant=tenant,
            topic=topic,
            payload=payload,
            tries=0,
            created_ts=now,
            first_failure_ts=now,
            last_attempt_ts=None,
            next_attempt_ts=now,
            last_error=error_text or None,
        )
        return message

    async def next_due(
        self, tenant: str, topic: str, now: Optional[float] = None, limit: int = 50
    ) -> list[DLQMessage]:
        window = now if now is not None else self._now()
        key = self._zset_key(tenant, topic)
        ids = await self._redis.zrangebyscore(key, "-inf", window, start=0, num=limit)
        return await self._load_messages(ids)

    async def ack(self, msg_id: str) -> bool:
        message = await self._load_message(msg_id)
        if message is None:
            return False
        await self._redis.zrem(self._zset_key(message.tenant, message.topic), msg_id)
        await self._redis.srem(self._quarantine_key(message.tenant, message.topic), msg_id)
        await self._redis.delete(self._msg_key(msg_id))
        return True

    async def nack(self, msg_id: str, error: str) -> Optional[DLQMessage]:
        message = await self._load_message(msg_id)
        if message is None:
            return None
        tries = message.tries + 1
        now = self._now()
        hash_key = self._msg_key(msg_id)
        error_text = str(error) if error else ""
        mapping = {
            "tries": str(tries),
            "last_attempt_ts": str(now),
            "last_error": error_text,
        }
        if tries >= self.max_tries:
            mapping["next_attempt_ts"] = str(now)
            await self._redis.hset(hash_key, mapping=cast(RedisHashMapping, mapping))
            await self._redis.zrem(self._zset_key(message.tenant, message.topic), msg_id)
            await self._redis.sadd(self._quarantine_key(message.tenant, message.topic), msg_id)
            return None
        delay = self._compute_delay(tries)
        next_attempt = max(now + delay, now)
        mapping["next_attempt_ts"] = str(next_attempt)
        await self._redis.hset(hash_key, mapping=cast(RedisHashMapping, mapping))
        await self._redis.zadd(
            self._zset_key(message.tenant, message.topic), {msg_id: next_attempt}
        )
        await self._redis.srem(self._quarantine_key(message.tenant, message.topic), msg_id)
        return DLQMessage(
            id=message.id,
            tenant=message.tenant,
            topic=message.topic,
            payload=message.payload,
            tries=tries,
            created_ts=message.created_ts,
            first_failure_ts=message.first_failure_ts,
            last_attempt_ts=now,
            next_attempt_ts=next_attempt,
            last_error=error_text or None,
        )

    async def replay_now(self, msg_id: str) -> Optional[DLQMessage]:
        message = await self._load_message(msg_id)
        if message is None:
            return None
        now = self._now()
        await self._redis.hset(
            self._msg_key(msg_id),
            mapping=cast(RedisHashMapping, {"next_attempt_ts": str(now)}),
        )
        await self._redis.zadd(self._zset_key(message.tenant, message.topic), {msg_id: now})
        await self._redis.srem(self._quarantine_key(message.tenant, message.topic), msg_id)
        return DLQMessage(
            id=message.id,
            tenant=message.tenant,
            topic=message.topic,
            payload=message.payload,
            tries=message.tries,
            created_ts=message.created_ts,
            first_failure_ts=message.first_failure_ts,
            last_attempt_ts=message.last_attempt_ts,
            next_attempt_ts=now,
            last_error=message.last_error,
        )

    async def list_pending(self, tenant: str, topic: str, limit: int = 100) -> list[DLQMessage]:
        key = self._zset_key(tenant, topic)
        ids = await self._redis.zrange(key, 0, limit - 1)
        return await self._load_messages(ids)

    async def list_quarantine(self, tenant: str, topic: str, limit: int = 200) -> list[str]:
        members = await self._redis.smembers(self._quarantine_key(tenant, topic))
        ids = sorted(self._decode(member) for member in members)
        return ids[: limit if limit >= 0 else len(ids)]

    async def _load_messages(self, ids: Sequence[bytes]) -> list[DLQMessage]:
        if not ids:
            return []
        decoded = [self._decode(msg_id) for msg_id in ids]
        pipe = self._redis.pipeline()
        for msg_id in decoded:
            pipe.hgetall(self._msg_key(msg_id))
        raw_records: Iterable[Any] = await pipe.execute()
        messages: list[DLQMessage] = []
        for msg_id, record in zip(decoded, raw_records):
            mapping: Mapping[bytes, bytes]
            if isinstance(record, Mapping):
                mapping = cast(Mapping[bytes, bytes], record)
            else:
                mapping = cast(Mapping[bytes, bytes], {})
            message = self._parse_record(msg_id, mapping)
            if message is not None:
                messages.append(message)
        messages.sort(key=lambda msg: msg.next_attempt_ts)
        return messages

    async def _load_message(self, msg_id: str) -> Optional[DLQMessage]:
        record = await self._redis.hgetall(self._msg_key(msg_id))
        if not record:
            return None
        return self._parse_record(msg_id, record)

    def _parse_record(self, msg_id: str, record: Mapping[bytes, bytes]) -> Optional[DLQMessage]:
        if not record:
            return None
        tenant = self._decode(record.get(b"tenant"))
        topic = self._decode(record.get(b"topic"))
        if not tenant or not topic:
            return None
        payload_raw = record.get(b"payload")
        payload = self._decode_json(payload_raw)
        tries = self._parse_int_bytes(record.get(b"tries"), default=0)
        created_raw = self._parse_float_bytes(record.get(b"created_ts"), default=0.0)
        created_ts = created_raw if created_raw is not None else 0.0
        first_raw = self._parse_float_bytes(record.get(b"first_failure_ts"), default=created_ts)
        first_failure_ts = first_raw if first_raw is not None else created_ts
        last_attempt_ts = self._parse_float_bytes(record.get(b"last_attempt_ts"))
        next_raw = self._parse_float_bytes(record.get(b"next_attempt_ts"), default=created_ts)
        next_attempt_ts = next_raw if next_raw is not None else created_ts
        last_error = self._decode(record.get(b"last_error")) or None
        return DLQMessage(
            id=msg_id,
            tenant=tenant,
            topic=topic,
            payload=payload,
            tries=tries,
            created_ts=created_ts,
            first_failure_ts=first_failure_ts,
            last_attempt_ts=last_attempt_ts,
            next_attempt_ts=next_attempt_ts,
            last_error=last_error,
        )

    def _compute_delay(self, tries: int) -> float:
        delay = self.base_delay * (self.backoff_mult ** max(tries - 1, 0))
        delay = min(delay, self.max_delay)
        jitter_range = delay * self.jitter_frac
        if jitter_range > 0.0:
            delay += random.uniform(-jitter_range, jitter_range)
        return max(delay, 0.0)

    @staticmethod
    def _msg_key(msg_id: str) -> str:
        return f"dlq:msg:{msg_id}"

    @staticmethod
    def _zset_key(tenant: str, topic: str) -> str:
        return f"dlq:{tenant}:{topic}:z"

    @staticmethod
    def _quarantine_key(tenant: str, topic: str) -> str:
        return f"dlq:{tenant}:{topic}:quarantine"

    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _decode(value: Optional[bytes]) -> str:
        return value.decode("utf-8") if value is not None else ""

    @staticmethod
    def _decode_json(value: Optional[bytes]) -> Any:
        if value is None:
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    @staticmethod
    def _parse_int(env_key: str, default: int, minimum: Optional[int] = None) -> int:
        raw = os.getenv(env_key)
        if raw is None:
            return default
        try:
            value = int(raw)
        except Exception:
            return default
        if minimum is not None and value < minimum:
            return minimum
        return value

    @staticmethod
    def _parse_float(
        env_key: str,
        default: float,
        minimum: Optional[float] = None,
        maximum: Optional[float] = None,
    ) -> float:
        raw = os.getenv(env_key)
        if raw is None:
            return default
        try:
            value = float(raw)
        except Exception:
            return default
        if minimum is not None and value < minimum:
            value = minimum
        if maximum is not None and value > maximum:
            value = maximum
        return value

    @staticmethod
    def _parse_int_bytes(
        raw: Optional[bytes], default: int = 0, minimum: Optional[int] = None
    ) -> int:
        if raw is None:
            return default
        try:
            value = int(raw.decode("utf-8"))
        except Exception:
            return default
        if minimum is not None and value < minimum:
            return minimum
        return value

    @staticmethod
    def _parse_float_bytes(
        raw: Optional[bytes], default: Optional[float] = None
    ) -> Optional[float]:
        if raw is None:
            return default
        try:
            return float(raw.decode("utf-8"))
        except Exception:
            return default
