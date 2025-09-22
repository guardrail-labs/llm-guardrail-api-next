import asyncio
import os
import time

import httpx

BASE = os.getenv("GUARDRAIL_BASE", "http://localhost:8000")
TOKEN = os.getenv("ADMIN_TOKEN", "")

HEADERS = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}


async def once(client: httpx.AsyncClient) -> tuple[int, int, int]:
    r1 = await client.get(f"{BASE}/healthz")
    r2 = await client.get(f"{BASE}/readyz")
    r3 = await client.get(
        f"{BASE}/admin/api/decisions?limit=10",
        headers=HEADERS,
    )
    return r1.status_code, r2.status_code, r3.status_code


async def main() -> None:
    async with httpx.AsyncClient(timeout=5) as client:
        start = time.time()
        oks = 0
        for _ in range(100):
            statuses = await once(client)
            oks += all(code == 200 for code in statuses)
        duration = time.time() - start
        print(f"OK triplets: {oks}/100 in {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
