"""Politeness controls shared by every network probe.

Two limits run together: a semaphore caps how many connections are open at once, and a token
bucket caps how many new connections start per second. Both are needed — the semaphore bounds
the burst, the bucket bounds the sustained rate — so a scan stays gentle on the target and on
any network device in between.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType


class AsyncRateLimiter:
    """Concurrency semaphore plus a token-bucket rate limiter, used as an async context manager."""

    def __init__(self, max_concurrency: int, requests_per_second: float) -> None:
        self._sem = asyncio.Semaphore(max_concurrency)
        self._rate = requests_per_second
        self._capacity = max(1.0, requests_per_second)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def _take_token(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)

    async def acquire(self) -> None:
        await self._sem.acquire()
        try:
            await self._take_token()
        except BaseException:  # pragma: no cover - defensive: never leak a permit
            self._sem.release()
            raise

    def release(self) -> None:
        self._sem.release()

    async def __aenter__(self) -> AsyncRateLimiter:
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
