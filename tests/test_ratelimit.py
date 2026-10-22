"""Tests for the concurrency and rate limiting."""

from __future__ import annotations

import asyncio
import time

from reconscope.ratelimit import AsyncRateLimiter


async def test_concurrency_is_bounded() -> None:
    limiter = AsyncRateLimiter(max_concurrency=2, requests_per_second=1000)
    active = 0
    peak = 0

    async def worker() -> None:
        nonlocal active, peak
        async with limiter:
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1

    await asyncio.gather(*(worker() for _ in range(6)))
    assert peak <= 2


async def test_rate_limits_throughput() -> None:
    limiter = AsyncRateLimiter(max_concurrency=10, requests_per_second=20)
    start = time.monotonic()

    async def tick() -> None:
        await limiter.acquire()
        limiter.release()

    # The bucket starts full (~20 tokens); the 25th request must wait for a refill.
    await asyncio.gather(*(tick() for _ in range(25)))
    assert time.monotonic() - start >= 0.1


async def test_release_on_token_failure() -> None:
    limiter = AsyncRateLimiter(max_concurrency=1, requests_per_second=1000)
    async with limiter:
        pass
    # The permit must be back so a second acquire does not block forever.
    await asyncio.wait_for(limiter.acquire(), timeout=1.0)
    limiter.release()
