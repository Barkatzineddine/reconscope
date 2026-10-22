"""Asynchronous TCP connect scan.

A connect scan completes the three-way handshake like any ordinary client, so it needs no raw
sockets and no special privileges, and it is honest: the target sees a normal, logged
connection. Every attempt goes through the shared rate limiter.
"""

from __future__ import annotations

import asyncio

from .models import PortResult, PortState
from .netutil import close_writer
from .ratelimit import AsyncRateLimiter


async def scan_port(host: str, port: int, limiter: AsyncRateLimiter, timeout: float) -> PortResult:
    """Attempt a single TCP connection and classify the outcome."""

    async with limiter:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        except TimeoutError:
            return PortResult(port=port, state=PortState.FILTERED)
        except ConnectionRefusedError:
            return PortResult(port=port, state=PortState.CLOSED)
        except OSError:
            # No route, reset, address family mismatch: treat as filtered, it is not reachable.
            return PortResult(port=port, state=PortState.FILTERED)
        await close_writer(writer)
        return PortResult(port=port, state=PortState.OPEN)


async def scan_host(
    host: str, ports: list[int], limiter: AsyncRateLimiter, timeout: float
) -> list[PortResult]:
    """Scan every port of a host concurrently, returned sorted by port number."""

    tasks = [asyncio.create_task(scan_port(host, port, limiter, timeout)) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.port)
