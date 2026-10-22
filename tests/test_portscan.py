"""Tests for the TCP connect scan."""

from __future__ import annotations

import asyncio

import pytest

from reconscope import portscan
from reconscope.models import PortState
from reconscope.ratelimit import AsyncRateLimiter
from tests.conftest import ServerFactory

LIMITER = AsyncRateLimiter(max_concurrency=10, requests_per_second=1000)


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()


async def test_open_port(make_server: ServerFactory) -> None:
    port = await make_server(_echo)
    result = await portscan.scan_port("127.0.0.1", port, LIMITER, timeout=2.0)
    assert result.state is PortState.OPEN


async def test_closed_port(monkeypatch: pytest.MonkeyPatch) -> None:
    # A refused connection means the port is closed. Forced here so the test is the same on
    # every platform (Windows drops connections to unbound loopback ports instead of refusing).
    async def refused(*_a: object, **_k: object) -> None:
        raise ConnectionRefusedError

    monkeypatch.setattr("asyncio.open_connection", refused)
    result = await portscan.scan_port("127.0.0.1", 1234, LIMITER, timeout=2.0)
    assert result.state is PortState.CLOSED


async def test_filtered_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def slow(*_a: object, **_k: object) -> None:
        raise TimeoutError

    monkeypatch.setattr("asyncio.open_connection", slow)
    result = await portscan.scan_port("127.0.0.1", 1234, LIMITER, timeout=0.1)
    assert result.state is PortState.FILTERED


async def test_filtered_on_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_route(*_a: object, **_k: object) -> None:
        raise OSError("no route to host")

    monkeypatch.setattr("asyncio.open_connection", no_route)
    result = await portscan.scan_port("127.0.0.1", 1234, LIMITER, timeout=0.1)
    assert result.state is PortState.FILTERED


async def test_scan_host_sorted(make_server: ServerFactory) -> None:
    port_a = await make_server(_echo)
    port_b = await make_server(_echo)
    results = await portscan.scan_host("127.0.0.1", [port_b, port_a], LIMITER, timeout=2.0)
    assert [r.port for r in results] == sorted([port_a, port_b])
    assert all(r.state is PortState.OPEN for r in results)
