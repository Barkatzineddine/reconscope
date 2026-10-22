"""Tests for the generic banner grab."""

from __future__ import annotations

import asyncio

from reconscope import banner
from tests.conftest import ServerFactory


async def _greeter(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(b"220 smtp.test ESMTP ready\r\nsecond line\r\n")
    await writer.drain()
    writer.close()


async def _silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()


async def test_reads_banner_first_line(make_server: ServerFactory) -> None:
    port = await make_server(_greeter)
    service = await banner.probe("127.0.0.1", port, timeout=2.0)
    assert service.banner == "220 smtp.test ESMTP ready"


async def test_known_port_name_without_banner(make_server: ServerFactory) -> None:
    port = await make_server(_silent)
    service = await banner.probe("127.0.0.1", port, timeout=2.0)
    assert service.banner is None
    assert service.name == "unknown"


async def test_connection_failure_returns_label() -> None:
    service = await banner.probe("127.0.0.1", 1, timeout=1.0)
    assert service.name == "unknown"
    assert service.banner is None
