"""Small async networking helpers shared by the scanner and the protocol probes."""

from __future__ import annotations

import asyncio
import contextlib


async def open_tcp(host: str, port: int, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection, raising ``TimeoutError`` if it does not connect in ``timeout``."""

    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


async def close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a writer without letting a late error from the peer surface."""

    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)


def decode_banner(raw: bytes) -> str:
    """Turn raw bytes from a service into a short, printable, single-line banner."""

    text = raw.decode("utf-8", errors="replace").strip()
    text = text.splitlines()[0] if text else ""
    return text[:200]
