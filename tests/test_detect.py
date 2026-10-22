"""Tests for the port-independent service detection layer."""

from __future__ import annotations

import asyncio
import ssl
import struct
from collections.abc import Callable

import pytest

from reconscope import detect
from reconscope.detect import Detection, _classify_banner
from tests.conftest import ServerFactory

TLSFactory = Callable[..., ssl.SSLContext]


def _greeter(banner: bytes):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(banner)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    return handler


def test_classify_banner_table() -> None:
    assert _classify_banner(b"SSH-2.0-OpenSSH", 22) == "ssh"
    assert _classify_banner(b"RFB 003.008\n", 5900) == "vnc"
    assert _classify_banner(b"+OK POP3 ready", 110) == "pop3"
    assert _classify_banner(b"* OK IMAP", 143) == "imap"
    assert _classify_banner(b"\xff\xfd\x18", 23) == "telnet"
    assert _classify_banner(b"\x0a\x00\x00\x00\x0a8.0\x00", 3306) == "mysql"
    assert _classify_banner(b"220 ready (FTP)", 21) == "ftp"
    assert _classify_banner(b"220 mail ESMTP Postfix", 25) == "smtp"
    assert _classify_banner(b"220 ambiguous", 21) == "ftp"
    assert _classify_banner(b"220 ambiguous", 25) == "smtp"
    assert _classify_banner(b"random noise", 9999) is None


async def test_detect_ssh_by_banner(make_server: ServerFactory) -> None:
    port = await make_server(_greeter(b"SSH-2.0-OpenSSH_9.6\r\n"))
    assert (await detect.detect("127.0.0.1", port, timeout=2.0)).kind == "ssh"


async def test_detect_mysql_by_handshake(make_server: ServerFactory) -> None:
    packet = struct.pack("<I", 10)[:3] + b"\x00" + bytes([10]) + b"8.0.0\x00rest"
    port = await make_server(_greeter(packet))
    assert (await detect.detect("127.0.0.1", port, timeout=2.0)).kind == "mysql"


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        data = await asyncio.wait_for(reader.read(128), timeout=0.8)
    except (TimeoutError, OSError):
        data = b""
    if data.startswith((b"GET", b"HEAD")):
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
    writer.close()


async def test_detect_http_actively(make_server: ServerFactory) -> None:
    port = await make_server(_http_handler)
    assert (await detect.detect("127.0.0.1", port, timeout=2.0)).kind == "http"


async def test_detect_tls_and_https(make_server: ServerFactory, tls_context: TLSFactory) -> None:
    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.read(16), timeout=0.8)
        except (TimeoutError, OSError):
            pass
        writer.close()

    tls_port = await make_server(accept, tls_context())
    detection = await detect.detect("127.0.0.1", tls_port, timeout=3.0)
    assert detection.kind == "tls"
    assert detection.tls is True

    https_port = await make_server(_http_handler, tls_context())
    assert (await detect.detect("127.0.0.1", https_port, timeout=3.0)).kind == "https"


async def test_detect_redis_actively(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=0.8)
        except (TimeoutError, OSError):
            line = b""
        if line.startswith(b"PING"):
            writer.write(b"+PONG\r\n")
            await writer.drain()
        writer.close()

    port = await make_server(handler)
    assert (await detect.detect("127.0.0.1", port, timeout=2.0)).kind == "redis"


async def test_detect_unknown_and_hint(make_server: ServerFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.read(8), timeout=0.6)
        except (TimeoutError, OSError):
            pass
        writer.close()

    port = await make_server(silent)
    assert (await detect.detect("127.0.0.1", port, timeout=1.5)).kind == "unknown"

    monkeypatch.setitem(detect.PORT_HINTS, port, "mssql")
    assert (await detect.detect("127.0.0.1", port, timeout=1.5)) == Detection(kind="mssql")
