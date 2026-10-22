"""Tests for the line-based probes: FTP, SMTP, Telnet, Redis."""

from __future__ import annotations

import asyncio

from reconscope.enum import ftp, redis, smtp, telnet
from reconscope.models import Severity
from tests.conftest import ServerFactory


def _ftp_server(with_tls: bool):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 Test FTP Server ready\r\n")
        await writer.drain()
        await reader.readline()  # FEAT
        feat = b"211-Features:\r\n MDTM\r\n UTF8\r\n"
        if with_tls:
            feat += b" AUTH TLS\r\n"
        feat += b"211 End\r\n"
        writer.write(feat)
        await writer.drain()
        await reader.readline()  # QUIT
        writer.close()

    return handler


async def test_ftp_without_tls_flagged(make_server: ServerFactory) -> None:
    port = await make_server(_ftp_server(with_tls=False))
    service, findings = await ftp.probe("127.0.0.1", port, timeout=2.0)
    assert service.name == "ftp"
    assert service.banner == "220 Test FTP Server ready"
    assert "MDTM" in service.details["features"]
    assert service.details["tls_supported"] is False
    assert any("FTP without TLS" in f.title for f in findings)


async def test_ftp_with_tls_clean(make_server: ServerFactory) -> None:
    port = await make_server(_ftp_server(with_tls=True))
    service, findings = await ftp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["tls_supported"] is True
    assert findings == []


def _smtp_server(with_starttls: bool):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 mail.test ESMTP Postfix\r\n")
        await writer.drain()
        await reader.readline()  # EHLO
        reply = b"250-mail.test\r\n"
        if with_starttls:
            reply += b"250-STARTTLS\r\n"
        reply += b"250 SIZE 10240000\r\n"
        writer.write(reply)
        await writer.drain()
        await reader.readline()  # QUIT
        writer.close()

    return handler


async def test_smtp_without_starttls_flagged(make_server: ServerFactory) -> None:
    port = await make_server(_smtp_server(with_starttls=False))
    service, findings = await smtp.probe("127.0.0.1", port, timeout=2.0)
    assert service.name == "smtp"
    assert service.details["starttls"] is False
    assert any(f.severity is Severity.MEDIUM for f in findings)


async def test_smtp_with_starttls_clean(make_server: ServerFactory) -> None:
    port = await make_server(_smtp_server(with_starttls=True))
    service, findings = await smtp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["starttls"] is True
    assert findings == []


async def test_telnet_always_flagged(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"\xff\xfd\x18\xff\xfd\x1flogin: ")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await telnet.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["negotiated"] is True
    assert "login:" in (service.banner or "")
    assert any("Telnet" in f.title for f in findings)


async def test_redis_unauthenticated_flagged(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n")  # PING
        writer.write(b"+PONG\r\n")
        await writer.drain()
        await reader.readuntil(b"\r\n")  # INFO server
        info = b"# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
        writer.write(b"$%d\r\n%s\r\n" % (len(info), info))
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await redis.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["authentication"] == "none"
    assert service.details["version"] == "7.2.4"
    assert any(f.severity is Severity.HIGH for f in findings)


async def test_redis_auth_required_clean(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n")
        writer.write(b"-NOAUTH Authentication required.\r\n")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await redis.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["authentication"] == "required"
    assert findings == []


async def test_redis_connection_failure() -> None:
    service, findings = await redis.probe("127.0.0.1", 1, timeout=1.0)
    assert "error" in service.details
    assert findings == []
