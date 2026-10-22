"""Tests for the binary-handshake probes: MySQL, PostgreSQL, VNC, RDP."""

from __future__ import annotations

import asyncio
import struct

from reconscope.enum import mysql, postgres, rdp, vnc
from reconscope.models import Severity
from tests.conftest import ServerFactory


def _mysql_handshake(version: str, ssl: bool) -> bytes:
    payload = bytes([10]) + version.encode() + b"\x00"
    payload += b"\x00\x00\x00\x00"  # connection id
    payload += b"\x00" * 8  # auth-plugin-data part 1
    payload += b"\x00"  # filler
    payload += struct.pack("<H", 0x0800 if ssl else 0x0000)  # capability flags (lower)
    payload += b"\x00" * 10  # charset, status, upper caps, ...
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


async def test_mysql_version_and_no_tls(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(_mysql_handshake("8.0.36", ssl=False))
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await mysql.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["version"] == "8.0.36"
    assert service.details["tls_capable"] is False
    assert any("MySQL without TLS" in f.title for f in findings)


async def test_mysql_with_tls_clean(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(_mysql_handshake("10.11.6-MariaDB", ssl=True))
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await mysql.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["tls_capable"] is True
    assert findings == []


async def test_postgres_no_tls_flagged(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readexactly(8)  # SSLRequest
        writer.write(b"N")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await postgres.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["tls_supported"] is False
    assert any(f.severity is Severity.MEDIUM for f in findings)


async def test_postgres_tls_supported_clean(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readexactly(8)
        writer.write(b"S")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await postgres.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["tls_supported"] is True
    assert findings == []


def _vnc_server(types: list[int], minor: int = 8):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"RFB 003.%03d\n" % minor)
        await writer.drain()
        await reader.readexactly(12)  # client version
        if minor >= 7:
            writer.write(bytes([len(types), *types]))
        else:
            writer.write(struct.pack(">I", types[0]))
        await writer.drain()
        writer.close()

    return handler


async def test_vnc_none_auth_flagged(make_server: ServerFactory) -> None:
    port = await make_server(_vnc_server([2, 1]))
    service, findings = await vnc.probe("127.0.0.1", port, timeout=2.0)
    assert "none" in service.details["security_types"]
    assert any(f.severity is Severity.HIGH for f in findings)


async def test_vnc_vnc_auth_clean(make_server: ServerFactory) -> None:
    port = await make_server(_vnc_server([2]))
    service, findings = await vnc.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["security_types"] == ["vnc"]
    assert findings == []


async def test_vnc_legacy_33_none(make_server: ServerFactory) -> None:
    port = await make_server(_vnc_server([1], minor=3))
    service, findings = await vnc.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["protocol"] == "3.3"
    assert any(f.severity is Severity.HIGH for f in findings)


def _rdp_response(selected: int) -> bytes:
    neg = struct.pack("<BBHI", 2, 0, 8, selected)  # RDP_NEG_RSP
    x224_body = b"\xd0\x00\x00\x00\x00\x00" + neg
    x224 = bytes([len(x224_body)]) + x224_body
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def _rdp_server(selected: int):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.wait_for(reader.read(64), timeout=1.0)  # connection request
        writer.write(_rdp_response(selected))
        await writer.drain()
        writer.close()

    return handler


async def test_rdp_standard_security_flagged(make_server: ServerFactory) -> None:
    port = await make_server(_rdp_server(0))  # PROTOCOL_RDP
    service, findings = await rdp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["selected_protocol"] == "standard-rdp"
    assert any("standard security" in f.title for f in findings)


async def test_rdp_nla_clean(make_server: ServerFactory) -> None:
    port = await make_server(_rdp_server(2))  # CredSSP / NLA
    service, findings = await rdp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["selected_protocol"] == "credssp-nla"
    assert service.details["nla"] is True
    assert findings == []


async def test_rdp_not_rdp() -> None:
    service, findings = await rdp.probe("127.0.0.1", 1, timeout=1.0)
    assert "error" in service.details
    assert findings == []
