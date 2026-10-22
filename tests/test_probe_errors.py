"""Error-path and malformed-response coverage for the protocol probes and detection."""

from __future__ import annotations

import asyncio
import struct

import pytest

from reconscope import detect
from reconscope.enum import ftp, mysql, postgres, rdp, smtp, telnet, vnc
from tests.conftest import ServerFactory

CONN_FAILERS = [ftp.probe, smtp.probe, telnet.probe, mysql.probe, postgres.probe, vnc.probe]


@pytest.mark.parametrize("probe", CONN_FAILERS)
async def test_connection_failure(probe: object, monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(*_a: object, **_k: object) -> None:
        raise ConnectionRefusedError

    monkeypatch.setattr("asyncio.open_connection", refuse)
    service, findings = await probe("127.0.0.1", 1234, timeout=0.5)  # type: ignore[operator]
    assert "error" in service.details
    assert findings == []


async def test_mysql_junk_response(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"not a mysql handshake")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await mysql.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["error"] == "no MySQL handshake"
    assert findings == []


async def test_postgres_unexpected_reply(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readexactly(8)
        writer.write(b"X")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await postgres.probe("127.0.0.1", port, timeout=2.0)
    assert "error" in service.details
    assert findings == []


async def test_vnc_not_rfb(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200")
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await vnc.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["error"] == "not an RFB server"
    assert findings == []


async def test_vnc_server_refuses(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        await reader.readexactly(12)
        writer.write(b"\x00" + struct.pack(">I", 3) + b"no!")  # zero security types + reason
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await vnc.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["error"] == "server refused the connection"
    assert findings == []


def _rdp_frame(payload: bytes) -> bytes:
    x224 = bytes([len(b"\xd0\x00\x00\x00\x00\x00" + payload)]) + b"\xd0\x00\x00\x00\x00\x00" + payload
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


async def test_rdp_negotiation_failure(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.wait_for(reader.read(64), timeout=1.0)
        writer.write(_rdp_frame(struct.pack("<BBHI", 3, 0, 8, 5)))  # TYPE_RDP_NEG_FAILURE
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await rdp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["negotiation_failure"] == 5
    assert findings == []


async def test_rdp_no_negotiation(make_server: ServerFactory) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.wait_for(reader.read(64), timeout=1.0)
        writer.write(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00")  # CC with no RDP negotiation
        await writer.drain()
        writer.close()

    port = await make_server(handler)
    service, findings = await rdp.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["security"] == "standard-rdp"
    assert any("standard security" in f.title for f in findings)


async def test_detect_all_probes_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(*_a: object, **_k: object) -> None:
        raise ConnectionRefusedError

    monkeypatch.setattr("asyncio.open_connection", refuse)
    assert (await detect.detect("127.0.0.1", 1234, timeout=0.5)).kind == "unknown"
