"""Tests for the SMB dialect and signing probe."""

from __future__ import annotations

import asyncio
import struct

from reconscope.enum import smb
from reconscope.models import Severity
from tests.conftest import ServerFactory

_SIGNING_REQUIRED = 0x0002


def _framed(message: bytes) -> bytes:
    return struct.pack(">I", len(message)) + message


def _smb2_response(dialect: int, security_mode: int) -> bytes:
    header = b"\xfeSMB" + b"\x00" * 60
    body = struct.pack("<HHH", 65, security_mode, dialect) + b"\x00" * 58
    return _framed(header + body)


def _smb1_response(dialect_index: int) -> bytes:
    header = b"\xffSMB" + b"\x00" * 28
    body = bytes([1]) + struct.pack("<H", dialect_index) + b"\x00" * 10
    return _framed(header + body)


def _server(*, dialect: int, security_mode: int, smbv1_index: int | None):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
            (length,) = struct.unpack(">I", header)
            message = await asyncio.wait_for(reader.readexactly(length), timeout=1.0)
        except (asyncio.IncompleteReadError, TimeoutError, OSError):
            writer.close()
            return
        if message[:4] == b"\xfeSMB":
            writer.write(_smb2_response(dialect, security_mode))
        elif message[:4] == b"\xffSMB" and smbv1_index is not None:
            writer.write(_smb1_response(smbv1_index))
        await writer.drain()
        writer.close()

    return handler


async def test_smbv1_and_no_signing(make_server: ServerFactory) -> None:
    port = await make_server(_server(dialect=0x0311, security_mode=0x0001, smbv1_index=0))
    service, findings = await smb.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["max_dialect"] == "SMB 3.1.1"
    assert service.details["signing_required"] is False
    assert service.details["smbv1_enabled"] is True
    titles = {f.title for f in findings}
    assert "Legacy SMBv1 enabled" in titles
    assert "SMB signing not required" in titles
    assert any(f.severity is Severity.HIGH for f in findings)


async def test_modern_and_signing_required(make_server: ServerFactory) -> None:
    port = await make_server(_server(dialect=0x0302, security_mode=_SIGNING_REQUIRED, smbv1_index=0xFFFF))
    service, findings = await smb.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["max_dialect"] == "SMB 3.0.2"
    assert service.details["signing_required"] is True
    assert service.details["smbv1_enabled"] is False
    assert findings == []


async def test_unknown_dialect_number(make_server: ServerFactory) -> None:
    port = await make_server(_server(dialect=0x02FF, security_mode=_SIGNING_REQUIRED, smbv1_index=0xFFFF))
    service, _ = await smb.probe("127.0.0.1", port, timeout=2.0)
    assert service.details["max_dialect"] == "0x02ff"


async def test_no_smb_response(make_server: ServerFactory) -> None:
    async def closer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    port = await make_server(closer)
    service, findings = await smb.probe("127.0.0.1", port, timeout=1.0)
    assert service.details.get("error") == "no SMB negotiation response"
    assert findings == []
