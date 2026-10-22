"""Tests for the SSH banner and algorithm probe."""

from __future__ import annotations

import asyncio
import struct

from reconscope.enum import ssh
from reconscope.models import Severity
from tests.conftest import ServerFactory


def _name_list(items: list[str]) -> bytes:
    raw = ",".join(items).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def _kexinit(kex: list[str], hostkey: list[str], enc: list[str], mac: list[str]) -> bytes:
    payload = bytes([ssh._SSH_MSG_KEXINIT]) + b"\x00" * 16
    payload += _name_list(kex)
    payload += _name_list(hostkey)
    payload += _name_list(enc) + _name_list(enc)
    payload += _name_list(mac) + _name_list(mac)
    payload += _name_list(["none"]) + _name_list(["none"])
    payload += _name_list([]) + _name_list([])
    payload += b"\x00" + struct.pack(">I", 0)

    block = 8
    unpadded = 4 + 1 + len(payload)
    pad = block - (unpadded % block)
    if pad < 4:
        pad += block
    packet_length = 1 + len(payload) + pad
    return struct.pack(">I", packet_length) + bytes([pad]) + payload + b"\x00" * pad


def _server(frame: bytes | None, banner: bytes = b"SSH-2.0-OpenSSH_9.6\r\n"):  # type: ignore[no-untyped-def]
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(banner)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.readline(), timeout=1.0)  # client identification
        except (TimeoutError, OSError):
            pass
        if frame is not None:
            writer.write(frame)
            await writer.drain()
        writer.close()

    return handler


async def test_weak_algorithms_flagged(make_server: ServerFactory) -> None:
    frame = _kexinit(
        kex=["diffie-hellman-group14-sha1", "curve25519-sha256"],
        hostkey=["ssh-rsa", "ssh-ed25519"],
        enc=["aes128-cbc", "aes256-gcm@openssh.com"],
        mac=["hmac-sha1", "hmac-sha2-256"],
    )
    port = await make_server(_server(frame))
    service, findings = await ssh.probe("127.0.0.1", port, timeout=2.0)
    assert service.banner == "SSH-2.0-OpenSSH_9.6"
    titles = {f.title for f in findings}
    assert "Weak SSH key exchange algorithm offered" in titles
    assert "Weak SSH host key algorithm offered" in titles
    assert "Weak SSH cipher algorithm offered" in titles
    assert "Weak SSH MAC algorithm offered" in titles
    assert any(f.severity is Severity.MEDIUM for f in findings)
    assert service.details["algorithms"]["kex_algorithms"][0].startswith("diffie-hellman")


async def test_modern_algorithms_clean(make_server: ServerFactory) -> None:
    frame = _kexinit(
        kex=["curve25519-sha256"],
        hostkey=["rsa-sha2-512", "ssh-ed25519"],
        enc=["chacha20-poly1305@openssh.com"],
        mac=["hmac-sha2-256"],
    )
    port = await make_server(_server(frame))
    _, findings = await ssh.probe("127.0.0.1", port, timeout=2.0)
    assert findings == []


async def test_no_kexinit_packet(make_server: ServerFactory) -> None:
    port = await make_server(_server(None))
    service, findings = await ssh.probe("127.0.0.1", port, timeout=2.0)
    assert findings == []
    assert "algorithms" not in service.details


async def test_connection_failure() -> None:
    service, findings = await ssh.probe("127.0.0.1", 1, timeout=1.0)
    assert "error" in service.details
    assert findings == []
