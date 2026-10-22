"""Identify the service behind an open port, regardless of the port number.

A powerful scanner does not assume port 8081 is HTTP just because it is near 8080, or that a
database has been left on its default port. This module classifies an open port by what it
actually speaks:

1. it reads whatever the service volunteers and matches the protocols that greet first (SSH,
   FTP, SMTP, POP3, IMAP, VNC, MySQL, Telnet);
2. if nothing is volunteered, it actively but gently probes -- a TLS handshake, then an HTTP
   request, then the client-first binary protocols (Redis, PostgreSQL, SMB, RDP);
3. the well-known port is used only as a last hint.

Every check is read-only and uses short-lived connections.
"""

from __future__ import annotations

import asyncio
import ssl
import struct
from dataclasses import dataclass

from .enum.tls import inspection_context
from .netutil import close_writer

# Well-known ports, used only when active detection is inconclusive.
PORT_HINTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtp",
    587: "smtp",
    993: "imap",
    995: "pop3",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
}


@dataclass(frozen=True, slots=True)
class Detection:
    kind: str
    tls: bool = False


def _classify_banner(data: bytes, port: int) -> str | None:
    if data.startswith(b"SSH-"):
        return "ssh"
    if data.startswith(b"RFB "):
        return "vnc"
    if data.startswith(b"+OK"):
        return "pop3"
    if data.startswith(b"* OK") or data.startswith(b"* PREAUTH"):
        return "imap"
    if data[:1] == b"\xff":
        return "telnet"
    if len(data) >= 5 and data[4] == 0x0A:  # MySQL handshake: protocol version 10
        return "mysql"
    if data.startswith(b"220"):
        upper = data.upper()
        if b"FTP" in upper and b"SMTP" not in upper:
            return "ftp"
        if b"SMTP" in upper or b"ESMTP" in upper:
            return "smtp"
        return "ftp" if port == 21 else "smtp"
    return None


async def _read_banner(host: str, port: int, timeout: float) -> bytes | None:
    """Open a connection and read whatever the service greets with, or None on failure."""

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError):
        return None
    try:
        return await asyncio.wait_for(reader.read(64), timeout=min(timeout, 1.5))
    except (OSError, TimeoutError):
        return b""
    finally:
        await close_writer(writer)


async def _is_tls(host: str, port: int, timeout: float) -> tuple[bool, bool]:
    """Return (is_tls, is_http_over_tls)."""

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=inspection_context(), server_hostname=None),
            timeout=timeout,
        )
    except (ssl.SSLError, OSError, TimeoutError):
        return False, False
    try:
        writer.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(16), timeout=timeout)
    except (OSError, ssl.SSLError, TimeoutError):
        reply = b""
    finally:
        await close_writer(writer)
    return True, reply.startswith(b"HTTP/")


async def _exchange(host: str, port: int, timeout: float, request: bytes) -> bytes:
    """Send one request and return the first bytes of the reply (empty on any failure)."""

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError):
        return b""
    try:
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(32), timeout=timeout)
    except (OSError, TimeoutError):
        return b""
    finally:
        await close_writer(writer)


async def _speaks(host: str, port: int, timeout: float, request: bytes, expect: bytes) -> bool:
    return expect in await _exchange(host, port, timeout, request)


def _smb2_negotiate() -> bytes:
    header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, b"\x00" * 16)
    body = struct.pack("<HHHHI16sQ", 36, 1, 1, 0, 0, b"\x00" * 16, 0) + struct.pack("<H", 0x0202)
    msg = header + body
    return struct.pack(">I", len(msg)) + msg


async def detect(host: str, port: int, timeout: float) -> Detection:
    """Classify the service behind an open port."""

    hint = PORT_HINTS.get(port)

    banner = await _read_banner(host, port, timeout)
    if banner:
        kind = _classify_banner(banner, port)
        if kind is not None:
            return Detection(kind=kind)

    # Nothing conclusive was volunteered: probe actively.
    is_tls, is_http = await _is_tls(host, port, timeout)
    if is_tls:
        return Detection(kind="https" if is_http else "tls", tls=True)

    if await _speaks(host, port, timeout, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n", b"HTTP/"):
        return Detection(kind="http")
    redis_reply = await _exchange(host, port, timeout, b"PING\r\n")
    if b"PONG" in redis_reply or b"NOAUTH" in redis_reply:
        return Detection(kind="redis")
    pg_reply = await _exchange(host, port, timeout, struct.pack(">II", 8, 80877103))
    if pg_reply[:1] in (b"S", b"N"):
        return Detection(kind="postgresql")
    if await _speaks(host, port, timeout, _smb2_negotiate(), b"\xfeSMB"):
        return Detection(kind="smb")

    return Detection(kind=hint or "unknown")
