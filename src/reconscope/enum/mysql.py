"""MySQL/MariaDB probe: read the initial handshake (read-only, no login).

A MySQL server sends a handshake packet the moment a client connects, before any
authentication. It names the server version and, in its capability flags, whether it can
negotiate TLS. The scanner reads just that packet and reports the version and TLS capability.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

_CLIENT_SSL = 0x0800
_PROTOCOL_V10 = 10


def _parse_handshake(packet: bytes) -> dict[str, object] | None:
    if len(packet) < 5:
        return None
    length = int.from_bytes(packet[0:3], "little")
    payload = packet[4 : 4 + length]
    if not payload or payload[0] != _PROTOCOL_V10:
        return None
    end = payload.find(b"\x00", 1)
    if end == -1:
        return None
    version = payload[1:end].decode("latin-1", errors="replace")
    # After the version string: connection id (4) + auth-plugin-data (8) + filler (1) = 13 bytes,
    # then the lower 16 bits of the capability flags.
    cap_offset = end + 1 + 13
    if len(payload) < cap_offset + 2:
        return {"version": version, "tls_capable": None}
    (cap_lower,) = struct.unpack_from("<H", payload, cap_offset)
    return {"version": version, "tls_capable": bool(cap_lower & _CLIENT_SSL)}


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="mysql")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        packet = await asyncio.wait_for(reader.read(512), timeout=timeout)
    except (OSError, TimeoutError):
        packet = b""
    finally:
        await close_writer(writer)

    parsed = _parse_handshake(packet)
    if parsed is None:
        service.details["error"] = "no MySQL handshake"
        return service, []

    version = str(parsed["version"])
    service.product = f"MySQL/MariaDB {version}"
    service.details["version"] = version
    service.details["tls_capable"] = parsed["tls_capable"]
    findings: list[Finding] = []
    if parsed["tls_capable"] is False:
        findings.append(
            Finding(
                Severity.MEDIUM,
                "MySQL without TLS capability",
                "The server does not advertise SSL/TLS support; connections would be in clear text.",
            )
        )
    return service, findings
