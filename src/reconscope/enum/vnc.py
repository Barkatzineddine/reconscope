"""VNC (RFB) probe: version and the authentication types the server offers.

An RFB server sends its protocol version first; the client echoes a version and the server then
lists the security types it will accept. Security type 1 means *no authentication at all*, so a
server that offers it exposes the desktop to anyone who can reach it. The scanner reads the
offered types and stops there -- it never authenticates and never sends input.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

_SEC_NONE = 1
_SEC_NAMES = {0: "invalid", 1: "none", 2: "vnc", 16: "tight", 18: "tls", 19: "vencrypt", 30: "apple-ard"}


def _parse_version(banner: bytes) -> tuple[int, int] | None:
    # Format: "RFB 003.008\n"
    if len(banner) < 12 or not banner.startswith(b"RFB "):
        return None
    try:
        major = int(banner[4:7])
        minor = int(banner[8:11])
    except ValueError:
        return None
    return major, minor


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="vnc")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        banner = await asyncio.wait_for(reader.readexactly(12), timeout=timeout)
        version = _parse_version(banner)
        if version is None:
            service.details["error"] = "not an RFB server"
            await close_writer(writer)
            return service, []
        major, minor = version
        service.product = f"RFB {major}.{minor}"
        service.details["protocol"] = f"{major}.{minor}"

        writer.write(banner)  # echo the server's version to advance the handshake
        await writer.drain()

        if minor >= 7:
            count_raw = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            count = count_raw[0]
            if count == 0:
                service.details["error"] = "server refused the connection"
                await close_writer(writer)
                return service, []
            types = list(await asyncio.wait_for(reader.readexactly(count), timeout=timeout))
        else:
            # RFB 3.3: a single 4-byte security type instead of a list.
            (single,) = struct.unpack(">I", await asyncio.wait_for(reader.readexactly(4), timeout=timeout))
            types = [single]
    except (OSError, TimeoutError, asyncio.IncompleteReadError, struct.error) as exc:
        service.details["error"] = f"handshake failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    service.details["security_types"] = [_SEC_NAMES.get(t, str(t)) for t in types]
    findings: list[Finding] = []
    if _SEC_NONE in types:
        findings.append(
            Finding(
                Severity.HIGH,
                "VNC without authentication",
                "The server offers security type 'None': the desktop is reachable with no password.",
            )
        )
    return service, findings
