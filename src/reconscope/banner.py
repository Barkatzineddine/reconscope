"""Generic banner grab for an open port with no dedicated protocol probe.

Many services announce themselves the moment a client connects (SMTP, FTP, some custom TCP
services). We read whatever the service volunteers within a short window; we do not send a
payload, so this stays a passive read.
"""

from __future__ import annotations

import asyncio

from .models import ServiceInfo
from .netutil import close_writer, decode_banner, open_tcp

# A short, well-known map from port to the service usually found there. Used only as a label
# when no banner is returned; it never changes which probe runs.
COMMON_SERVICES: dict[int, str] = {
    21: "ftp",
    25: "smtp",
    110: "pop3",
    143: "imap",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
}


async def probe(host: str, port: int, timeout: float) -> ServiceInfo:
    """Read an initial banner, if the service sends one."""

    name = COMMON_SERVICES.get(port, "unknown")
    try:
        reader, writer = await open_tcp(host, port, timeout)
    except (OSError, TimeoutError):
        return ServiceInfo(name=name)
    try:
        raw = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (OSError, TimeoutError):
        raw = b""
    finally:
        await close_writer(writer)

    banner = decode_banner(raw)
    return ServiceInfo(name=name, banner=banner or None)
