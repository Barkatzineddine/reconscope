"""PostgreSQL probe: ask whether the server supports TLS (read-only, no login).

PostgreSQL has a dedicated, pre-authentication ``SSLRequest`` message: the server answers a
single byte, ``S`` if it is willing to use TLS or ``N`` if it is not. The scanner sends that
message and reports the answer; a server that cannot do TLS carries credentials and queries in
clear text.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

# Int32 length (8) followed by the SSLRequest magic code 1234.5679 (80877103).
_SSL_REQUEST = struct.pack(">II", 8, 80877103)


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="postgresql")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        writer.write(_SSL_REQUEST)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(1), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    if reply == b"S":
        service.details["tls_supported"] = True
        return service, []
    if reply == b"N":
        service.details["tls_supported"] = False
        return service, [
            Finding(
                Severity.MEDIUM,
                "PostgreSQL without TLS",
                "The server declined an SSLRequest; connections would travel in clear text.",
            )
        ]
    service.details["error"] = "unexpected SSLRequest reply"
    return service, []
