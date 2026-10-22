"""FTP probe: banner and advertised features (read-only, no authentication).

The scanner reads the greeting and asks the server for its feature list with ``FEAT`` -- a
command that needs no login. From that it reports the software banner and whether the control
channel can be upgraded to TLS (``AUTH TLS``); a plain FTP service that cannot is worth noting.
"""

from __future__ import annotations

import asyncio

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer, decode_banner


async def _read_reply(reader: asyncio.StreamReader, timeout: float) -> list[str]:
    """Read a (possibly multi-line) FTP reply, ending when a line is 'NNN ...' not 'NNN-...'."""

    lines: list[str] = []
    for _ in range(40):
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not raw:
            break
        line = raw.decode("latin-1", errors="replace").rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[3] == " " and line[:3].isdigit():
            break
    return lines


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="ftp")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        greeting = await _read_reply(reader, timeout)
        service.banner = decode_banner(greeting[0].encode()) if greeting else None
        service.product = service.banner

        writer.write(b"FEAT\r\n")
        await writer.drain()
        feat = await _read_reply(reader, timeout)
        # Keep the feature lines between the '211-Features:' header and the '211 End' trailer.
        features = [line.strip() for line in feat[1:-1] if line.strip()]
        service.details["features"] = features

        writer.write(b"QUIT\r\n")
        await writer.drain()
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    tls_supported = any("AUTH TLS" in f.upper() or "AUTH SSL" in f.upper() for f in features)
    service.details["tls_supported"] = tls_supported
    findings: list[Finding] = []
    if not tls_supported:
        findings.append(
            Finding(
                Severity.MEDIUM,
                "FTP without TLS",
                "The server does not advertise AUTH TLS; credentials and data travel in clear text.",
            )
        )
    return service, findings
