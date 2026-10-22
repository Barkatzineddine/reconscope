"""SMTP probe: banner and ESMTP capabilities (read-only, no mail sent).

The scanner reads the greeting, says ``EHLO`` and lists the capabilities the server advertises.
From those it reports the software and whether ``STARTTLS`` is offered; a mail server that
cannot upgrade to TLS exposes credentials and mail in clear text.
"""

from __future__ import annotations

import asyncio

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer, decode_banner


async def _read_reply(reader: asyncio.StreamReader, timeout: float) -> list[str]:
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
    service = ServiceInfo(name="smtp")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        greeting = await _read_reply(reader, timeout)
        service.banner = decode_banner(greeting[0].encode()) if greeting else None
        service.product = service.banner

        writer.write(b"EHLO reconscope.invalid\r\n")
        await writer.drain()
        ehlo = await _read_reply(reader, timeout)
        # Capabilities are the text after the status code on each 250 line, except the greeting.
        caps = sorted({line[4:].strip().upper() for line in ehlo[1:] if len(line) > 4})
        service.details["capabilities"] = caps

        writer.write(b"QUIT\r\n")
        await writer.drain()
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    starttls = any(cap.startswith("STARTTLS") for cap in service.details.get("capabilities", []))
    service.details["starttls"] = starttls
    findings: list[Finding] = []
    if not starttls:
        findings.append(
            Finding(
                Severity.MEDIUM,
                "SMTP without STARTTLS",
                "The server does not offer STARTTLS; mail and credentials can travel in clear text.",
            )
        )
    return service, findings
