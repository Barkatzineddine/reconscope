"""Telnet probe: presence detection.

Telnet carries logins and sessions in clear text, so simply finding it open is the finding.
The scanner reads the initial option-negotiation bytes (which a Telnet server sends first) to
confirm the protocol, and reports any readable login banner. It sends nothing and never logs in.
"""

from __future__ import annotations

import asyncio

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

_IAC = 0xFF


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="telnet")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        raw = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (OSError, TimeoutError):
        raw = b""
    finally:
        await close_writer(writer)

    negotiated = bool(raw) and raw[0] == _IAC
    service.details["negotiated"] = negotiated
    # Strip the IAC option-negotiation triplets to leave any human-readable banner text.
    text = bytes(b for b in raw if 0x20 <= b < 0x7F).decode("ascii", errors="replace").strip()
    if text:
        service.banner = text[:200]

    findings = [
        Finding(
            Severity.MEDIUM,
            "Telnet enabled (clear text)",
            "Telnet carries logins and session data without encryption and should be replaced by SSH.",
        )
    ]
    return service, findings
