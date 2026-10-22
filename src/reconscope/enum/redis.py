"""Redis probe: detect an unauthenticated instance.

Redis speaks a simple text protocol. The scanner sends ``PING``; a ``+PONG`` without being
asked for a password means the instance is reachable with no authentication -- a serious
exposure, since Redis then allows reads, writes and, on many builds, command execution. When
that is the case the scanner also reads ``INFO server`` to report the version. A ``-NOAUTH``
reply means authentication is required, which is reported without a finding.
"""

from __future__ import annotations

import asyncio

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer


def _parse_version(info: str) -> str | None:
    for line in info.splitlines():
        if line.startswith("redis_version:"):
            return line.split(":", 1)[1].strip()
    return None


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="redis")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    findings: list[Finding] = []
    try:
        writer.write(b"PING\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(128), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []

    text = reply.decode("latin-1", errors="replace")
    if text.startswith("-NOAUTH") or "NOAUTH" in text:
        service.details["authentication"] = "required"
        await close_writer(writer)
        return service, findings

    if text.startswith("+PONG"):
        service.details["authentication"] = "none"
        try:
            writer.write(b"INFO server\r\n")
            await writer.drain()
            info_raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        except (OSError, TimeoutError):
            info_raw = b""
        version = _parse_version(info_raw.decode("latin-1", errors="replace"))
        if version:
            service.product = f"Redis {version}"
            service.details["version"] = version
        findings.append(
            Finding(
                Severity.HIGH,
                "Unauthenticated Redis",
                "The server answered PING (and INFO) with no authentication; it is fully exposed.",
            )
        )
    else:
        service.details["reply"] = text.strip()[:80]

    await close_writer(writer)
    return service, findings
