"""HTTP(S) probe: one GET request, then report what a defender cares about.

We send a single ``GET /`` with a clear ``User-Agent`` and read the status line, the response
headers and just enough of the body to find the page title. From the headers we flag the
common security headers that are missing -- the kind of quick hygiene check that belongs in an
authorized assessment.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer
from .tls import inspection_context

_USER_AGENT = "reconscope/1.0 (+authorized-assessment)"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Security headers every site should set, with the severity of their absence.
_SECURITY_HEADERS: dict[str, Severity] = {
    "strict-transport-security": Severity.MEDIUM,
    "content-security-policy": Severity.MEDIUM,
    "x-content-type-options": Severity.LOW,
    "x-frame-options": Severity.LOW,
    "referrer-policy": Severity.LOW,
}


def _parse_headers(head: bytes) -> tuple[str, dict[str, str]]:
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", errors="replace") if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return status_line, headers


def _extract_title(body: bytes) -> str | None:
    match = _TITLE_RE.search(body)
    if not match:
        return None
    title = match.group(1).decode("utf-8", errors="replace")
    return re.sub(r"\s+", " ", title).strip()[:200] or None


def _missing_header_findings(headers: dict[str, str], use_tls: bool) -> list[Finding]:
    findings: list[Finding] = []
    for header, severity in _SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not use_tls:
            continue  # HSTS is only meaningful over HTTPS.
        if header not in headers:
            findings.append(
                Finding(severity, f"Missing {header} header", f"The response did not set '{header}'.")
            )
    return findings


async def probe(
    host: str, port: int, timeout: float, use_tls: bool, server_name: str | None = None
) -> tuple[ServiceInfo, list[Finding]]:
    """Fetch the home page and summarise the server, title and security headers."""

    service = ServiceInfo(name="https" if use_tls else "http")
    ssl_ctx = inspection_context() if use_tls else None
    host_header = server_name or host
    request = (
        f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
        f"User-Agent: {_USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("latin-1")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ssl_ctx, server_hostname=server_name if use_tls else None
            ),
            timeout=timeout,
        )
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        writer.write(request)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(65536), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    head, _, body = raw.partition(b"\r\n\r\n")
    status_line, headers = _parse_headers(head)

    details: dict[str, Any] = {"status_line": status_line, "server": headers.get("server")}
    title = _extract_title(body)
    if title:
        details["title"] = title
    present = [h for h in _SECURITY_HEADERS if h in headers]
    details["security_headers_present"] = present
    service.details = details
    service.product = headers.get("server")
    service.banner = status_line or None

    return service, _missing_header_findings(headers, use_tls)
