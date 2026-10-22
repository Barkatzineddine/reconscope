"""Tests for the HTTP(S) probe."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable

from reconscope.enum import http
from reconscope.models import Severity
from tests.conftest import ServerFactory

_BODY = b"<html><head><title>  Hello   World </title></head><body>hi</body></html>"


def _responder(headers: bytes) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], object]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2.0)
        except (asyncio.IncompleteReadError, TimeoutError):
            pass
        resp = b"HTTP/1.1 200 OK\r\nServer: testsrv/1.0\r\n" + headers
        resp += b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(_BODY) + _BODY
        writer.write(resp)
        await writer.drain()
        writer.close()

    return handler


async def test_http_title_server_and_missing_headers(make_server: ServerFactory) -> None:
    port = await make_server(_responder(b""))
    service, findings = await http.probe("127.0.0.1", port, timeout=2.0, use_tls=False)
    assert service.name == "http"
    assert service.details["status_line"] == "HTTP/1.1 200 OK"
    assert service.details["server"] == "testsrv/1.0"
    assert service.details["title"] == "Hello World"
    titles = {f.title for f in findings}
    assert "Missing content-security-policy header" in titles
    # HSTS is not flagged over plaintext HTTP.
    assert "Missing strict-transport-security header" not in titles


async def test_http_all_headers_present(make_server: ServerFactory) -> None:
    headers = (
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Referrer-Policy: no-referrer\r\n"
    )
    port = await make_server(_responder(headers))
    service, findings = await http.probe("127.0.0.1", port, timeout=2.0, use_tls=False)
    assert findings == []
    assert set(service.details["security_headers_present"]) >= {
        "content-security-policy",
        "x-frame-options",
    }


async def test_https_flags_missing_hsts(
    make_server: ServerFactory, tls_context: Callable[..., ssl.SSLContext]
) -> None:
    port = await make_server(_responder(b""), tls_context())
    service, findings = await http.probe("127.0.0.1", port, timeout=3.0, use_tls=True)
    assert service.name == "https"
    titles = {f.title for f in findings}
    assert "Missing strict-transport-security header" in titles
    assert any(f.severity is Severity.MEDIUM for f in findings)


async def test_http_connection_failure() -> None:
    service, findings = await http.probe("127.0.0.1", 1, timeout=1.0, use_tls=False)
    assert "error" in service.details
    assert findings == []
