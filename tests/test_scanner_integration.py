"""End-to-end scans against real local servers, exercising detection dispatch."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import Callable

import pytest

from reconscope.models import Finding
from reconscope.scanner import ScanConfig, run_scan
from reconscope.scope import Scope
from tests.conftest import ServerFactory

TLSFactory = Callable[..., ssl.SSLContext]


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(target: str, timeout: float) -> tuple[dict[str, list[str]], list[Finding]]:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return {"A": ["127.0.0.1"]}, []
        return {}, []

    monkeypatch.setattr("reconscope.scanner.dns.probe", fake)


def _scope(port: int, hosts: list[str] | None = None) -> Scope:
    return Scope.from_dict(
        {
            "authorization": "test",
            "allow": {"hosts": hosts or ["127.0.0.1"], "ports": [port]},
            "deny": {"hosts": []},
            "rate": {"max_concurrency": 10, "requests_per_second": 200},
        }
    )


async def test_scan_detects_and_probes_redis(make_server: ServerFactory) -> None:
    async def redis_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=0.8)
        except (TimeoutError, OSError):
            writer.close()
            return
        if line.startswith(b"PING"):
            writer.write(b"+PONG\r\n")
            await writer.drain()
            try:
                await asyncio.wait_for(reader.readline(), timeout=0.8)
                info = b"redis_version:7.2.4\r\n"
                writer.write(b"$%d\r\n%s\r\n" % (len(info), info))
                await writer.drain()
            except (TimeoutError, OSError):
                pass
        writer.close()

    port = await make_server(redis_server)
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=2.0))
    service = report.hosts[0].open_ports[0].service
    assert service is not None
    assert service.details["detected_as"] == "redis"
    assert any("Unauthenticated Redis" in f.title for f in report.hosts[0].open_ports[0].findings)


async def test_scan_detects_and_probes_https(make_server: ServerFactory, tls_context: TLSFactory) -> None:
    async def https_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=0.8)
        except (TimeoutError, OSError):
            data = b""
        if data.startswith((b"GET", b"HEAD")):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        writer.close()

    port = await make_server(https_server, tls_context())
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=3.0))
    port_result = report.hosts[0].open_ports[0]
    assert port_result.service is not None
    assert port_result.service.details["detected_as"] == "https"
    assert "tls" in port_result.service.details
    assert any("Self-signed" in f.title for f in port_result.findings)


async def test_scan_resolves_localhost(make_server: ServerFactory) -> None:
    async def http_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(reader.read(128), timeout=0.8)
        except (TimeoutError, OSError):
            data = b""
        if data.startswith((b"GET", b"HEAD")):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        writer.close()

    port = await make_server(http_server)
    report = await run_scan(_scope(port, hosts=["localhost"]), ["localhost"], ScanConfig(timeout=2.0))
    assert report.hosts, f"localhost refused: {report.refused}"
    assert report.hosts[0].hostname == "localhost"
