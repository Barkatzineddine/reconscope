"""Integration tests for the orchestrator, against local servers."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import Callable

import pytest

from reconscope import scanner
from reconscope.models import Finding, PortState
from reconscope.scanner import ScanConfig, run_scan
from reconscope.scope import Scope
from tests.conftest import ServerFactory


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the scanner off the real DNS during tests."""

    async def fake(target: str, timeout: float) -> tuple[dict[str, list[str]], list[Finding]]:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return {"A": ["127.0.0.1"]}, []
        return {"PTR": ["ptr.test"]}, []

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


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2.0)
    except (asyncio.IncompleteReadError, TimeoutError):
        pass
    body = b"<title>home</title>"
    writer.write(
        b"HTTP/1.1 200 OK\r\nServer: s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
    )
    writer.write(body)
    await writer.drain()
    writer.close()


async def test_scan_http_service(make_server: ServerFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    port = await make_server(_http_handler)
    monkeypatch.setattr(scanner, "HTTP_PORTS", frozenset({port}))
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=2.0))
    host = report.hosts[0]
    open_ports = host.open_ports
    assert [p.port for p in open_ports] == [port]
    assert open_ports[0].service is not None
    assert open_ports[0].service.name == "http"
    assert any("Missing" in f.title for f in open_ports[0].findings)


async def test_scan_https_service(
    make_server: ServerFactory,
    monkeypatch: pytest.MonkeyPatch,
    tls_context: Callable[..., ssl.SSLContext],
) -> None:
    port = await make_server(_http_handler, tls_context())
    monkeypatch.setattr(scanner, "HTTPS_PORTS", frozenset({port}))
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=3.0))
    service = report.hosts[0].open_ports[0].service
    assert service is not None
    assert service.name == "https"
    assert "tls" in service.details


async def test_scan_generic_banner(make_server: ServerFactory) -> None:
    async def greeter(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HELLO\r\n")
        await writer.drain()
        writer.close()

    port = await make_server(greeter)
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=2.0))
    service = report.hosts[0].open_ports[0].service
    assert service is not None
    assert service.banner == "HELLO"


async def test_scan_resolves_name(make_server: ServerFactory) -> None:
    # 'localhost' resolves through the real resolver (no external DNS) to a loopback address.
    port = await make_server(_http_handler)
    scope = _scope(port, hosts=["localhost"])
    report = await run_scan(scope, ["localhost"], ScanConfig(timeout=2.0))
    assert report.hosts, f"localhost was refused: {report.refused}"
    host = report.hosts[0]
    assert host.hostname == "localhost"
    assert host.reverse_dns == "ptr.test"


async def test_target_refused_out_of_scope() -> None:
    report = await run_scan(_scope(80), ["10.9.9.9"], ScanConfig(timeout=1.0))
    assert report.hosts == []
    assert report.refused[0]["target"] == "10.9.9.9"


async def test_resolution_failure_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(80, hosts=["ghost.test"])

    async def no_resolve(target: str) -> list[str]:
        return []

    monkeypatch.setattr(scanner, "_resolve", no_resolve)
    report = await run_scan(scope, ["ghost.test"], ScanConfig(timeout=1.0))
    assert report.refused[0]["reason"] == "could not resolve"


async def test_resolved_address_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    # Name is allowed, but it resolves into an address outside the allowed network.
    scope = Scope.from_dict(
        {
            "authorization": "t",
            "allow": {"hosts": ["10.0.0.0/24", "sneaky.test"], "ports": [80]},
            "deny": {"hosts": []},
            "rate": {"max_concurrency": 5, "requests_per_second": 50},
        }
    )

    async def resolve_public(target: str) -> list[str]:
        return ["203.0.113.9"]

    monkeypatch.setattr(scanner, "_resolve", resolve_public)
    report = await run_scan(scope, ["sneaky.test"], ScanConfig(timeout=1.0))
    assert report.hosts == []
    assert "not inside any allowed network" in report.refused[0]["reason"]


async def test_closed_ports_have_no_service(free_port: int) -> None:
    # Scope a port with nothing listening: it is not open (closed or filtered, platform
    # dependent) and no service is built for it.
    report = await run_scan(_scope(free_port), ["127.0.0.1"], ScanConfig(timeout=1.0))
    port = report.hosts[0].ports[0]
    assert port.state is not PortState.OPEN
    assert port.service is None


def test_ensure_service_fills_missing() -> None:
    from reconscope.models import PortResult

    result = PortResult(port=5, state=PortState.OPEN)
    service = scanner.ensure_service(result)
    assert service.name == "unknown"
    assert result.service is service
