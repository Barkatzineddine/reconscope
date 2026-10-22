"""Integration tests for the orchestrator: detection dispatch, chaining, concurrency."""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from reconscope import scanner
from reconscope.models import Finding, HostResult, PortResult, PortState, ServiceInfo
from reconscope.scanner import ScanConfig, _candidate_names, _Target, run_scan
from reconscope.scope import Scope
from tests.conftest import ServerFactory


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
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
        data = await asyncio.wait_for(reader.read(256), timeout=0.8)
    except (TimeoutError, OSError):
        data = b""
    if data.startswith((b"GET", b"HEAD")):
        body = b"<title>home</title>"
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
        )
        writer.write(body)
        await writer.drain()
    writer.close()


async def test_detects_and_probes_http(make_server: ServerFactory) -> None:
    port = await make_server(_http_handler)
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=2.0))
    service = report.hosts[0].open_ports[0].service
    assert service is not None
    assert service.name == "http"
    assert service.details["detected_as"] == "http"
    assert any("Missing" in f.title for f in report.hosts[0].open_ports[0].findings)


async def test_detects_ssh_on_nonstandard_port(make_server: ServerFactory) -> None:
    async def ssh_like(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    port = await make_server(ssh_like)  # ephemeral port, not 22
    report = await run_scan(_scope(port), ["127.0.0.1"], ScanConfig(timeout=2.0))
    service = report.hosts[0].open_ports[0].service
    assert service is not None
    assert service.details["detected_as"] == "ssh"


async def test_refused_out_of_scope() -> None:
    report = await run_scan(_scope(80), ["10.9.9.9"], ScanConfig(timeout=1.0))
    assert report.hosts == []
    assert report.refused[0]["target"] == "10.9.9.9"


def test_candidate_names_from_cert_and_dns() -> None:
    host = HostResult(host="10.0.0.1", hostname="a.test")
    host.ports = [
        PortResult(
            port=443,
            state=PortState.OPEN,
            service=ServiceInfo(
                name="https",
                details={
                    "certificate": {"subject_alt_names": ["b.test", "*.wild.test"]},
                    "location": "https://c.test/login",
                },
            ),
        )
    ]
    host.dns = {"CNAME": ["d.test."], "MX": ["10 mail.test."]}
    names = _candidate_names(host)
    assert "b.test" in names
    assert "c.test" in names
    assert "d.test" in names
    assert "mail.test" in names
    assert not any("*" in n for n in names)  # wildcard dropped


async def test_chaining_discovers_new_host(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = Scope.from_dict(
        {
            "authorization": "t",
            "allow": {"hosts": ["10.0.0.0/30", "found.test"], "ports": [443]},
            "deny": {"hosts": []},
            "rate": {"max_concurrency": 5, "requests_per_second": 100},
        }
    )

    async def fake_resolve(target: str) -> list[str]:
        return {"10.0.0.1": ["10.0.0.1"], "found.test": ["10.0.0.2"]}.get(target, [])

    async def fake_scan_host(target: _Target, scope_: Scope, limiter: object, cfg: object) -> HostResult:
        host = HostResult(host=target.address, hostname=target.hostname, discovered_via=target.discovered_via)
        if target.address == "10.0.0.1":
            host.ports = [
                PortResult(
                    port=443,
                    state=PortState.OPEN,
                    service=ServiceInfo(
                        name="https", details={"certificate": {"subject_alt_names": ["found.test"]}}
                    ),
                )
            ]
        return host

    monkeypatch.setattr(scanner, "_resolve", fake_resolve)
    monkeypatch.setattr(scanner, "_scan_host", fake_scan_host)

    report = await run_scan(scope, ["10.0.0.1"], ScanConfig(timeout=1.0))
    addresses = {h.host for h in report.hosts}
    assert addresses == {"10.0.0.1", "10.0.0.2"}
    discovered = next(h for h in report.hosts if h.host == "10.0.0.2")
    assert discovered.discovered_via is not None
    assert "found.test" in discovered.discovered_via


async def test_scans_multiple_hosts_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = Scope.from_dict(
        {
            "authorization": "t",
            "allow": {"hosts": ["10.0.0.0/29"], "ports": [80]},
            "deny": {"hosts": []},
            "rate": {"max_concurrency": 5, "requests_per_second": 100},
        }
    )

    async def fake_resolve(target: str) -> list[str]:
        return [target]

    async def fake_scan_host(target: _Target, scope_: Scope, limiter: object, cfg: object) -> HostResult:
        await asyncio.sleep(0.01)
        return HostResult(host=target.address)

    monkeypatch.setattr(scanner, "_resolve", fake_resolve)
    monkeypatch.setattr(scanner, "_scan_host", fake_scan_host)

    report = await run_scan(scope, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], ScanConfig(timeout=1.0))
    assert len(report.hosts) == 3
    # Sorted numerically by address.
    assert [h.host for h in report.hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


async def test_resolution_failure_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(80, hosts=["ghost.test"])

    async def no_resolve(target: str) -> list[str]:
        return []

    monkeypatch.setattr(scanner, "_resolve", no_resolve)
    report = await run_scan(scope, ["ghost.test"], ScanConfig(timeout=1.0))
    assert report.refused[0]["reason"] == "could not resolve"


async def test_resolved_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
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


def test_ensure_service_fills_missing() -> None:
    result = PortResult(port=5, state=PortState.OPEN)
    service = scanner.ensure_service(result)
    assert service.name == "unknown"
    assert result.service is service
