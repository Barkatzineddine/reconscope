"""The orchestrator.

Given a :class:`~reconscope.scope.Scope` and a list of targets, the scanner authorizes each
target, resolves names, runs the connect scan for the in-scope ports and dispatches a
protocol probe for every open port. Authorization is checked twice -- once on the name or
address the user gave, and again on every address it resolves to -- so nothing outside the
scope is ever contacted.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
from dataclasses import dataclass

from . import __version__, banner
from .enum import dns, http, smb, ssh, tls
from .models import HostResult, PortResult, PortState, ScanReport, ServiceInfo
from .portscan import scan_host
from .ratelimit import AsyncRateLimiter
from .scope import Scope

# Which probe to run for an open port. Ports not listed fall back to a generic banner grab.
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888})
HTTPS_PORTS = frozenset({443, 8443})
SSH_PORTS = frozenset({22, 2222})
SMB_PORTS = frozenset({445})


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Tunables that are not part of the authorization scope."""

    timeout: float = 3.0


async def _resolve(target: str) -> list[str]:
    """Resolve a host name to its addresses; an address literal resolves to itself."""

    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return [target]

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


async def _enumerate_port(address: str, port: int, server_name: str | None, cfg: ScanConfig) -> PortResult:
    result = PortResult(port=port, state=PortState.OPEN)
    if port in HTTPS_PORTS:
        tls_service, tls_findings = await tls.probe(address, port, cfg.timeout, server_name)
        http_service, http_findings = await http.probe(address, port, cfg.timeout, True, server_name)
        service = http_service
        service.details["tls"] = tls_service.details
        if tls_service.product:
            service.details.setdefault("certificate_subject", tls_service.product)
        result.service = service
        result.findings = tls_findings + http_findings
    elif port in HTTP_PORTS:
        service, findings = await http.probe(address, port, cfg.timeout, False, server_name)
        result.service, result.findings = service, findings
    elif port in SSH_PORTS:
        service, findings = await ssh.probe(address, port, cfg.timeout)
        result.service, result.findings = service, findings
    elif port in SMB_PORTS:
        service, findings = await smb.probe(address, port, cfg.timeout)
        result.service, result.findings = service, findings
    else:
        result.service = await banner.probe(address, port, cfg.timeout)
    return result


async def _scan_target(
    target: str, scope: Scope, limiter: AsyncRateLimiter, cfg: ScanConfig, report: ScanReport
) -> None:
    addresses = await _resolve(target)
    if not addresses:
        report.refused.append({"target": target, "reason": "could not resolve"})
        return

    address: str | None = None
    for candidate in addresses:
        decision = scope.authorize_resolved(ipaddress.ip_address(candidate))
        if decision.allowed:
            address = candidate
            break
        report.refused.append({"target": f"{target} -> {candidate}", "reason": decision.reason})
    if address is None:
        return

    is_name = address != target
    server_name = target if is_name else None

    host = HostResult(host=address, hostname=target if is_name else None)

    # DNS runs regardless of open ports: forward records for a name, PTR for the address.
    host.dns, _ = await dns.probe(target, cfg.timeout)
    reverse, _ = await dns.probe(address, cfg.timeout)
    if "PTR" in reverse:
        host.reverse_dns = reverse["PTR"][0]

    ports = sorted(scope.ports)
    scan_results = await scan_host(address, ports, limiter, cfg.timeout)
    host.ports = scan_results

    open_ports = [p.port for p in scan_results if p.state is PortState.OPEN]
    enriched = await asyncio.gather(
        *(_enumerate_port(address, port, server_name, cfg) for port in open_ports)
    )
    by_port = {result.port: result for result in enriched}
    host.ports = [by_port.get(p.port, p) for p in scan_results]

    report.hosts.append(host)


async def run_scan(scope: Scope, targets: list[str], cfg: ScanConfig | None = None) -> ScanReport:
    """Run a full scan and return the assembled report."""

    cfg = cfg or ScanConfig()
    report = ScanReport(
        tool="reconscope",
        version=__version__,
        authorization=scope.authorization,
        started_at=dt.datetime.now(dt.UTC),
        scope_summary=scope.summary(),
        requested=list(targets),
    )
    limiter = AsyncRateLimiter(scope.rate.max_concurrency, scope.rate.requests_per_second)

    for target in targets:
        decision = scope.authorize_host(target)
        if not decision.allowed:
            report.refused.append({"target": target, "reason": decision.reason})
            continue
        await _scan_target(target, scope, limiter, cfg, report)

    report.finished_at = dt.datetime.now(dt.UTC)
    return report


def ensure_service(result: PortResult) -> ServiceInfo:
    """Return the port's service, creating an empty one if a probe left none (used by reports)."""

    if result.service is None:
        result.service = ServiceInfo(name="unknown")
    return result.service
