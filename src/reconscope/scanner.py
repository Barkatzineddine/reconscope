"""The orchestrator.

Given a :class:`~reconscope.scope.Scope` and a list of targets, the scanner:

* authorizes every target (on the name/address given and again on each resolved address);
* scans the in-scope ports of each host concurrently with a connect scan;
* identifies the service behind each open port by what it speaks, not by the port number
  (see :mod:`reconscope.detect`), and runs the matching read-only probe;
* chains discoveries: host names found in TLS certificates, HTTP redirects and DNS records are
  authorized against the scope and, when they are in scope, scanned in turn.

Hosts are scanned concurrently (bounded) and every target, discovered or not, passes the scope
gate before it is touched.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import __version__, banner
from .detect import detect
from .enum import dns, ftp, http, mysql, postgres, rdp, redis, smb, smtp, ssh, telnet, tls, vnc
from .models import Finding, HostResult, PortResult, PortState, ScanReport, ServiceInfo
from .portscan import scan_host
from .ratelimit import AsyncRateLimiter
from .scope import Scope

# How many waves of chained discovery to follow beyond the initial targets.
MAX_DISCOVERY_WAVES = 2
# Upper bound on hosts scanned at once; the rate limiter still bounds connections underneath.
HOST_CONCURRENCY = 16
# Service kinds that have no dedicated probe; a generic banner grab is used.
_GENERIC_KINDS = frozenset({"pop3", "imap", "ldap", "mssql", "dns", "unknown"})


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Tunables that are not part of the authorization scope."""

    timeout: float = 3.0


@dataclass(frozen=True, slots=True)
class _Target:
    address: str
    hostname: str | None
    discovered_via: str | None


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


async def _probe_service(
    kind: str, address: str, port: int, server_name: str | None, cfg: ScanConfig
) -> tuple[ServiceInfo | None, list[Finding]]:
    t = cfg.timeout
    if kind == "https":
        tls_service, tls_findings = await tls.probe(address, port, t, server_name)
        http_service, http_findings = await http.probe(address, port, t, True, server_name)
        http_service.details["tls"] = tls_service.details
        return http_service, [*tls_findings, *http_findings]
    if kind == "tls":
        return await tls.probe(address, port, t, server_name)
    if kind == "http":
        return await http.probe(address, port, t, False, server_name)
    simple = {
        "ssh": ssh.probe,
        "smb": smb.probe,
        "ftp": ftp.probe,
        "smtp": smtp.probe,
        "telnet": telnet.probe,
        "redis": redis.probe,
        "mysql": mysql.probe,
        "postgresql": postgres.probe,
        "vnc": vnc.probe,
        "rdp": rdp.probe,
    }
    probe = simple.get(kind)
    if probe is not None:
        return await probe(address, port, t)
    return await banner.probe(address, port, t), []


async def _enumerate_port(address: str, port: int, server_name: str | None, cfg: ScanConfig) -> PortResult:
    result = PortResult(port=port, state=PortState.OPEN)
    detection = await detect(address, port, cfg.timeout)
    service, findings = await _probe_service(detection.kind, address, port, server_name, cfg)
    if service is None:
        service = ServiceInfo(name=detection.kind)
    service.details.setdefault("detected_as", detection.kind)
    result.service = service
    result.findings = findings
    return result


def _host_from_url(url: str) -> str | None:
    candidate = url if "//" in url else f"//{url}"
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host


def _candidate_names(host: HostResult) -> set[str]:
    """Host names worth following, gathered from certificates, redirects and DNS records."""

    names: set[str] = set()
    for port in host.ports:
        if port.service is None:
            continue
        details = port.service.details
        cert = details.get("certificate")
        if not isinstance(cert, dict):
            tls_details = details.get("tls")
            cert = tls_details.get("certificate") if isinstance(tls_details, dict) else None
        if isinstance(cert, dict):
            for san in cert.get("subject_alt_names", []):
                names.add(str(san))
        location = details.get("location")
        if isinstance(location, str):
            from_url = _host_from_url(location)
            if from_url:
                names.add(from_url)
    for rtype, values in host.dns.items():
        if rtype in {"CNAME", "NS"}:
            names.update(values)
        elif rtype == "MX":
            names.update(v.split()[-1] for v in values if v.split())
    cleaned = {n.lower().lstrip("*.").rstrip(".") for n in names}
    cleaned.discard((host.hostname or "").lower())
    return {n for n in cleaned if n and "*" not in n}


async def _scan_host(target: _Target, scope: Scope, limiter: AsyncRateLimiter, cfg: ScanConfig) -> HostResult:
    host = HostResult(host=target.address, hostname=target.hostname, discovered_via=target.discovered_via)
    name_for_dns = target.hostname or target.address
    host.dns, _ = await dns.probe(name_for_dns, cfg.timeout)
    reverse, _ = await dns.probe(target.address, cfg.timeout)
    if "PTR" in reverse:
        host.reverse_dns = reverse["PTR"][0]

    ports = sorted(scope.ports)
    scan_results = await scan_host(target.address, ports, limiter, cfg.timeout)
    open_ports = [p.port for p in scan_results if p.state is PortState.OPEN]
    enriched = await asyncio.gather(
        *(_enumerate_port(target.address, port, target.hostname, cfg) for port in open_ports)
    )
    by_port = {result.port: result for result in enriched}
    host.ports = [by_port.get(p.port, p) for p in scan_results]
    return host


async def _resolve_candidates(
    target: str,
    via: str | None,
    scope: Scope,
    seen: set[str],
    report: ScanReport,
    record_refusals: bool,
) -> list[_Target]:
    """Resolve a target and return the in-scope, not-yet-seen addresses to scan."""

    addresses = await _resolve(target)
    if not addresses:
        if record_refusals:
            report.refused.append({"target": target, "reason": "could not resolve"})
        return []
    out: list[_Target] = []
    for address in addresses:
        if address in seen:
            continue
        decision = scope.authorize_resolved(ipaddress.ip_address(address))
        if not decision.allowed:
            if record_refusals:
                report.refused.append({"target": f"{target} -> {address}", "reason": decision.reason})
            continue
        seen.add(address)
        hostname = target if address != target else None
        out.append(_Target(address=address, hostname=hostname, discovered_via=via))
    return out


async def run_scan(scope: Scope, targets: list[str], cfg: ScanConfig | None = None) -> ScanReport:
    """Run a full scan -- initial targets plus chained discoveries -- and return the report."""

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
    seen: set[str] = set()

    pending: list[_Target] = []
    for target in targets:
        decision = scope.authorize_host(target)
        if not decision.allowed:
            report.refused.append({"target": target, "reason": decision.reason})
            continue
        pending.extend(await _resolve_candidates(target, None, scope, seen, report, True))

    semaphore = asyncio.Semaphore(HOST_CONCURRENCY)

    async def scan_one(target: _Target) -> HostResult:
        async with semaphore:
            return await _scan_host(target, scope, limiter, cfg)

    wave = 0
    while pending:
        results = await asyncio.gather(*(scan_one(target) for target in pending))
        report.hosts.extend(results)
        if wave >= MAX_DISCOVERY_WAVES:
            break
        discovered: list[_Target] = []
        for host in results:
            for name in _candidate_names(host):
                if not scope.authorize_host(name).allowed:
                    continue
                via = f"{host.host} ({name})"
                discovered.extend(await _resolve_candidates(name, via, scope, seen, report, False))
        pending = discovered
        wave += 1

    report.finished_at = dt.datetime.now(dt.UTC)
    report.hosts.sort(key=_host_sort_key)
    return report


def _host_sort_key(host: HostResult) -> tuple[int, tuple[int, ...], str]:
    """Order hosts: IP addresses first (numerically), then names alphabetically."""

    try:
        packed = ipaddress.ip_address(host.host).packed
    except ValueError:
        return (1, (), host.host)
    return (0, tuple(packed), "")


def ensure_service(result: PortResult) -> ServiceInfo:
    """Return the port's service, creating an empty one if a probe left none (used by reports)."""

    if result.service is None:
        result.service = ServiceInfo(name="unknown")
    return result.service
