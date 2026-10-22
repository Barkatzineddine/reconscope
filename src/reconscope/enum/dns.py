"""DNS probe: resolve the common record types for a name, or the PTR for an address.

This is ordinary resolution against the configured resolver -- the same queries any client
makes. It does not attempt zone transfers or any other operation that a server would treat as
privileged.
"""

from __future__ import annotations

import ipaddress

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename

from ..models import Finding

_FORWARD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    return resolver


async def _query(resolver: dns.asyncresolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except (dns.exception.Timeout, dns.exception.DNSException):
        return []
    return sorted(str(record).strip() for record in answer)


async def probe(target: str, timeout: float) -> tuple[dict[str, list[str]], list[Finding]]:
    """Return a mapping of record type to values. Findings are reserved for future use."""

    resolver = _resolver(timeout)
    records: dict[str, list[str]] = {}

    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        addr = None

    if addr is not None:
        ptr_name = dns.reversename.from_address(str(addr)).to_text()
        values = await _query(resolver, ptr_name, "PTR")
        if values:
            records["PTR"] = values
        return records, []

    for rdtype in _FORWARD_TYPES:
        values = await _query(resolver, target, rdtype)
        if values:
            records[rdtype] = values
    return records, []
