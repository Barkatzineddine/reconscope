"""The authorization gate.

``reconscope`` only ever touches what a scope file explicitly allows. The scope file names the
engagement (so a report can never be mistaken for an unauthorized scan), lists the hosts and
ports in scope, and may carve exceptions back out with a deny list. Everything else is refused
before a single packet is sent.

The gate is deliberately strict and fail-closed:

* an empty or missing allow list authorizes nothing;
* a deny entry always wins over an allow entry;
* a host given as an IP address must fall inside an allowed network;
* a host given as a name must be listed by name in the allow list (matching by resolved
  address alone is not enough, so a hijacked DNS answer cannot pull an unlisted name into
  scope).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class ScopeError(ValueError):
    """The scope file is missing, malformed or does not authorize anything."""


@dataclass(frozen=True, slots=True)
class RateLimits:
    """Politeness limits applied to the whole scan."""

    max_concurrency: int = 50
    requests_per_second: float = 20.0

    def validate(self) -> None:
        if self.max_concurrency < 1:
            raise ScopeError("rate.max_concurrency must be at least 1")
        if self.requests_per_second <= 0:
            raise ScopeError("rate.requests_per_second must be positive")


@dataclass(frozen=True, slots=True)
class Decision:
    """Why a target was allowed or refused, for the report and the logs."""

    allowed: bool
    reason: str


def _parse_networks(entries: list[str]) -> tuple[list[IPNetwork], set[str]]:
    """Split a list of host entries into IP networks and lower-cased host names."""

    networks: list[IPNetwork] = []
    names: set[str] = set()
    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            names.add(entry.lower().rstrip("."))
    return networks, names


def _parse_ports(entries: list[Any]) -> set[int]:
    """Expand a list of ports and ``start-end`` ranges into a set of port numbers."""

    ports: set[int] = set()
    for raw in entries:
        text = str(raw).strip()
        if not text:
            continue
        if "-" in text:
            lo_s, hi_s = text.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            if lo < 1 or hi > 65535:
                raise ScopeError(f"port range out of bounds: {text}")
            ports.update(range(lo, hi + 1))
        else:
            port = int(text)
            if not 1 <= port <= 65535:
                raise ScopeError(f"port out of bounds: {port}")
            ports.add(port)
    return ports


MAX_EXPANDED_HOSTS = 1024


def expand_targets(targets: list[str]) -> list[str]:
    """Expand any CIDR targets into individual host addresses, leaving names untouched.

    Refuses to expand a network larger than :data:`MAX_EXPANDED_HOSTS` so a stray ``/8`` cannot
    turn into millions of probes by accident.
    """

    expanded: list[str] = []
    for raw in targets:
        target = raw.strip()
        if not target:
            continue
        if "/" not in target:
            expanded.append(target)
            continue
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            expanded.append(target)
            continue
        if network.num_addresses > MAX_EXPANDED_HOSTS:
            raise ScopeError(
                f"{target} expands to {network.num_addresses} hosts "
                f"(limit {MAX_EXPANDED_HOSTS}); list smaller ranges"
            )
        hosts = list(network.hosts()) or [network.network_address]
        expanded.extend(str(h) for h in hosts)
    return expanded


class Scope:
    """An authorized scope loaded from a YAML file."""

    def __init__(
        self,
        *,
        authorization: str,
        allow_entries: list[str],
        allow_networks: list[IPNetwork],
        allow_names: set[str],
        deny_networks: list[IPNetwork],
        deny_names: set[str],
        ports: set[int],
        rate: RateLimits,
    ) -> None:
        self.authorization = authorization
        self.allow_entries = allow_entries
        self.allow_networks = allow_networks
        self.allow_names = allow_names
        self.deny_networks = deny_networks
        self.deny_names = deny_names
        self.ports = ports
        self.rate = rate

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:  # pragma: no cover - passthrough of the parser message
            raise ScopeError(f"scope file is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError("scope file must be a YAML mapping")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scope:
        authorization = str(data.get("authorization", "")).strip()
        if not authorization:
            raise ScopeError(
                "scope file must carry an 'authorization' note describing the engagement "
                "(client, ticket or written permission). reconscope refuses to run without it."
            )

        allow = data.get("allow") or {}
        if not isinstance(allow, dict):
            raise ScopeError("'allow' must be a mapping with 'hosts' and 'ports'")
        allow_hosts = allow.get("hosts") or []
        allow_ports = allow.get("ports") or []
        if not allow_hosts:
            raise ScopeError("'allow.hosts' is empty: the scope authorizes nothing")
        if not allow_ports:
            raise ScopeError("'allow.ports' is empty: no ports are in scope")

        deny = data.get("deny") or {}
        if not isinstance(deny, dict):
            raise ScopeError("'deny' must be a mapping with 'hosts'")
        deny_hosts = deny.get("hosts") or []

        allow_networks, allow_names = _parse_networks(list(allow_hosts))
        deny_networks, deny_names = _parse_networks(list(deny_hosts))
        ports = _parse_ports(list(allow_ports))

        rate_raw = data.get("rate") or {}
        if not isinstance(rate_raw, dict):
            raise ScopeError("'rate' must be a mapping")
        rate = RateLimits(
            max_concurrency=int(rate_raw.get("max_concurrency", 50)),
            requests_per_second=float(rate_raw.get("requests_per_second", 20.0)),
        )
        rate.validate()

        return cls(
            authorization=authorization,
            allow_entries=[str(h).strip() for h in allow_hosts if str(h).strip()],
            allow_networks=allow_networks,
            allow_names=allow_names,
            deny_networks=deny_networks,
            deny_names=deny_names,
            ports=ports,
            rate=rate,
        )

    # -- authorization checks -------------------------------------------------

    def _denied_address(self, addr: IPAddress) -> bool:
        return any(addr in net for net in self.deny_networks)

    def authorize_host(self, target: str) -> Decision:
        """Decide whether ``target`` (an IP address or a host name) is in scope."""

        cleaned = target.strip().lower().rstrip(".")
        if not cleaned:
            return Decision(False, "empty target")

        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            addr = None

        if addr is not None:
            if self._denied_address(addr):
                return Decision(False, f"{target} is on the deny list")
            if any(addr in net for net in self.allow_networks):
                return Decision(True, f"{target} is inside an allowed network")
            return Decision(False, f"{target} is not inside any allowed network")

        if cleaned in self.deny_names:
            return Decision(False, f"{target} is on the deny list")
        if cleaned in self.allow_names:
            return Decision(True, f"{target} is an allowed host name")
        return Decision(False, f"{target} is not listed in the scope")

    def authorize_resolved(self, addr: IPAddress) -> Decision:
        """Second gate: a name allowed by the scope must still resolve into an allowed network.

        This stops an allowed name whose DNS answer points at an out-of-scope address from
        being scanned at that address.
        """

        if self._denied_address(addr):
            return Decision(False, f"resolved address {addr} is on the deny list")
        if any(addr in net for net in self.allow_networks):
            return Decision(True, f"resolved address {addr} is inside an allowed network")
        # A name may legitimately resolve outside the allowed networks when the networks were
        # not listed; in that case the name itself is the authorization and we allow it.
        if self.allow_networks:
            return Decision(False, f"resolved address {addr} is not inside any allowed network")
        return Decision(True, f"resolved address {addr} is covered by an allowed host name")

    def port_allowed(self, port: int) -> bool:
        return port in self.ports

    def default_targets(self) -> list[str]:
        """Targets to scan when the user names none: every entry in the allow list."""

        return list(self.allow_entries)

    def summary(self) -> dict[str, Any]:
        return {
            "authorization": self.authorization,
            "allow_networks": [str(n) for n in self.allow_networks],
            "allow_names": sorted(self.allow_names),
            "deny_networks": [str(n) for n in self.deny_networks],
            "deny_names": sorted(self.deny_names),
            "ports_in_scope": len(self.ports),
            "rate": {
                "max_concurrency": self.rate.max_concurrency,
                "requests_per_second": self.rate.requests_per_second,
            },
        }
