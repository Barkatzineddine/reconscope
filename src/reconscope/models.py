"""Typed data model for a scan and its JSON-serialisable form.

Every value the scanner learns about a target ends up in one of these dataclasses. Keeping the
model in one place means the JSON report, the HTML report and the tests all agree on the shape
of the data, and nothing in the enumeration code has to build dictionaries by hand.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from typing import Any


class Severity(StrEnum):
    """How much a finding matters to a defender. Ordered from least to most important."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        return order.index(self)


class PortState(StrEnum):
    """Outcome of a single TCP connect attempt."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(slots=True)
class Finding:
    """A single observation worth a defender's attention, e.g. a deprecated TLS version."""

    severity: Severity
    title: str
    detail: str


@dataclass(slots=True)
class ServiceInfo:
    """What the scanner could tell about the service behind an open port."""

    name: str
    banner: str | None = None
    product: str | None = None
    # Protocol-specific details (certificate fields, SSH algorithms, HTTP headers, ...).
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PortResult:
    """Result for one port on one host."""

    port: int
    state: PortState
    protocol: str = "tcp"
    service: ServiceInfo | None = None
    findings: list[Finding] = field(default_factory=list)


@dataclass(slots=True)
class HostResult:
    """Everything learned about a single authorized host."""

    host: str
    hostname: str | None = None
    reverse_dns: str | None = None
    dns: dict[str, list[str]] = field(default_factory=dict)
    ports: list[PortResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state is PortState.OPEN]


@dataclass(slots=True)
class ScanReport:
    """Top-level report: the engagement, the hosts scanned and summary statistics."""

    tool: str
    version: str
    authorization: str
    started_at: dt.datetime
    finished_at: dt.datetime | None = None
    scope_summary: dict[str, Any] = field(default_factory=dict)
    requested: list[str] = field(default_factory=list)
    refused: list[dict[str, str]] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for host in self.hosts:
            out.extend(host.findings)
            for port in host.ports:
                out.extend(port.findings)
        return out

    def finding_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.all_findings:
            counts[finding.severity.value] += 1
        return counts


def to_jsonable(value: Any) -> Any:
    """Recursively turn the dataclass model into plain JSON types.

    Enums become their string value, datetimes become ISO-8601 UTC strings, dataclasses become
    dicts. Written by hand rather than with ``dataclasses.asdict`` so that properties are left
    out and enums/datetimes are converted in one pass.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value
