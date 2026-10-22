"""Tests for the data model and its JSON serialisation."""

from __future__ import annotations

import datetime as dt

from reconscope.models import (
    Finding,
    HostResult,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
    Severity,
    to_jsonable,
)


def _report() -> ScanReport:
    port = PortResult(
        port=443,
        state=PortState.OPEN,
        service=ServiceInfo(name="https", details={"negotiated_version": "TLSv1.3"}),
        findings=[Finding(Severity.MEDIUM, "x", "y")],
    )
    closed = PortResult(port=22, state=PortState.CLOSED)
    host = HostResult(host="1.1.1.1", ports=[port, closed], findings=[Finding(Severity.HIGH, "h", "d")])
    return ScanReport(
        tool="reconscope",
        version="1.0.0",
        authorization="auth",
        started_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        finished_at=dt.datetime(2026, 1, 1, 0, 0, 5, tzinfo=dt.UTC),
        hosts=[host],
    )


def test_severity_rank_order() -> None:
    assert Severity.INFO.rank < Severity.LOW.rank < Severity.MEDIUM.rank < Severity.HIGH.rank


def test_open_ports_filter() -> None:
    report = _report()
    assert [p.port for p in report.hosts[0].open_ports] == [443]


def test_all_findings_and_counts() -> None:
    report = _report()
    assert len(report.all_findings) == 2
    counts = report.finding_counts()
    assert counts == {"info": 0, "low": 0, "medium": 1, "high": 1}


def test_to_jsonable_converts_enums_and_dates() -> None:
    data = to_jsonable(_report())
    assert data["started_at"] == "2026-01-01T00:00:00+00:00"
    assert data["hosts"][0]["ports"][0]["state"] == "open"
    assert data["hosts"][0]["ports"][0]["findings"][0]["severity"] == "medium"
    # Properties such as open_ports must not leak into the serialised form.
    assert "open_ports" not in data["hosts"][0]


def test_to_jsonable_primitive_passthrough() -> None:
    assert to_jsonable(5) == 5
    assert to_jsonable([1, (2, 3)]) == [1, [2, 3]]
    assert to_jsonable({"k": Severity.LOW}) == {"k": "low"}
