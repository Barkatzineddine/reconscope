"""Tests for the JSON and HTML reports, including the HTML hardening."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re

from reconscope.models import (
    Finding,
    HostResult,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
    Severity,
)
from reconscope.report import to_html, to_json

XSS = "<script>alert(1)</script>"


def _report() -> ScanReport:
    port = PortResult(
        port=80,
        state=PortState.OPEN,
        service=ServiceInfo(name="http", banner=XSS, details={"title": XSS}),
        findings=[Finding(Severity.MEDIUM, "Missing header", "detail " + XSS)],
    )
    host = HostResult(
        host="10.0.0.5",
        hostname="evil.test",
        reverse_dns="ptr.test",
        dns={"A": ["10.0.0.5"]},
        ports=[port, PortResult(port=22, state=PortState.CLOSED)],
    )
    return ScanReport(
        tool="reconscope",
        version="1.0.0",
        authorization="engagement " + XSS,
        started_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        finished_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        scope_summary={"ports_in_scope": 2},
        requested=["10.0.0.5"],
        refused=[{"target": "9.9.9.9", "reason": "out of scope " + XSS}],
        hosts=[host],
    )


def test_to_json_is_valid_and_complete() -> None:
    data = json.loads(to_json(_report()))
    assert data["hosts"][0]["host"] == "10.0.0.5"
    assert data["refused"][0]["target"] == "9.9.9.9"


def test_html_escapes_collected_values() -> None:
    html = to_html(_report())
    # The raw script tag from a banner/title/finding/refusal must never appear unescaped.
    assert XSS not in html
    assert "&lt;script&gt;" in html


def test_html_csp_hash_matches_style() -> None:
    html = to_html(_report())
    style = re.search(r"<style>(.*?)</style>", html, re.DOTALL)
    assert style is not None
    digest = base64.b64encode(hashlib.sha256(style.group(1).encode("utf-8")).digest()).decode()
    meta = re.search(r"style-src 'sha256-([^']+)'", html)
    assert meta is not None
    assert meta.group(1) == digest


def test_html_shows_open_port_and_refused() -> None:
    html = to_html(_report())
    assert "80/tcp" in html
    assert "Refused (out of scope)" in html
    assert "ptr.test" in html


def test_html_handles_no_open_ports() -> None:
    report = _report()
    report.hosts[0].ports = [PortResult(port=22, state=PortState.CLOSED)]
    html = to_html(report)
    assert "No open ports in scope." in html
