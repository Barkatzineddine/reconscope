#!/usr/bin/env python3
"""Assert that a reconscope report of the docker-compose lab found what the lab plants.

Run as ``python lab/check_report.py report.json``. Exits non-zero with a clear message if any
expected service, port or finding is missing, so CI fails loudly when a probe regresses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

WEB = "10.13.37.10"
SSH = "10.13.37.20"
SMB = "10.13.37.30"
DNS = "10.13.37.40"
REDIS = "10.13.37.50"


def _host(report: dict[str, Any], address: str) -> dict[str, Any]:
    for host in report["hosts"]:
        if host["host"] == address:
            return host
    raise AssertionError(f"host {address} is missing from the report")


def _port(host: dict[str, Any], number: int) -> dict[str, Any]:
    for port in host["ports"]:
        if port["port"] == number and port["state"] == "open":
            return port
    raise AssertionError(f"{host['host']} has no open port {number}")


def _finding_titles(port: dict[str, Any]) -> set[str]:
    return {f["title"] for f in port["findings"]}


def main(path: str) -> int:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    checks: list[str] = []

    web = _host(report, WEB)
    https = _port(web, 443)
    assert https["service"]["name"] == "https", "port 443 is not identified as https"
    assert any("Self-signed" in t for t in _finding_titles(https)), "self-signed cert not flagged"
    checks.append("web: https with self-signed certificate flagged")

    http = _port(web, 80)
    assert http["service"]["name"] == "http", "port 80 is not identified as http"
    assert any("Missing" in t for t in _finding_titles(http)), "missing security headers not flagged"
    checks.append("web: http with missing security headers flagged")

    ssh = _port(_host(report, SSH), 22)
    assert ssh["service"]["name"] == "ssh", "port 22 is not identified as ssh"
    assert ssh["service"]["details"].get("algorithms"), "ssh algorithms not collected"
    assert any("Weak SSH" in t for t in _finding_titles(ssh)), "weak ssh algorithms not flagged"
    checks.append("ssh: weak algorithms flagged")

    smb = _port(_host(report, SMB), 445)
    assert smb["service"]["name"] == "smb", "port 445 is not identified as smb"
    assert smb["service"]["details"].get("smbv1_enabled") is True, "SMBv1 not detected"
    assert any("SMBv1" in t for t in _finding_titles(smb)), "SMBv1 not flagged"
    checks.append("smb: legacy SMBv1 detected and flagged")

    _port(_host(report, DNS), 53)
    checks.append("dns: port 53 open")

    redis = _port(_host(report, REDIS), 6379)
    assert redis["service"]["name"] == "redis", "port 6379 is not identified as redis"
    assert redis["service"]["details"].get("detected_as") == "redis", "redis not detected by behaviour"
    assert any("Unauthenticated Redis" in t for t in _finding_titles(redis)), "unauth Redis not flagged"
    checks.append("redis: unauthenticated access detected and flagged")

    print("Lab report checks passed:")
    for line in checks:
        print(f"  - {line}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_report.py REPORT.json", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
