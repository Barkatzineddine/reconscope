"""Tests for the command-line interface."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from reconscope import cli
from reconscope.models import ScanReport
from reconscope.scope import Scope

SCOPE_YAML = """
authorization: cli test engagement
allow:
  hosts: ['127.0.0.1', '10.0.0.0/30']
  ports: ['80']
deny:
  hosts: []
rate:
  max_concurrency: 5
  requests_per_second: 50
"""


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yml"
    path.write_text(SCOPE_YAML, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _stub_scan(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Replace the real scan with a fake that records the targets it was given."""

    captured: dict[str, object] = {}

    async def fake_run_scan(scope: Scope, targets: list[str], cfg: object) -> ScanReport:
        captured["targets"] = targets
        now = dt.datetime.now(dt.UTC)
        return ScanReport(
            tool="reconscope",
            version="1.0.0",
            authorization=scope.authorization,
            started_at=now,
            finished_at=now,
            requested=targets,
        )

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    return captured


def test_validate_scope(scope_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate-scope", str(scope_file)]) == 0
    out = capsys.readouterr().out
    assert "Scope OK" in out
    assert "cli test engagement" in out


def test_scan_writes_json_and_html(scope_file: Path, tmp_path: Path) -> None:
    json_out = tmp_path / "r.json"
    html_out = tmp_path / "r.html"
    code = cli.main(
        ["scan", "--scope", str(scope_file), "--json", str(json_out), "--html", str(html_out), "127.0.0.1"]
    )
    assert code == 0
    assert json.loads(json_out.read_text(encoding="utf-8"))["tool"] == "reconscope"
    assert "<!doctype html>" in html_out.read_text(encoding="utf-8")


def test_scan_prints_json_without_outputs(scope_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", "--scope", str(scope_file), "127.0.0.1"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"] == "reconscope"


def test_scan_defaults_to_scope_hosts_and_expands(scope_file: Path, _stub_scan: dict[str, object]) -> None:
    cli.main(["scan", "--scope", str(scope_file)])
    targets = _stub_scan["targets"]
    assert isinstance(targets, list)
    # 127.0.0.1 plus the two usable hosts of 10.0.0.0/30.
    assert "127.0.0.1" in targets
    assert "10.0.0.1" in targets and "10.0.0.2" in targets


def test_bad_scope_returns_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bad.yml"
    path.write_text("authorization: ''\nallow: {hosts: [], ports: []}\n", encoding="utf-8")
    assert cli.main(["scan", "--scope", str(path)]) == 2
    assert "Scope error" in capsys.readouterr().err


def test_missing_file_returns_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate-scope", str(tmp_path / "nope.yml")]) == 2
    assert "File not found" in capsys.readouterr().err


def test_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "reconscope 1.0.0" in capsys.readouterr().out


def test_no_subcommand_errors() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
