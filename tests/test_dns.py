"""Tests for the DNS probe, using a fake resolver (no real queries)."""

from __future__ import annotations

import dns.exception
import dns.resolver
import pytest

from reconscope.enum import dns as dns_probe


class _Record:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class _FakeResolver:
    lifetime = 0.0
    timeout = 0.0

    def __init__(self, mapping: dict[str, list[str]], raise_exc: Exception | None = None) -> None:
        self.mapping = mapping
        self.raise_exc = raise_exc

    async def resolve(self, name: str, rdtype: str) -> list[_Record]:
        if self.raise_exc is not None:
            raise self.raise_exc
        if rdtype in self.mapping:
            return [_Record(v) for v in self.mapping[rdtype]]
        raise dns.resolver.NoAnswer()


def _patch(monkeypatch: pytest.MonkeyPatch, resolver: _FakeResolver) -> None:
    monkeypatch.setattr(dns_probe, "_resolver", lambda timeout: resolver)


async def test_forward_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeResolver({"A": ["1.2.3.4"], "MX": ["10 mail.test."]}))
    records, findings = await dns_probe.probe("host.test", timeout=1.0)
    assert records["A"] == ["1.2.3.4"]
    assert records["MX"] == ["10 mail.test."]
    assert "AAAA" not in records
    assert findings == []


async def test_reverse_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeResolver({"PTR": ["dns.google."]}))
    records, _ = await dns_probe.probe("8.8.8.8", timeout=1.0)
    assert records == {"PTR": ["dns.google."]}


async def test_reverse_no_ptr(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeResolver({}))
    records, _ = await dns_probe.probe("8.8.4.4", timeout=1.0)
    assert records == {}


async def test_timeout_yields_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _FakeResolver({}, raise_exc=dns.exception.DNSException()))
    records, _ = await dns_probe.probe("host.test", timeout=1.0)
    assert records == {}


async def test_real_resolver_factory() -> None:
    # Exercise the real _resolver builder (no query is sent).
    resolver = dns_probe._resolver(2.5)
    assert resolver.lifetime == 2.5
    assert resolver.timeout == 2.5
