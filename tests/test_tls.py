"""Tests for the TLS certificate and version probe."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable

import pytest

from reconscope.enum import tls
from reconscope.models import Finding, Severity
from tests.conftest import ServerFactory

TLSFactory = Callable[..., ssl.SSLContext]


async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.read(16), timeout=1.0)
    except (TimeoutError, OSError):
        pass
    writer.close()


def _sev(findings: list[Finding], title_part: str) -> Severity | None:
    for f in findings:
        if title_part in f.title:
            return f.severity
    return None


async def test_valid_cert_self_signed(make_server: ServerFactory, tls_context: TLSFactory) -> None:
    port = await make_server(_accept, tls_context(days_valid=365))
    service, findings = await tls.probe("127.0.0.1", port, timeout=3.0, server_name="test.local")
    cert = service.details["certificate"]
    assert cert["subject"] == "test.local"
    assert cert["self_signed"] is True
    assert "test.local" in cert["subject_alt_names"]
    assert service.details["negotiated_version"].startswith("TLSv1.")
    assert any(v.startswith("TLSv1.") for v in service.details["supported_versions"])
    assert _sev(findings, "Self-signed") is Severity.LOW


async def test_expiring_soon(make_server: ServerFactory, tls_context: TLSFactory) -> None:
    port = await make_server(_accept, tls_context(days_valid=10))
    _, findings = await tls.probe("127.0.0.1", port, timeout=3.0, server_name="test.local")
    assert _sev(findings, "expiring soon") is Severity.MEDIUM


async def test_expired(make_server: ServerFactory, tls_context: TLSFactory) -> None:
    port = await make_server(_accept, tls_context(days_valid=-1))
    _, findings = await tls.probe("127.0.0.1", port, timeout=3.0, server_name="test.local")
    assert _sev(findings, "Expired") is Severity.HIGH


def test_weak_key_cert_analysis() -> None:
    # A 1024-bit key cannot be served (OpenSSL rejects it), so the analysis is tested directly.
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak.local")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    details, findings = tls._analyse_certificate(der)
    assert details["key_bits"] == 1024
    assert _sev(findings, "Weak TLS key") is Severity.HIGH


async def test_handshake_failure_on_plain_tcp(make_server: ServerFactory) -> None:
    port = await make_server(_accept)  # no TLS: the handshake cannot complete
    service, findings = await tls.probe("127.0.0.1", port, timeout=2.0)
    assert service.details.get("error") == "TLS handshake failed"
    assert findings == []


async def test_deprecated_version_finding(
    make_server: ServerFactory, tls_context: TLSFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    port = await make_server(_accept, tls_context())

    async def fake_versions(*_a: object, **_k: object) -> list[str]:
        return ["TLSv1", "TLSv1.2", "TLSv1.3"]

    monkeypatch.setattr(tls, "_supported_versions", fake_versions)
    _, findings = await tls.probe("127.0.0.1", port, timeout=3.0, server_name="test.local")
    assert _sev(findings, "Deprecated TLS version") is Severity.MEDIUM
