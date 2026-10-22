"""TLS probe: certificate hygiene and supported protocol versions.

The scanner must be able to look at the certificate of a host that presents a self-signed or
expired one -- that is exactly the kind of finding a defender wants -- so it negotiates TLS
without verification. The connection is read-only: it completes the handshake, reads the
certificate the server offers and closes. No application data is ever sent.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

# TLS versions we actively test for, oldest first. 1.0 and 1.1 are deprecated (RFC 8996).
_VERSIONS: list[tuple[str, ssl.TLSVersion]] = [
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
_DEPRECATED = {"TLSv1", "TLSv1.1"}


def inspection_context() -> ssl.SSLContext:
    """An SSL context that negotiates but does not verify, so any certificate can be inspected."""

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _single_version_context(version: ssl.TLSVersion) -> ssl.SSLContext | None:
    ctx = inspection_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        # The local OpenSSL build has disabled this version outright: we cannot test it.
        return None
    return ctx


class _Handshake:
    """What a successful handshake told us, read off the live socket before it was closed."""

    __slots__ = ("der", "version")

    def __init__(self, der: bytes | None, version: str | None) -> None:
        self.der = der
        self.version = version


async def _handshake(
    host: str, port: int, ctx: ssl.SSLContext, server_name: str | None, timeout: float
) -> _Handshake | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_name),
            timeout=timeout,
        )
    except (ssl.SSLError, OSError, TimeoutError):
        return None
    del reader
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:  # pragma: no cover - should not happen on a TLS connection
        await close_writer(writer)
        return None
    der: bytes | None = ssl_object.getpeercert(binary_form=True)
    version: str | None = ssl_object.version()
    await close_writer(writer)
    return _Handshake(der, version)


async def _supported_versions(host: str, port: int, server_name: str | None, timeout: float) -> list[str]:
    found: list[str] = []
    for label, version in _VERSIONS:
        ctx = _single_version_context(version)
        if ctx is None:
            continue
        if await _handshake(host, port, ctx, server_name, timeout) is not None:
            found.append(label)
    return found


def _name_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _san_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = cast(x509.SubjectAlternativeName, ext.value)
    return [str(n) for n in san.get_values_for_type(x509.DNSName)]


def _key_bits(cert: x509.Certificate) -> int | None:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.key_size
    return None


def _analyse_certificate(der: bytes) -> tuple[dict[str, Any], list[Finding]]:
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    subject_cn = _name_cn(cert.subject)
    issuer_cn = _name_cn(cert.issuer)
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    key_bits = _key_bits(cert)

    details: dict[str, Any] = {
        "subject": subject_cn,
        "issuer": issuer_cn,
        "subject_alt_names": _san_names(cert),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "signature_hash": sig_hash,
        "key_bits": key_bits,
        "self_signed": cert.subject == cert.issuer,
    }

    findings: list[Finding] = []
    now = dt.datetime.now(dt.UTC)
    days_left = (not_after - now).days
    if not_after < now:
        findings.append(
            Finding(Severity.HIGH, "Expired TLS certificate", f"Certificate expired on {not_after.date()}.")
        )
    elif days_left < 30:
        findings.append(
            Finding(
                Severity.MEDIUM, "TLS certificate expiring soon", f"Certificate expires in {days_left} days."
            )
        )
    if details["self_signed"]:
        findings.append(
            Finding(Severity.LOW, "Self-signed TLS certificate", "The certificate is its own issuer.")
        )
    if sig_hash.lower() in {"md5", "sha1"}:
        findings.append(
            Finding(Severity.HIGH, "Weak certificate signature", f"Certificate is signed with {sig_hash}.")
        )
    if key_bits is not None and key_bits < 2048 and isinstance(cert.public_key(), rsa.RSAPublicKey):
        findings.append(
            Finding(Severity.HIGH, "Weak TLS key", f"RSA key is only {key_bits} bits (2048 is the minimum).")
        )
    return details, findings


async def probe(
    host: str, port: int, timeout: float, server_name: str | None = None
) -> tuple[ServiceInfo, list[Finding]]:
    """Inspect the certificate and the set of protocol versions a TLS service accepts."""

    service = ServiceInfo(name="tls")
    findings: list[Finding] = []

    handshake = await _handshake(host, port, inspection_context(), server_name, timeout)
    if handshake is None:
        service.details["error"] = "TLS handshake failed"
        return service, findings

    service.details["negotiated_version"] = handshake.version

    der = handshake.der
    if der:
        try:
            cert_details, cert_findings = _analyse_certificate(der)
        except ValueError:  # pragma: no cover - malformed certificate
            service.details["certificate_error"] = "could not parse certificate"
        else:
            service.details["certificate"] = cert_details
            service.product = cert_details.get("subject") or None
            findings.extend(cert_findings)

    versions = await _supported_versions(host, port, server_name, timeout)
    service.details["supported_versions"] = versions
    deprecated = sorted(_DEPRECATED.intersection(versions))
    if deprecated:
        findings.append(
            Finding(
                Severity.MEDIUM,
                "Deprecated TLS version accepted",
                f"The service still accepts {', '.join(deprecated)} (deprecated by RFC 8996).",
            )
        )
    return service, findings
