"""Shared fixtures: tiny local TCP/TLS servers so the probes can be tested for real.

Every server binds to ``127.0.0.1`` on an ephemeral port, so the tests need no network and no
privileges, and they exercise the actual socket code paths rather than mocks.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
ServerFactory = Callable[..., Awaitable[int]]


@pytest.fixture
async def make_server() -> AsyncIterator[ServerFactory]:
    """Return a factory that starts a server and yields its port; all are closed on teardown."""

    servers: list[asyncio.AbstractServer] = []

    async def _make(handler: Handler, ssl_ctx: ssl.SSLContext | None = None) -> int:
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
        servers.append(server)
        sock = server.sockets[0]
        return int(sock.getsockname()[1])

    yield _make

    for server in servers:
        server.close()
        await server.wait_closed()


@pytest.fixture
def free_port() -> int:
    """A loopback port with nothing listening, so a connection to it is refused (closed)."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _self_signed(days_valid: int, key_bits: int = 2048) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=365))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


@pytest.fixture
def tls_context(tmp_path: Path) -> Callable[..., ssl.SSLContext]:
    """Return a factory that builds a server-side TLS context with a fresh self-signed cert."""

    def _make(days_valid: int = 365, key_bits: int = 2048) -> ssl.SSLContext:
        cert_pem, key_pem = _self_signed(days_valid, key_bits)
        cert_file = tmp_path / f"cert-{days_valid}-{key_bits}.pem"
        key_file = tmp_path / f"key-{days_valid}-{key_bits}.pem"
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        return ctx

    return _make
