"""SSH probe: identification banner and the algorithms the server offers.

After the version-string exchange an SSH server sends a ``KEXINIT`` packet listing every key
exchange, host-key, cipher and MAC algorithm it is willing to use. Reading that list requires
no authentication and reveals plenty for a hygiene check: servers that still offer SHA-1 key
exchange, CBC ciphers or ``ssh-rsa`` host keys are worth flagging.

Only the version string and the first ``KEXINIT`` are read; the handshake is then abandoned, so
no key exchange and no authentication take place.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer, decode_banner

_CLIENT_ID = b"SSH-2.0-reconscope_1.0\r\n"
_SSH_MSG_KEXINIT = 20

# Substrings that mark an algorithm as weak or deprecated, by category.
_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "-sha1", "gss-group1")
_WEAK_HOSTKEY = ("ssh-rsa", "ssh-dss")
_WEAK_CIPHER = ("3des", "arcfour", "-cbc", "none", "blowfish", "cast128")
_WEAK_MAC = ("hmac-md5", "hmac-sha1", "-96", "umac-64")


def _parse_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    (length,) = struct.unpack_from(">I", data, offset)
    offset += 4
    raw = data[offset : offset + length]
    offset += length
    names = [item for item in raw.decode("ascii", errors="replace").split(",") if item]
    return names, offset


def _parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    # payload[0] is the message code, then a 16-byte cookie, then ten name-lists.
    offset = 1 + 16
    fields = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_c2s",
        "encryption_s2c",
        "mac_c2s",
        "mac_s2c",
        "compression_c2s",
        "compression_s2c",
        "languages_c2s",
        "languages_s2c",
    ]
    out: dict[str, list[str]] = {}
    for name in fields:
        values, offset = _parse_name_list(payload, offset)
        out[name] = values
    return out


def _weak(names: list[str], markers: tuple[str, ...]) -> list[str]:
    return sorted({n for n in names if any(m in n for m in markers)})


def _algorithm_findings(algos: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    checks = [
        ("key exchange", algos.get("kex_algorithms", []), _WEAK_KEX, Severity.MEDIUM),
        ("host key", algos.get("server_host_key_algorithms", []), _WEAK_HOSTKEY, Severity.LOW),
        ("cipher", algos.get("encryption_s2c", []), _WEAK_CIPHER, Severity.MEDIUM),
        ("MAC", algos.get("mac_s2c", []), _WEAK_MAC, Severity.LOW),
    ]
    for label, names, markers, severity in checks:
        weak = _weak(names, markers)
        if weak:
            findings.append(
                Finding(
                    severity,
                    f"Weak SSH {label} algorithm offered",
                    f"The server offers deprecated {label} algorithms: {', '.join(weak)}.",
                )
            )
    return findings


async def _read_identification(reader: asyncio.StreamReader, timeout: float) -> str:
    # The server may send banner lines before its SSH version string; skip to the SSH- line.
    for _ in range(10):
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            break
        if line.startswith(b"SSH-"):
            return decode_banner(line)
    return ""


async def _read_packet(reader: asyncio.StreamReader, timeout: float) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    (packet_length,) = struct.unpack(">I", header)
    if not 1 <= packet_length <= 35000:
        raise ValueError("implausible SSH packet length")
    body = await asyncio.wait_for(reader.readexactly(packet_length), timeout=timeout)
    padding_length = body[0]
    return body[1 : packet_length - padding_length]


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    """Read the SSH banner and the offered algorithms."""

    service = ServiceInfo(name="ssh")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        banner = await _read_identification(reader, timeout)
        service.banner = banner or None
        service.product = banner.split("-", 2)[-1] if banner else None
        writer.write(_CLIENT_ID)
        await writer.drain()
        payload = await _read_packet(reader, timeout)
    except (OSError, TimeoutError, asyncio.IncompleteReadError, ValueError) as exc:
        service.details["error"] = f"handshake read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    if not payload or payload[0] != _SSH_MSG_KEXINIT:
        return service, []

    try:
        algos = _parse_kexinit(payload)
    except (struct.error, IndexError):  # pragma: no cover - malformed KEXINIT
        service.details["error"] = "could not parse KEXINIT"
        return service, []

    service.details["algorithms"] = algos
    return service, _algorithm_findings(algos)
