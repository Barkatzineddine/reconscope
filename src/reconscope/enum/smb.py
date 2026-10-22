"""SMB probe: which dialects a server speaks and whether it requires signing.

Two read-only negotiations are performed on port 445:

* an SMB2 ``NEGOTIATE`` offering dialects 2.0.2 through 3.0.2, to learn the highest dialect and
  whether message signing is required; and
* a legacy SMB1 ``NEGOTIATE`` offering ``NT LM 0.12``, purely to detect whether the obsolete
  SMBv1 protocol is still enabled.

Neither step authenticates, opens a tree or touches a share. It is the protocol equivalent of
asking "which versions do you speak?" and hanging up.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}
_SIGNING_REQUIRED = 0x0002


def _direct_tcp(message: bytes) -> bytes:
    """Wrap an SMB message in the 4-byte direct-TCP transport header used on port 445."""

    return struct.pack(">I", len(message)) + message


def _smb2_negotiate_request() -> bytes:
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",  # ProtocolId
        64,  # StructureSize
        0,  # CreditCharge
        0,  # Status
        0x0000,  # Command: NEGOTIATE
        1,  # CreditRequest
        0,  # Flags
        0,  # NextCommand
        0,  # MessageId
        0,  # ProcessId
        0,  # TreeId
        0,  # SessionId
        b"\x00" * 16,  # Signature
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = struct.pack(
        "<HHHHI16sQ",
        36,  # StructureSize
        len(dialects),  # DialectCount
        1,  # SecurityMode: signing enabled
        0,  # Reserved
        0,  # Capabilities
        b"\x00" * 16,  # ClientGuid
        0,  # ClientStartTime
    ) + b"".join(struct.pack("<H", d) for d in dialects)
    return header + body


def _smb1_negotiate_request() -> bytes:
    header = struct.pack(
        "<4sB I B H H 8s H H H H H",
        b"\xffSMB",  # Protocol
        0x72,  # Command: SMB_COM_NEGOTIATE
        0,  # Status
        0x18,  # Flags
        0xC853,  # Flags2
        0,  # PIDHigh
        b"\x00" * 8,  # SecurityFeatures
        0,  # Reserved
        0,  # TID
        0,  # PIDLow
        0,  # UID
        0,  # MID
    )
    dialect = b"\x02NT LM 0.12\x00"
    body = struct.pack("<B", 0) + struct.pack("<H", len(dialect)) + dialect
    return header + body


async def _exchange(host: str, port: int, request: bytes, timeout: float) -> bytes | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError):
        return None
    try:
        writer.write(_direct_tcp(request))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        (length,) = struct.unpack(">I", header)
        if not 1 <= length <= 65535:
            return None
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        return None
    finally:
        await close_writer(writer)


def _parse_smb2_response(data: bytes) -> tuple[int, int] | None:
    if len(data) < 64 + 8 or data[:4] != b"\xfeSMB":
        return None
    security_mode = struct.unpack_from("<H", data, 64 + 2)[0]
    dialect = struct.unpack_from("<H", data, 64 + 4)[0]
    return dialect, security_mode


def _smb1_enabled(data: bytes | None) -> bool:
    if not data or len(data) < 37 or data[:4] != b"\xffSMB":
        return False
    # WordCount at offset 32; a successful negotiate response has WordCount >= 1 and a
    # DialectIndex that is not 0xFFFF (which would mean "none of your dialects accepted").
    word_count = data[32]
    if word_count < 1 or len(data) < 35:
        return False
    dialect_index = struct.unpack_from("<H", data, 33)[0]
    return bool(dialect_index != 0xFFFF)


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    """Negotiate SMB dialects and report version and signing hygiene."""

    service = ServiceInfo(name="smb")
    findings: list[Finding] = []

    smb2 = await _exchange(host, port, _smb2_negotiate_request(), timeout)
    parsed = _parse_smb2_response(smb2) if smb2 else None
    if parsed is not None:
        dialect, security_mode = parsed
        service.details["max_dialect"] = _DIALECT_NAMES.get(dialect, f"0x{dialect:04x}")
        signing_required = bool(security_mode & _SIGNING_REQUIRED)
        service.details["signing_required"] = signing_required
        service.product = service.details["max_dialect"]
        if not signing_required:
            findings.append(
                Finding(
                    Severity.MEDIUM,
                    "SMB signing not required",
                    "The server negotiates SMB without requiring signing, which enables relay attacks.",
                )
            )

    smb1 = await _exchange(host, port, _smb1_negotiate_request(), timeout)
    smb1_enabled = _smb1_enabled(smb1)
    service.details["smbv1_enabled"] = smb1_enabled
    if smb1_enabled:
        findings.append(
            Finding(
                Severity.HIGH,
                "Legacy SMBv1 enabled",
                "The server still answers the obsolete SMBv1 protocol; it should be disabled.",
            )
        )

    if parsed is None and not smb1_enabled:
        service.details["error"] = "no SMB negotiation response"
    return service, findings
