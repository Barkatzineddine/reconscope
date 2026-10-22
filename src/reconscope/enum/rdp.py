"""RDP probe: which security protocol the server negotiates (read-only, no login).

The scanner sends the standard X.224 connection request with an RDP negotiation request
offering TLS and CredSSP (NLA), and reads the server's negotiation response. From it, it reports
the protocol the server selected and flags a server that falls back to legacy standard RDP
security (no TLS, no Network Level Authentication). It never proceeds past the negotiation.
"""

from __future__ import annotations

import asyncio
import struct

from ..models import Finding, ServiceInfo, Severity
from ..netutil import close_writer

_PROTOCOLS = {0: "standard-rdp", 1: "tls", 2: "credssp-nla", 8: "rdstls", 16: "credssp-ex"}
_TYPE_RESPONSE = 2
_TYPE_FAILURE = 3


def _request() -> bytes:
    neg = struct.pack("<BBHI", 1, 0, 8, 0x00000003)  # type, flags, length, TLS|CredSSP
    x224_body = b"\xe0\x00\x00\x00\x00\x00" + neg  # CR + dst/src ref + class + negotiation
    x224 = bytes([len(x224_body)]) + x224_body
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def _parse_response(data: bytes) -> dict[str, object]:
    # TPKT (4) + X.224 CC header (7), then the 8-byte RDP negotiation response, when present.
    if len(data) < 11 + 8:
        return {"negotiation": False}
    neg_type = data[11]
    if neg_type == _TYPE_FAILURE:
        (code,) = struct.unpack_from("<I", data, 11 + 4)
        return {"negotiation": True, "failure_code": code}
    if neg_type == _TYPE_RESPONSE:
        (selected,) = struct.unpack_from("<I", data, 11 + 4)
        return {"negotiation": True, "selected_protocol": selected}
    return {"negotiation": False}


async def probe(host: str, port: int, timeout: float) -> tuple[ServiceInfo, list[Finding]]:
    service = ServiceInfo(name="rdp")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"connection failed: {exc.__class__.__name__}"
        return service, []

    try:
        writer.write(_request())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
    except (OSError, TimeoutError) as exc:
        service.details["error"] = f"read failed: {exc.__class__.__name__}"
        await close_writer(writer)
        return service, []
    await close_writer(writer)

    if not data.startswith(b"\x03\x00"):
        service.details["error"] = "not an RDP/TPKT response"
        return service, []

    parsed = _parse_response(data)
    findings: list[Finding] = []
    if not parsed.get("negotiation"):
        # No negotiation response: the server only understands legacy standard RDP security.
        service.details["security"] = "standard-rdp"
        findings.append(
            Finding(
                Severity.MEDIUM,
                "RDP standard security (no TLS/NLA)",
                "The server did not negotiate TLS or CredSSP; the session would use legacy RDP security.",
            )
        )
        return service, findings

    if "failure_code" in parsed:
        service.details["negotiation_failure"] = parsed["failure_code"]
        return service, findings

    raw_selected = parsed.get("selected_protocol", 0)
    selected = raw_selected if isinstance(raw_selected, int) else 0
    service.details["selected_protocol"] = _PROTOCOLS.get(selected, f"0x{selected:x}")
    service.details["nla"] = bool(selected & (2 | 16))  # CredSSP or CredSSP-EX
    service.product = service.details["selected_protocol"]
    if selected == 0:
        findings.append(
            Finding(
                Severity.MEDIUM,
                "RDP standard security (no TLS/NLA)",
                "The server selected legacy standard RDP security instead of TLS or CredSSP (NLA).",
            )
        )
    return service, findings
