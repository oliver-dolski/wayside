"""The Modbus/TCP layer over scapy: MBAP validation as a gate, function
code classification and reconstruction of the request/response direction
without reference to a port number.

Protocol recognition goes by the shape of the MBAP header on any TCP port
(PROTO-01) - scapy binds Modbus rigidly to port 502 through `bind_layers`
(02-RESEARCH.md, Pitfall 2), so this module never relies on automatic
dissection of `pkt[TCP].payload`. `validate_mbap` is the gate: an invalid
header never reaches functional classification (PROTO-02) - scapy itself
validates neither `protoId` nor the consistency of the `len` field
(verified in 02-RESEARCH.md).

Function codes are classified against the full Modbus Application Protocol
table reconstructed from `scapy.contrib.modbus` (PROTO-04) - the code list
is a reading of a publicly documented specification, not guesswork.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass

import wayside.pcap  # noqa: F401  - scapy cache isolation BEFORE layer imports

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse  # noqa: E402

from wayside.decode import Segment  # noqa: E402

__all__ = [
    "MBAP_HEADER_LEN",
    "MIN_ADU_LEN",
    "FUNCTION_CODE_KIND",
    "FUNCTION_CODE_NAME",
    "MbapHeader",
    "ModbusEvent",
    "validate_mbap",
    "classify_function_code",
    "dissect_all",
]

MBAP_HEADER_LEN = 7
MIN_ADU_LEN = 8  # 7 bytes of MBAP + at least 1 byte of function code

# The Modbus Application Protocol function code table, reconstructed from
# `scapy.contrib.modbus` (02-RESEARCH.md, Pattern 3). Exactly 19 entries.
FUNCTION_CODE_KIND: dict[int, str] = {
    0x01: "read",
    0x02: "read",
    0x03: "read",
    0x04: "read",
    0x05: "write",
    0x06: "write",
    0x07: "read",
    0x08: "other",  # Diagnostics - the effect depends on subFunc
    0x0B: "read",
    0x0C: "read",
    0x0F: "write",
    0x10: "write",
    0x11: "read",
    0x14: "read",
    0x15: "write",
    0x16: "write",
    0x17: "write",  # Read/Write Multiple Registers - the PDU contains a write
    0x18: "read",
    0x2B: "read",
}

FUNCTION_CODE_NAME: dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Slave Id",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Read Device Identification",
}


@dataclass(frozen=True)
class MbapHeader:
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int


@dataclass(frozen=True)
class ModbusEvent:
    packet_number: int
    session_id: int
    unit_id: int
    transaction_id: int
    function_code: int
    function_name: str
    kind: str
    direction: str
    src_ip: str
    dst_ip: str
    timestamp: float


def validate_mbap(raw: bytes) -> MbapHeader | None:
    """Validates the MBAP header as a gate before functional parsing.

    The order of checks is required (threat T-2-01): the length is checked
    BEFORE any indexing based on the length field. `scapy` validates none of
    these three conditions on its own (verified in 02-RESEARCH.md).
    """
    if len(raw) < MIN_ADU_LEN:
        return None

    protocol_id = struct.unpack(">H", raw[2:4])[0]
    if protocol_id != 0:
        return None

    length_field = struct.unpack(">H", raw[4:6])[0]
    if length_field != len(raw) - 6:
        return None

    transaction_id = struct.unpack(">H", raw[0:2])[0]
    unit_id = raw[6]

    return MbapHeader(
        transaction_id=transaction_id,
        protocol_id=protocol_id,
        length=length_field,
        unit_id=unit_id,
    )


def classify_function_code(code: int) -> str:
    """Classifies a function code. A code outside the table returns
    `unknown`; it never raises `KeyError` and never returns `read` by
    default."""
    return FUNCTION_CODE_KIND.get(code, "unknown")


def dissect_all(segments: list[Segment]) -> list[ModbusEvent]:
    """Modbus/TCP dissection over a list of segments, in file order.

    The direction is settled WITHOUT reference to port 502: the party that
    first sent, in a given session, a payload passing `validate_mbap` is the
    client - its segments are `request`, the other party's `response`
    (PROTO-01). `ModbusADURequest`/`ModbusADUResponse` are constructed by
    hand from raw bytes, following the settled direction, purely as an
    additional gate (a `struct.error` rejects the segment) - the function
    code comes from the raw byte at position `MBAP_HEADER_LEN`, not from an
    attribute of a scapy object.
    """
    events: list[ModbusEvent] = []
    session_clients: dict[int, tuple[str, int]] = {}

    for segment in segments:
        header = validate_mbap(segment.payload)
        if header is None:
            continue

        client_endpoint = session_clients.get(segment.session_id)
        if client_endpoint is None:
            client_endpoint = (segment.src_ip, segment.src_port)
            session_clients[segment.session_id] = client_endpoint

        direction = (
            "request"
            if (segment.src_ip, segment.src_port) == client_endpoint
            else "response"
        )

        try:
            if direction == "request":
                ModbusADURequest(segment.payload)
            else:
                ModbusADUResponse(segment.payload)
        except struct.error:
            continue

        function_code = segment.payload[MBAP_HEADER_LEN]
        events.append(
            ModbusEvent(
                packet_number=segment.packet_number,
                session_id=segment.session_id,
                unit_id=header.unit_id,
                transaction_id=header.transaction_id,
                function_code=function_code,
                function_name=FUNCTION_CODE_NAME.get(function_code, "Unknown"),
                kind=classify_function_code(function_code),
                direction=direction,
                src_ip=segment.src_ip,
                dst_ip=segment.dst_ip,
                timestamp=segment.timestamp,
            )
        )

    return events
