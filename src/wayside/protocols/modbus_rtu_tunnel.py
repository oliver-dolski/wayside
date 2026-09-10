"""A discriminator for a Modbus RTU frame tunnelled over TCP without an
MBAP header: a second, positive test called ONLY after MBAP validation
fails (`wayside.protocols.modbus_tcp.validate_mbap`, assumption Z-17 in
03-04-PLAN.md).

This module does NOT decode native Modbus/TCP - that is what
`wayside.protocols.modbus_tcp.dissect_all` is for - and does NOT return
results into `protocol_events`: every recognition from this module goes into
a SEPARATE type (`LowConfidenceEvent`), in a SEPARATE model list
(`analysis["low_confidence_events"]`), because a checksum match is a
low-confidence recognition, never a confident protocol recognition
(assumption Z-18, threats T-3-13/T-3-16). The Phase 2 check engine reads
`protocol_events` only - the separation is structural, not a flag on a
shared list.

Source for the address byte range and the checksum parameters: "MODBUS over
Serial Line Specification and Implementation Guide V1.02" (Modbus.org, Dec
20, 2006), retrieved 2026-09-04 from the Wayback Machine archive (the live
modbus.org/specs.php refused the connection through a WAF in that
executor's session):
web.archive.org/web/20250910152913/https://www.modbus.org/docs/Modbus_over_serial_line_V1_02.pdf

[VERIFIED], not [CITED] and not [ASSUMED] - the phase research
(03-RESEARCH.md Pattern 3, Assumption A3) marked both values as unconfirmed
against the primary source; this task closes that verification by reading
the document directly:

- Address byte range (chapter 2.2 "MODBUS Addressing rules", p. 8): the
  addressing space covers 256 values - 0 is the broadcast address, 1 to 247
  are individual device addresses ("Slave individual addresses"), 248 to 255
  are reserved.
- The CRC16 algorithm (chapter 6.2.2 "CRC Generation", p. 39, "A procedure
  for generating a CRC"): initial register `0xFFFF`; every message byte is
  XORed with the low byte of the register; then eight right shifts of the
  register, and whenever the bit pushed out by a shift is a one, the register
  is additionally XORed with the polynomial in reversed form `0xA001`; when
  inserted into the frame the low CRC byte goes first, the high byte second
  (Figure 30 "CRC Byte Sequence", p. 39).
- Test vector: the same document, "Example of CRC calculation (frame 02 07)"
  (p. 41) together with Figure 30 (p. 39) - for a two-byte frame `0x02 0x07`
  the final CRC register is `0x1241`, placed in the frame as the bytes `0x41
  0x12` (low byte first). That same vector is the PROTO-03 machine gate in
  `tests/test_modbus_rtu_tunnel.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from wayside.decode import Segment  # noqa: F401 - the detect_all parameter type
from wayside.protocols.modbus_tcp import (
    FUNCTION_CODE_KIND,
    FUNCTION_CODE_NAME,
    validate_mbap,
)

__all__ = [
    "RTU_MIN_FRAME_LEN",
    "RTU_ADDRESS_MIN",
    "RTU_ADDRESS_MAX",
    "CONFIDENCE_LOW",
    "RTU_DETECTION_BASIS",
    "LowConfidenceEvent",
    "modbus_crc16",
    "looks_like_rtu_frame",
    "detect_all",
]

# Address 1B + function code 1B + checksum 2B - an RTU frame shorter than
# that does not carry even the minimal fields required for recognition
# (T-3-14).
RTU_MIN_FRAME_LEN = 4

# The unit address (Unit ID) range for a frame addressed to a single device -
# the source is in the module docstring, chapter 2.2.
RTU_ADDRESS_MIN = 1
RTU_ADDRESS_MAX = 247

# The recognition confidence level - the discriminator matches a checksum,
# not the frame structure directly, so the recognition is never confident
# (assumption Z-18).
CONFIDENCE_LOW = "low"

# The name of the recognition basis, repeated in every LowConfidenceEvent and
# in the text of the report warning - one named constant, not a literal
# scattered through the code.
RTU_DETECTION_BASIS = "crc16-modbus-match"

# The protocol name written into LowConfidenceEvent.protocol - one place, so
# that pipeline.py and the tests do not have to repeat the literal.
_RTU_PROTOCOL_NAME = "modbus-rtu-over-tcp"

# The CRC16/Modbus polynomial in reversed form and the initial register - the
# source is in the module docstring, chapter 6.2.2.
_CRC_INITIAL_REGISTER = 0xFFFF
_CRC_POLYNOMIAL_REVERSED = 0xA001


@dataclass(frozen=True)
class LowConfidenceEvent:
    """A recognition of a Modbus RTU frame tunnelled over TCP, based ONLY
    on a checksum match.

    This type is deliberately NOT a protocol event in the `ModbusEvent`
    sense: it does not enter `protocol_events`, it is not input for the check
    engine and it carries no payload byte (the same reason as `Evidence` in
    `model.py`). `confidence` and `basis` always equal `CONFIDENCE_LOW` and
    `RTU_DETECTION_BASIS` respectively - the fields exist on the record so
    that every consumer of the model (the report, a future check) has the
    confidence level at hand without reaching for a module constant.
    """

    packet_number: int
    session_id: int
    protocol: str
    confidence: str
    basis: str
    unit_id: int
    function_code: int
    function_name: str
    kind: str
    is_exception: bool
    src_ip: str
    dst_ip: str
    timestamp: float


def modbus_crc16(data: bytes) -> int:
    """Computes CRC16/Modbus over `data`. A pure function, with no state.

    The initial register, the reversed polynomial and the shift order follow
    the procedure described in the module docstring (chapter 6.2.2). For an
    empty sequence it returns the initial register untouched - the loop over
    bytes does not execute even once.
    """
    crc = _CRC_INITIAL_REGISTER
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ _CRC_POLYNOMIAL_REVERSED
            else:
                crc >>= 1
    return crc


def looks_like_rtu_frame(raw: bytes) -> bool:
    """Checks whether `raw` looks like a raw Modbus RTU frame with a valid
    checksum. Returns a `bool`, never raises.

    The order of checks is required (threat T-3-14, the same order as
    `validate_mbap`): length BEFORE any indexed access, then the address
    byte, then the function code byte, and the checksum last - each earlier
    condition ends the function with `False` before it reaches the more
    expensive check.
    """
    if len(raw) < RTU_MIN_FRAME_LEN:
        return False

    address_byte = raw[0]
    if not (RTU_ADDRESS_MIN <= address_byte <= RTU_ADDRESS_MAX):
        return False

    function_byte = raw[1]
    function_code = function_byte & 0x7F
    if function_code not in FUNCTION_CODE_KIND:
        return False

    body, crc_bytes = raw[:-2], raw[-2:]
    computed = modbus_crc16(body)
    transmitted = crc_bytes[0] | (crc_bytes[1] << 8)  # low byte first
    return computed == transmitted


def detect_all(segments: list[Segment]) -> list[LowConfidenceEvent]:
    """The RTU-over-TCP discriminator over the FULL segment list, in file
    order.

    For every segment it FIRST calls `validate_mbap` and skips the segment
    when validation returned anything other than `None` - that is a property
    of THIS module (assumption Z-17), not an obligation of the caller:
    `pipeline.py` calls `detect_all` on the same segment list as
    `modbus_tcp.dissect_all`, and the mutual exclusion between them is
    guaranteed here.
    """
    events: list[LowConfidenceEvent] = []

    for segment in segments:
        if validate_mbap(segment.payload) is not None:
            continue

        raw = segment.payload
        if not looks_like_rtu_frame(raw):
            continue

        unit_id = raw[0]
        function_byte = raw[1]
        is_exception = bool(function_byte & 0x80)
        function_code = function_byte & 0x7F

        events.append(
            LowConfidenceEvent(
                packet_number=segment.packet_number,
                session_id=segment.session_id,
                protocol=_RTU_PROTOCOL_NAME,
                confidence=CONFIDENCE_LOW,
                basis=RTU_DETECTION_BASIS,
                unit_id=unit_id,
                function_code=function_code,
                function_name=FUNCTION_CODE_NAME.get(function_code, "Unknown"),
                kind=FUNCTION_CODE_KIND.get(function_code, "unknown"),
                is_exception=is_exception,
                src_ip=segment.src_ip,
                dst_ip=segment.dst_ip,
                timestamp=segment.timestamp,
            )
        )

    return events
