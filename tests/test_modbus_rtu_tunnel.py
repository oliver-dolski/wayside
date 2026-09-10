"""Machine gate PROTO-03: the checksum, the address range boundaries, the
negative case over the Modbus/TCP fixtures (plan 03-04, Task 1).

The pattern is identical to `tests/test_modbus_tcp.py`: raw bytes built in the
test by `struct.pack`, a helper joining the frame body with its checksum, so
that the positive and the negative case differ by one value rather than by a
whole literal.

The test vector test (`test_modbus_crc16_matches_specification_worked_example`)
uses values taken straight from "MODBUS over Serial Line Specification and
Implementation Guide V1.02" (Modbus.org, Dec 20, 2006), section 6.2.2
"Example of CRC calculation (frame 02 07)" (p. 41) together with Figure 30
(p. 39) - the source is recorded in the docstring of
`wayside.protocols.modbus_rtu_tunnel` as well.
"""

from __future__ import annotations

import struct
from pathlib import Path

from wayside import decode, pcap
from wayside.decode import Segment
from wayside.protocols.modbus_rtu_tunnel import (
    CONFIDENCE_LOW,
    RTU_ADDRESS_MAX,
    RTU_ADDRESS_MIN,
    RTU_DETECTION_BASIS,
    RTU_MIN_FRAME_LEN,
    detect_all,
    looks_like_rtu_frame,
    modbus_crc16,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

FIXTURE_WRITE_SINGLE_REGISTER = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_NON_STANDARD_PORT = "tests/fixtures/pcap/modbus_write_non_standard_port.pcap"
FIXTURE_MALFORMED_MBAP = "tests/fixtures/pcap/modbus_malformed_mbap.pcap"


def _rtu_frame(body: bytes) -> bytes:
    """Joins the frame body with its checksum in least significant byte first
    order - the positive and the negative case in this file differ only in the
    value passed to `body`, or in a single byte appended after this function,
    never in a whole frame literal."""
    return body + struct.pack("<H", modbus_crc16(body))


def _write_single_register_body(*, address: int = 1) -> bytes:
    """A six-byte body: the address, function code 0x06 (Write Single
    Register), register address 0x0001, value 0x002A - exactly the same
    functional content as the Phase 2 Modbus/TCP fixtures, only without the
    MBAP header."""
    return struct.pack(">BBHH", address, 0x06, 0x0001, 0x002A)


def _make_segment(payload: bytes, *, packet_number: int = 1, session_id: int = 0) -> Segment:
    return Segment(
        packet_number=packet_number,
        session_id=session_id,
        timestamp=1700000000.0 + packet_number * 0.01,
        src_ip="192.0.2.10",
        src_port=50500,
        dst_ip="192.0.2.20",
        dst_port=10502,
        payload=payload,
        src_mac="02:00:00:00:00:01",
        dst_mac="02:00:00:00:00:02",
    )


# --- modbus_crc16: rejestr poczatkowy, wektor testowy, wlasnosc reszty -----


def test_modbus_crc16_of_empty_bytes_is_untouched_initial_register():
    assert modbus_crc16(b"") == 0xFFFF


def test_modbus_crc16_matches_specification_worked_example():
    """The test vector from "MODBUS over Serial Line Specification and
    Implementation Guide V1.02", section 6.2.2, "Example of CRC calculation
    (frame 02 07)" (p. 41): for the two-byte frame `02 07` the final CRC
    register is `0x1241` (Figure 30, p. 39, the same document, the same worked
    value written there as "1241 hex")."""
    assert modbus_crc16(bytes([0x02, 0x07])) == 0x1241


def test_modbus_crc16_remainder_property_holds_on_several_byte_strings():
    """The checksum computed over any string `d` with the two bytes of its own
    checksum appended (least significant byte first) is zero - the property
    holds regardless of the length of `d`, including the empty and the
    one-byte string, so it is a gate against every swap of the polynomial or
    of the byte order that a single literal test vector could let through by
    accident."""
    for body in (b"", b"\x01", b"\x01\x06\x00\x01\x00\x2a", bytes([0x02, 0x07])):
        crc = modbus_crc16(body)
        appended = body + struct.pack("<H", crc)
        assert modbus_crc16(appended) == 0


# --- looks_like_rtu_frame: dlugosc PRZED indeksowaniem (T-3-14) ------------


def test_looks_like_rtu_frame_rejects_empty_bytes_without_indexing():
    assert looks_like_rtu_frame(b"") is False


def test_looks_like_rtu_frame_rejects_three_byte_input_below_minimum():
    assert len(b"\x01\x06\x00") < RTU_MIN_FRAME_LEN
    assert looks_like_rtu_frame(b"\x01\x06\x00") is False


# --- looks_like_rtu_frame: granice zakresu adresu --------------------------


def test_looks_like_rtu_frame_accepts_address_at_lower_boundary():
    assert RTU_ADDRESS_MIN == 1
    frame = _rtu_frame(_write_single_register_body(address=RTU_ADDRESS_MIN))
    assert looks_like_rtu_frame(frame) is True


def test_looks_like_rtu_frame_accepts_address_at_upper_boundary():
    assert RTU_ADDRESS_MAX == 247
    frame = _rtu_frame(_write_single_register_body(address=RTU_ADDRESS_MAX))
    assert looks_like_rtu_frame(frame) is True


def test_looks_like_rtu_frame_rejects_broadcast_address_zero():
    frame = _rtu_frame(_write_single_register_body(address=0))
    assert looks_like_rtu_frame(frame) is False


def test_looks_like_rtu_frame_rejects_reserved_address_248():
    frame = _rtu_frame(_write_single_register_body(address=248))
    assert looks_like_rtu_frame(frame) is False


# --- looks_like_rtu_frame: kod funkcji ---------------------------------------


def test_looks_like_rtu_frame_rejects_function_code_outside_table():
    body = struct.pack(">BBHH", 1, 0x00, 0x0001, 0x002A)  # 0x00 poza tabela
    assert looks_like_rtu_frame(_rtu_frame(body)) is False


def test_looks_like_rtu_frame_accepts_exception_bit_with_otherwise_valid_frame():
    body = struct.pack(">BBHH", 1, 0x06 | 0x80, 0x0001, 0x002A)
    assert looks_like_rtu_frame(_rtu_frame(body)) is True


# --- looks_like_rtu_frame: suma kontrolna niezgodna -------------------------


def test_looks_like_rtu_frame_rejects_frame_with_one_flipped_bit_in_body():
    good_body = _write_single_register_body()
    good_frame = _rtu_frame(good_body)
    corrupted_body = bytearray(good_body)
    corrupted_body[0] ^= 0x01  # jeden przekrecony bit w bajcie adresu
    corrupted_frame = bytes(corrupted_body) + good_frame[-2:]
    assert looks_like_rtu_frame(corrupted_frame) is False


# --- detect_all: lista pusta, brama MBAP, kolejnosc pliku -------------------


def test_detect_all_on_empty_segment_list_returns_empty_list():
    assert detect_all([]) == []


def test_detect_all_skips_segment_that_passes_mbap_validation():
    # A valid MBAP header (transId=1, protoId=0, length=2, unitId=1) plus a
    # function code - this segment passes validate_mbap, so detect_all NEVER
    # checks it by checksum, regardless of what stands in the body after the
    # header.
    mbap_payload = struct.pack(">HHH", 1, 0, 2) + bytes([1, 0x06])
    segment = _make_segment(mbap_payload)
    assert detect_all([segment]) == []


def test_detect_all_returns_one_event_with_confidence_low_and_basis():
    frame = _rtu_frame(_write_single_register_body())
    segment = _make_segment(frame, packet_number=1, session_id=0)

    events = detect_all([segment])

    assert len(events) == 1
    event = events[0]
    assert event.confidence == CONFIDENCE_LOW
    assert event.basis == RTU_DETECTION_BASIS
    assert event.protocol == "modbus-rtu-over-tcp"
    assert event.unit_id == 1
    assert event.function_code == 0x06
    assert event.function_name == "Write Single Register"
    assert event.kind == "write"
    assert event.is_exception is False


def test_detect_all_preserves_file_order_across_two_matching_segments():
    frame = _rtu_frame(_write_single_register_body())
    first = _make_segment(frame, packet_number=1, session_id=0)
    second = _make_segment(frame, packet_number=2, session_id=0)

    events = detect_all([first, second])

    assert [event.packet_number for event in events] == [1, 2]


# --- detect_all: the negative case over three Modbus/TCP fixtures ----------
# (two prove the precedence of the MBAP gate, the third proves that a payload
# failing MBAP validation does not match the checksum by accident)


def test_detect_all_returns_empty_list_on_three_existing_modbus_tcp_fixtures():
    for fixture in (
        FIXTURE_WRITE_SINGLE_REGISTER,
        FIXTURE_NON_STANDARD_PORT,
        FIXTURE_MALFORMED_MBAP,
    ):
        packets = pcap.read_capture(REPO_ROOT / fixture)
        segments = decode.decode_segments(packets)
        assert detect_all(segments) == [], fixture


# --- Task 2: the fixture generator - two independent implementations of ----
# the checksum agree on every test vector used in Task 1
# --------------------------------------------------------------------------


def _load_gen_fixtures_module():
    """Loads `scripts/gen_fixtures.py` as a module through
    `importlib.util.spec_from_file_location` - the same way the check engine
    (`wayside.checks.engine._load_evaluator`) loads the evaluator sitting next
    to its YAML, so that importing by path stays consistent with the only
    other place in the project that needs it."""
    import importlib.util

    module_path = REPO_ROOT / "scripts" / "gen_fixtures.py"
    spec = importlib.util.spec_from_file_location("gen_fixtures", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_rtu_crc16_in_generator_agrees_with_module_crc16_on_every_vector():
    gen_fixtures = _load_gen_fixtures_module()

    for body in (b"", b"\x01", b"\x01\x06\x00\x01\x00\x2a", bytes([0x02, 0x07])):
        assert gen_fixtures._rtu_crc16(body) == modbus_crc16(body), body


# --- Task 2: fixture generowany - dwa ladunki oblewaja MBAP, przechodza ---
# dyskryminator
# --------------------------------------------------------------------------


def test_generated_fixture_payloads_reject_mbap_and_pass_discriminator():
    from wayside.protocols.modbus_tcp import validate_mbap

    fixture_path = REPO_ROOT / "tests/fixtures/pcap/modbus_rtu_over_tcp.pcap"
    packets = pcap.read_capture(fixture_path)
    segments = decode.decode_segments(packets)

    assert len(segments) == 2
    for segment in segments:
        assert validate_mbap(segment.payload) is None
        assert looks_like_rtu_frame(segment.payload) is True

    events = detect_all(segments)
    assert [event.packet_number for event in events] == [1, 2]
