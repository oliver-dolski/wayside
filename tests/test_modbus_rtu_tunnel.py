"""Bramka maszynowa PROTO-03: suma kontrolna, granice zakresu adresu, przypadek
negatywny na fixture'ach Modbus/TCP (plan 03-04, Task 1).

Wzorzec identyczny jak w `tests/test_modbus_tcp.py`: budowa surowych bajtow w
tescie przez `struct.pack`, funkcja pomocnicza sklejajaca cialo ramki z suma
kontrolna, zeby przypadek pozytywny i negatywny roznily sie jedna wartoscia,
nie calym literalem.

Test wektora testowego (`test_modbus_crc16_matches_specification_worked_example`)
uzywa wartosci wprost z "MODBUS over Serial Line Specification and
Implementation Guide V1.02" (Modbus.org, Dec 20, 2006), rozdzial 6.2.2
"Example of CRC calculation (frame 02 07)" (str. 41) razem z Figure 30
(str. 39) - zrodlo zapisane takze w docstringu
`wayside.protocols.modbus_rtu_tunnel`.
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
    """Skleja cialo ramki z suma kontrolna w porzadku bajtu mlodszego jako
    pierwszego - przypadek pozytywny i negatywny w tym pliku roznia sie
    wylacznie wartoscia przekazana do `body` albo pojedynczym bajtem
    dopisanym po tej funkcji, nigdy calym literalem ramki."""
    return body + struct.pack("<H", modbus_crc16(body))


def _write_single_register_body(*, address: int = 1) -> bytes:
    """Cialo szesciobajtowe: adres, kod funkcji 0x06 (Write Single Register),
    adres rejestru 0x0001, wartosc 0x002A - dokladnie ta sama tresc funkcjonalna
    co fixture'y Modbus/TCP z Fazy 2, tylko bez naglowka MBAP."""
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
    """Wektor testowy z "MODBUS over Serial Line Specification and
    Implementation Guide V1.02", rozdzial 6.2.2, "Example of CRC calculation
    (frame 02 07)" (str. 41): dla ramki dwubajtowej `02 07` rejestr CRC
    koncowy wynosi `0x1241` (Figure 30, str. 39, ten sam dokument, ta sama
    wartosc przykladowa zapisana jako "1241 hex")."""
    assert modbus_crc16(bytes([0x02, 0x07])) == 0x1241


def test_modbus_crc16_remainder_property_holds_on_several_byte_strings():
    """Suma policzona nad dowolnym ciagiem `d` z dolaczonymi dwoma bajtami
    wlasnej sumy (bajt mlodszy pierwszy) wynosi zero - wlasnosc trzyma sie
    niezaleznie od dlugosci `d`, w tym dla ciagu pustego i jednobajtowego,
    wiec jest bramka na kazda zamiane wielomianu albo kolejnosci bajtow,
    ktora jeden literalny wektor testowy przepuscilby przypadkiem."""
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
    # Naglowek MBAP poprawny (transId=1, protoId=0, length=2, unitId=1) plus
    # kod funkcji - ten segment przechodzi validate_mbap, wiec detect_all
    # NIGDY nie sprawdza go suma kontrolna, niezaleznie od tego, co jest w
    # ciele za naglowkiem.
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


# --- detect_all: przypadek negatywny na trzech fixture'ach Modbus/TCP ------
# (dwa dowodza pierwszenstwa bramy MBAP, trzeci dowodzi, ze ladunek oblewajacy
# walidacje MBAP nie dopasowuje sie do sumy kontrolnej przypadkiem)


def test_detect_all_returns_empty_list_on_three_existing_modbus_tcp_fixtures():
    for fixture in (
        FIXTURE_WRITE_SINGLE_REGISTER,
        FIXTURE_NON_STANDARD_PORT,
        FIXTURE_MALFORMED_MBAP,
    ):
        packets = pcap.read_capture(REPO_ROOT / fixture)
        segments = decode.decode_segments(packets)
        assert detect_all(segments) == [], fixture
