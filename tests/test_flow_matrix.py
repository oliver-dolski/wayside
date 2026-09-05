"""Bramka maszynowa FLOW-01 i FLOW-02: strona inicjujaca sesje z pakietu
uzgodnienia polaczenia oraz macierz komunikacji ze zrodlem, celem, kierunkiem,
protokolem i wolumenem (plan 03-07).

Pakiety syntetyczne budowane w tym pliku przez scapy, bez przejscia przez dysk -
`find_session_initiators` przyjmuje liste pakietow, wiec test nie potrzebuje pliku.
Adresacja z zakresu dokumentacyjnego RFC 5737 (192.0.2.0/24), adresy warstwy
drugiej lokalnie administrowane (prefiks `02:`), dokladnie jak
`scripts/gen_fixtures.py`. Zaden adres nie pochodzi z zadnej rzeczywistej sieci.

`test_initiator_from_syn_when_present` jest czescia kontraktu wymaganie na test
z `03-VALIDATION.md`, nazwa nie ulega zmianie.
"""

from __future__ import annotations

import wayside.pcap  # noqa: F401  - izolacja cache scapy PRZED importem warstw

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402

from wayside.decode import (  # noqa: E402
    SessionInitiator,
    decode_segments,
    find_session_initiators,
)
from wayside.flow import PROTOCOL_UNRECOGNIZED, build_comm_matrix  # noqa: E402
from wayside.model import assert_provenance_complete  # noqa: E402
from wayside.pcap import read_capture  # noqa: E402

FIXTURE_HANDSHAKE = "tests/fixtures/pcap/modbus_tcp_handshake.pcap"
FIXTURE_NO_HANDSHAKE = "tests/fixtures/pcap/modbus_write_single_register.pcap"

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 50400
SERVER_PORT = 502


def _packet(*, flags: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
            src_mac: str, dst_mac: str, payload: bytes = b""):
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=src_port, dport=dst_port, flags=flags)
    )
    if payload:
        pkt = pkt / payload
    return pkt


def _syn():
    return _packet(
        flags="S",
        src_ip=CLIENT_IP, src_port=CLIENT_PORT,
        dst_ip=SERVER_IP, dst_port=SERVER_PORT,
        src_mac=CLIENT_MAC, dst_mac=SERVER_MAC,
    )


def _syn_ack():
    return _packet(
        flags="SA",
        src_ip=SERVER_IP, src_port=SERVER_PORT,
        dst_ip=CLIENT_IP, dst_port=CLIENT_PORT,
        src_mac=SERVER_MAC, dst_mac=CLIENT_MAC,
    )


def _ack():
    return _packet(
        flags="A",
        src_ip=CLIENT_IP, src_port=CLIENT_PORT,
        dst_ip=SERVER_IP, dst_port=SERVER_PORT,
        src_mac=CLIENT_MAC, dst_mac=SERVER_MAC,
    )


def _data(payload: bytes = b"payload"):
    return _packet(
        flags="PA",
        src_ip=CLIENT_IP, src_port=CLIENT_PORT,
        dst_ip=SERVER_IP, dst_port=SERVER_PORT,
        src_mac=CLIENT_MAC, dst_mac=SERVER_MAC,
        payload=payload,
    )


# --- find_session_initiators (Task 1) ---------------------------------------


def test_empty_input_gives_empty_mapping():
    assert find_session_initiators([], []) == {}


def test_initiator_from_syn_when_present():
    packets = [_syn(), _syn_ack(), _ack(), _data()]
    segments = decode_segments(packets)

    initiators = find_session_initiators(packets, segments)

    assert len(initiators) == 1
    initiator = next(iter(initiators.values()))
    assert isinstance(initiator, SessionInitiator)
    assert initiator.ip == CLIENT_IP
    assert initiator.port == CLIENT_PORT


def test_syn_ack_packet_alone_creates_no_entry():
    packets = [_syn_ack(), _data()]
    segments = decode_segments(packets)

    assert find_session_initiators(packets, segments) == {}


def test_ack_only_packet_creates_no_entry():
    packets = [_ack(), _data()]
    segments = decode_segments(packets)

    assert find_session_initiators(packets, segments) == {}


def test_two_syn_packets_for_one_session_take_the_first_in_file_order():
    first = _syn()
    second = _packet(
        flags="S",
        src_ip=SERVER_IP, src_port=SERVER_PORT,
        dst_ip=CLIENT_IP, dst_port=CLIENT_PORT,
        src_mac=SERVER_MAC, dst_mac=CLIENT_MAC,
    )
    packets = [first, second, _data()]
    segments = decode_segments(packets)

    initiator = next(iter(find_session_initiators(packets, segments).values()))

    assert (initiator.ip, initiator.port) == (CLIENT_IP, CLIENT_PORT)


def test_syn_for_endpoint_pair_absent_from_segments_creates_no_entry():
    """Sesja bez ani jednego segmentu z ladunkiem nie wystepuje w zadnej innej
    sekcji modelu (zalozenie Z-31), wiec nie dostaje tu wpisu - inaczej klucze
    slownika rozjechalyby sie z numeracja `decode_segments`."""
    stray_syn = _packet(
        flags="S",
        src_ip="192.0.2.99", src_port=40000,
        dst_ip="192.0.2.98", dst_port=502,
        src_mac="02:00:00:00:00:09", dst_mac="02:00:00:00:00:08",
    )
    packets = [stray_syn, _syn(), _data()]
    segments = decode_segments(packets)

    initiators = find_session_initiators(packets, segments)

    assert len(initiators) == 1
    assert next(iter(initiators.values())).ip == CLIENT_IP


def test_mapping_keys_are_session_ids_matching_segment_session_id():
    packets = [_syn(), _data()]
    segments = decode_segments(packets)

    initiators = find_session_initiators(packets, segments)

    assert set(initiators) == {segment.session_id for segment in segments}


def test_handshake_fixture_gives_client_endpoint_as_initiator():
    packets = read_capture(FIXTURE_HANDSHAKE)
    segments = decode_segments(packets)

    initiators = find_session_initiators(packets, segments)

    assert len(initiators) == 1
    initiator = next(iter(initiators.values()))
    assert (initiator.ip, initiator.port) == ("192.0.2.10", 50400)


def test_fixture_without_handshake_gives_empty_mapping():
    """Polowa, bez ktorej funkcja zwracajaca zawsze pierwszego nadawce
    przeszlaby test pozytywny."""
    packets = read_capture(FIXTURE_NO_HANDSHAKE)
    segments = decode_segments(packets)

    assert find_session_initiators(packets, segments) == {}


# --- build_comm_matrix (Task 2) ---------------------------------------------


def _event(*, session_id: int, unit_id: int = 1, protocol: str = "modbus-tcp") -> dict:
    return {
        "packet_number": 1,
        "session_id": session_id,
        "protocol": protocol,
        "confidence": "high",
        "unit_id": unit_id,
        "transaction_id": 1,
        "function_code": 0x06,
        "function_name": "Write Single Register",
        "kind": "write",
        "direction": "request",
        "src_ip": CLIENT_IP,
        "dst_ip": SERVER_IP,
        "timestamp": 0.0,
    }


def _low_confidence_event(*, session_id: int) -> dict:
    return {
        "packet_number": 1,
        "session_id": session_id,
        "protocol": "modbus-rtu-over-tcp",
        "confidence": "low",
        "basis": "crc16-modbus-match",
    }


def test_build_comm_matrix_on_empty_input_returns_empty_list():
    assert build_comm_matrix(
        packets=[], segments=[], events=[], low_confidence_events=[], initiators={}
    ) == []


def test_session_without_protocol_event_gets_row_with_protocol_tcp():
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[], initiators={},
    )

    assert len(matrix) == 1
    assert matrix[0]["protocol"] == {
        "value": PROTOCOL_UNRECOGNIZED,
        "provenance": "observed",
    }


def test_session_with_modbus_event_gets_protocol_modbus_tcp():
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments,
        events=[_event(session_id=segments[0].session_id)],
        low_confidence_events=[], initiators={},
    )

    assert matrix[0]["protocol"] == {
        "value": "modbus-tcp",
        "provenance": "inferred:payload-shape",
    }


def test_session_with_only_low_confidence_event_gets_protocol_rtu_tunnel():
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[_low_confidence_event(session_id=segments[0].session_id)],
        initiators={},
    )

    assert matrix[0]["protocol"] == {
        "value": "modbus-rtu-over-tcp",
        "provenance": "inferred:payload-shape",
    }


def test_session_with_made_up_protocol_id_gets_label_from_data():
    """Dowod, ze etykieta idzie z danych: identyfikator wymyslony, nieobecny
    nigdzie w kodzie pod `src/wayside/`, wciaz staje sie etykieta wiersza
    bez zadnej zmiany w `flow.py` (PROTO-05)."""
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments,
        events=[_event(session_id=segments[0].session_id, protocol="fictional-protocol-x")],
        low_confidence_events=[], initiators={},
    )

    assert matrix[0]["protocol"] == {
        "value": "fictional-protocol-x",
        "provenance": "inferred:payload-shape",
    }


def test_session_with_two_high_confidence_protocols_gets_composite_label():
    """Zalozenie Z-43: dwa protokoly o pewnosci wysokiej w tej samej sesji
    daja etykiete zlozona, posortowane identyfikatory rozdzielone znakiem
    plus - nigdy wybor jednego z nich."""
    packets = [_data()]
    segments = decode_segments(packets)
    session_id = segments[0].session_id

    matrix = build_comm_matrix(
        packets=packets, segments=segments,
        events=[
            _event(session_id=session_id, protocol="zeta-protocol"),
            _event(session_id=session_id, protocol="alfa-protocol"),
        ],
        low_confidence_events=[], initiators={},
    )

    assert matrix[0]["protocol"] == {
        "value": "alfa-protocol+zeta-protocol",
        "provenance": "inferred:payload-shape",
    }


def test_session_present_on_both_lists_gets_label_from_high_confidence_only():
    """Sesja obecna na obu listach dostaje etykiete z pola `protocol`
    zdarzenia o pewnosci wysokiej, bez czlonu z listy pewnosci niskiej."""
    packets = [_data()]
    segments = decode_segments(packets)
    session_id = segments[0].session_id

    matrix = build_comm_matrix(
        packets=packets, segments=segments,
        events=[_event(session_id=session_id, protocol="modbus-tcp")],
        low_confidence_events=[_low_confidence_event(session_id=session_id)],
        initiators={},
    )

    assert matrix[0]["protocol"] == {
        "value": "modbus-tcp",
        "provenance": "inferred:payload-shape",
    }


def test_modbus_event_wins_over_low_confidence_event_for_the_same_session():
    """Kolejnosc rozstrzygania jest nieprzemienna: sesja rozpoznana po naglowku
    MBAP jest Modbusem po TCP, nawet gdy niesie w tle segment przypadkiem
    dopasowany suma kontrolna."""
    packets = [_data()]
    segments = decode_segments(packets)
    session_id = segments[0].session_id

    matrix = build_comm_matrix(
        packets=packets, segments=segments,
        events=[_event(session_id=session_id)],
        low_confidence_events=[_low_confidence_event(session_id=session_id)],
        initiators={},
    )

    assert matrix[0]["protocol"]["value"] == "modbus-tcp"


def test_row_order_is_first_seen_session_order_and_repeats_across_calls():
    other = _packet(
        flags="PA",
        src_ip="192.0.2.30", src_port=40000,
        dst_ip=SERVER_IP, dst_port=SERVER_PORT,
        src_mac="02:00:00:00:00:03", dst_mac=SERVER_MAC,
        payload=b"x",
    )
    packets = [other, _data()]
    segments = decode_segments(packets)

    first = [
        row["session_id"]["value"]
        for row in build_comm_matrix(
            packets=packets, segments=segments, events=[],
            low_confidence_events=[], initiators={},
        )
    ]
    second = [
        row["session_id"]["value"]
        for row in build_comm_matrix(
            packets=packets, segments=segments, events=[],
            low_confidence_events=[], initiators={},
        )
    ]

    assert first == second == [0, 1]


def test_row_with_observed_initiator_carries_observed_direction_and_endpoints():
    packets = [_syn(), _syn_ack(), _ack(), _data()]
    segments = decode_segments(packets)
    initiators = find_session_initiators(packets, segments)

    matrix = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[], initiators=initiators,
    )
    row = matrix[0]

    assert row["initiator"] == {
        "value": CLIENT_IP + ":" + str(CLIENT_PORT),
        "provenance": "observed",
    }
    assert row["direction"]["provenance"] == "observed"
    assert row["source"]["provenance"] == "observed"
    assert row["target"]["provenance"] == "observed"


def test_row_without_initiator_has_null_initiator_and_inferred_direction():
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[], initiators={},
    )
    row = matrix[0]

    assert row["initiator"] == {"value": None, "provenance": "not-derivable-passively"}
    assert row["direction"]["provenance"] == "inferred:first-observed-sender"
    assert row["source"]["provenance"] == "inferred:first-observed-sender"
    assert row["target"]["provenance"] == "inferred:first-observed-sender"


def test_direction_value_joins_source_and_target():
    packets = [_data()]
    segments = decode_segments(packets)

    row = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[], initiators={},
    )[0]

    assert row["direction"]["value"] == (
        row["source"]["value"] + " -> " + row["target"]["value"]
    )


def test_volume_counts_all_packets_of_the_session_not_only_payload_bytes():
    """Zalozenie Z-33: wolumen obejmuje pakiety uzgodnienia polaczenia
    i potwierdzenia, wiec jest wiekszy od sumy dlugosci samych ladunkow."""
    packets = read_capture(FIXTURE_HANDSHAKE)
    segments = decode_segments(packets)

    row = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[],
        initiators=find_session_initiators(packets, segments),
    )[0]
    payload_bytes = sum(len(segment.payload) for segment in segments)

    assert row["volume_bytes"]["value"] > payload_bytes
    assert row["volume_bytes"]["provenance"] == "observed"


def test_matrix_packet_count_differs_from_conversations_packet_count():
    """Jedyna obserwowalna konsekwencja zalozenia Z-33: macierz liczy WSZYSTKIE
    pakiety sesji, a `conversations` same segmenty z ladunkiem."""
    packets = read_capture(FIXTURE_HANDSHAKE)
    segments = decode_segments(packets)

    row = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[],
        initiators=find_session_initiators(packets, segments),
    )[0]

    assert row["packet_count"]["value"] == 5
    assert len(segments) == 2


def test_every_matrix_field_carries_provenance():
    packets = [_data()]
    segments = decode_segments(packets)

    matrix = build_comm_matrix(
        packets=packets, segments=segments, events=[],
        low_confidence_events=[], initiators={},
    )

    assert_provenance_complete(matrix, path="comm_matrix")
