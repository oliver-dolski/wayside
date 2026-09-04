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
