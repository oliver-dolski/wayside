"""Bramka maszynowa ASSET-01: `build_assets` scala hosty po adresie IP,
przypisuje adres MAC wedlug zalozenia Z-03, zachowuje kolejnosc pierwszego
zaobserwowania i zwraca liste pusta na zrzucie bez segmentow (plan 03-01,
Task 2).

`decode.Segment` budowany bezposrednio w tym pliku, bez pliku pcap i bez
subprocessu - `build_assets` jest czysta funkcja nad lista segmentow. Zaden
adres tutaj nie pochodzi z zadnej rzeczywistej sieci: adresy IP z zakresu
dokumentacyjnego RFC 5737 (192.0.2.0/24), adresy MAC lokalnie administrowane
(prefiks `02:`) - dokladnie jak `scripts/gen_fixtures.py`.
"""

from __future__ import annotations

from wayside.assets.inventory import build_assets
from wayside.decode import Segment

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
THIRD_IP = "192.0.2.30"

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
THIRD_MAC = "02:00:00:00:00:03"
ALT_CLIENT_MAC = "02:00:00:00:00:04"


def _segment(
    *,
    packet_number: int,
    session_id: int,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    src_mac: str | None,
    dst_mac: str | None,
    timestamp: float = 0.0,
    payload: bytes = b"x",
) -> Segment:
    return Segment(
        packet_number=packet_number,
        session_id=session_id,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=payload,
        src_mac=src_mac,
        dst_mac=dst_mac,
    )


# --- empty: zrzut bez segmentow daje pusta liste -----------------------------


def test_empty_segment_list_returns_empty_list():
    assert build_assets(segments=[]) == []


# --- pojedynczy segment: dwa wpisy, nadawca a potem odbiorca -----------------


def test_single_segment_gives_two_hosts_sender_then_receiver():
    segments = [
        _segment(
            packet_number=1,
            session_id=0,
            src_ip=CLIENT_IP,
            src_port=50000,
            dst_ip=SERVER_IP,
            dst_port=502,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
        )
    ]

    assets = build_assets(segments=segments)

    assert [entry["ip"]["value"] for entry in assets] == [CLIENT_IP, SERVER_IP]


def test_mac_present_when_ether_layer_observed():
    segments = [
        _segment(
            packet_number=1,
            session_id=0,
            src_ip=CLIENT_IP,
            src_port=50000,
            dst_ip=SERVER_IP,
            dst_port=502,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
        )
    ]

    assets = build_assets(segments=segments)

    assert assets[0]["ip"] == {"value": CLIENT_IP, "provenance": "observed"}
    assert assets[0]["mac"] == {"value": CLIENT_MAC, "provenance": "observed"}
    assert assets[1]["ip"] == {"value": SERVER_IP, "provenance": "observed"}
    assert assets[1]["mac"] == {"value": SERVER_MAC, "provenance": "observed"}


# --- adjacency: dwa kierunki tej samej pary daja dwa wpisy, nie cztery ------


def test_adjacency_two_opposite_direction_segments_give_two_hosts_not_four():
    request = _segment(
        packet_number=1,
        session_id=0,
        src_ip=CLIENT_IP,
        src_port=50000,
        dst_ip=SERVER_IP,
        dst_port=502,
        src_mac=CLIENT_MAC,
        dst_mac=SERVER_MAC,
    )
    response = _segment(
        packet_number=2,
        session_id=0,
        src_ip=SERVER_IP,
        src_port=502,
        dst_ip=CLIENT_IP,
        dst_port=50000,
        src_mac=SERVER_MAC,
        dst_mac=CLIENT_MAC,
    )

    assets = build_assets(segments=[request, response])

    assert len(assets) == 2
    assert [entry["ip"]["value"] for entry in assets] == [CLIENT_IP, SERVER_IP]


# --- Z-03, galaz pierwsza: adres MAC nieobecny przy pierwszym napotkaniu ---


def test_mac_absent_at_first_encounter_gives_not_derivable():
    segments = [
        _segment(
            packet_number=1,
            session_id=0,
            src_ip=CLIENT_IP,
            src_port=50000,
            dst_ip=SERVER_IP,
            dst_port=502,
            src_mac=None,
            dst_mac=None,
        )
    ]

    assets = build_assets(segments=segments)

    assert assets[0]["mac"] == {"value": None, "provenance": "not-derivable-passively"}
    assert assets[1]["mac"] == {"value": None, "provenance": "not-derivable-passively"}


# --- Z-03, galaz druga: adres MAC niezgodny przy powtornym napotkaniu ------


def test_two_different_macs_for_same_ip_gives_not_derivable():
    first_seen = _segment(
        packet_number=1,
        session_id=0,
        src_ip=CLIENT_IP,
        src_port=50000,
        dst_ip=SERVER_IP,
        dst_port=502,
        src_mac=CLIENT_MAC,
        dst_mac=SERVER_MAC,
    )
    second_seen_different_mac = _segment(
        packet_number=2,
        session_id=1,
        src_ip=CLIENT_IP,
        src_port=50001,
        dst_ip=SERVER_IP,
        dst_port=502,
        src_mac=ALT_CLIENT_MAC,
        dst_mac=SERVER_MAC,
    )

    assets = build_assets(segments=[first_seen, second_seen_different_mac])

    client_entry = next(entry for entry in assets if entry["ip"]["value"] == CLIENT_IP)
    assert client_entry["mac"] == {"value": None, "provenance": "not-derivable-passively"}
    # Adres serwera niezmieniony w obu segmentach - zostaje "observed".
    server_entry = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)
    assert server_entry["mac"] == {"value": SERVER_MAC, "provenance": "observed"}


# --- ordering: kolejnosc pierwszego napotkania, identyczna przy powtorzeniu -


def test_ordering_is_first_seen_order_and_deterministic_across_repeated_calls():
    seg_a = _segment(
        packet_number=1,
        session_id=0,
        src_ip=THIRD_IP,
        src_port=1,
        dst_ip=CLIENT_IP,
        dst_port=502,
        src_mac=THIRD_MAC,
        dst_mac=CLIENT_MAC,
    )
    seg_b = _segment(
        packet_number=2,
        session_id=1,
        src_ip=SERVER_IP,
        src_port=502,
        dst_ip=THIRD_IP,
        dst_port=1,
        src_mac=SERVER_MAC,
        dst_mac=THIRD_MAC,
    )
    segments = [seg_a, seg_b]

    first_run = [entry["ip"]["value"] for entry in build_assets(segments=segments)]
    second_run = [entry["ip"]["value"] for entry in build_assets(segments=segments)]

    assert first_run == second_run
    assert first_run == [THIRD_IP, CLIENT_IP, SERVER_IP]
