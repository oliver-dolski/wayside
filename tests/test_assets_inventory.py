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
from wayside.model import assert_provenance_complete

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


# --- ASSET-02: oui_vendor, vendor_lookup wstrzykiwany (Z-20), plan 03-05 ---


def test_build_assets_without_vendor_lookup_gives_not_derivable_oui_vendor():
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

    assert all(
        entry["oui_vendor"] == {"value": None, "provenance": "not-derivable-passively"}
        for entry in assets
    )


def test_build_assets_with_vendor_lookup_returning_name_gives_inferred_oui_vendor():
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

    assets = build_assets(
        segments=segments,
        vendor_lookup=lambda mac: "Organizacja Testowa" if mac == CLIENT_MAC else None,
    )

    client_entry = next(entry for entry in assets if entry["ip"]["value"] == CLIENT_IP)
    assert client_entry["oui_vendor"] == {
        "value": "Organizacja Testowa",
        "provenance": "inferred:oui-lookup",
    }
    server_entry = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)
    assert server_entry["oui_vendor"] == {"value": None, "provenance": "not-derivable-passively"}


def test_build_assets_vendor_lookup_returning_none_gives_not_derivable_oui_vendor():
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

    assets = build_assets(segments=segments, vendor_lookup=lambda mac: None)

    assert all(
        entry["oui_vendor"] == {"value": None, "provenance": "not-derivable-passively"}
        for entry in assets
    )


def test_build_assets_host_without_mac_never_calls_vendor_lookup():
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
    call_count = 0

    def _counting_lookup(mac: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return "Organizacja Testowa"

    assets = build_assets(segments=segments, vendor_lookup=_counting_lookup)

    assert call_count == 0
    assert all(
        entry["oui_vendor"] == {"value": None, "provenance": "not-derivable-passively"}
        for entry in assets
    )


def test_assert_provenance_complete_passes_on_build_assets_result_with_oui_vendor():
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

    assets = build_assets(
        segments=segments, vendor_lookup=lambda mac: "Organizacja Testowa"
    )

    assert_provenance_complete(assets, path="assets")


def test_build_assets_every_host_entry_carries_oui_vendor_key():
    segments = [
        _segment(
            packet_number=1,
            session_id=0,
            src_ip=CLIENT_IP,
            src_port=50000,
            dst_ip=SERVER_IP,
            dst_port=502,
            src_mac=CLIENT_MAC,
            dst_mac=None,
        )
    ]

    assets = build_assets(segments=segments)

    assert all("oui_vendor" in entry for entry in assets)


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


# --- Unit ID jako podadres i wykrycie prawdopodobnej bramy (plan 03-06, Task 1) ---
#
# Zdarzenia budowane slownikiem, w ksztalcie `analysis["protocol_events"]`, czyli
# wyniku `dataclasses.asdict` na `ModbusEvent`. Funkcja pomocnicza z wartosciami
# domyslnymi, zeby test rozniacy sie jedna wartoscia roznil sie jednym argumentem,
# a nie calym literalem.


def _event(
    *,
    unit_id: int,
    direction: str = "request",
    src_ip: str = CLIENT_IP,
    dst_ip: str = SERVER_IP,
    packet_number: int = 1,
    session_id: int = 0,
    transaction_id: int = 1,
    function_code: int = 0x06,
    function_name: str = "Write Single Register",
    kind: str = "write",
    timestamp: float = 0.0,
) -> dict:
    return {
        "packet_number": packet_number,
        "session_id": session_id,
        "unit_id": unit_id,
        "transaction_id": transaction_id,
        "function_code": function_code,
        "function_name": function_name,
        "kind": kind,
        "direction": direction,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp": timestamp,
    }


def _client_server_segments() -> list[Segment]:
    return [
        _segment(
            packet_number=1,
            session_id=0,
            src_ip=CLIENT_IP,
            src_port=1024,
            dst_ip=SERVER_IP,
            dst_port=502,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
        )
    ]


def test_build_assets_without_events_gives_not_derivable_unit_ids_and_gateway():
    assets = build_assets(segments=_client_server_segments())

    for entry in assets:
        assert entry["unit_ids"] == {"value": None, "provenance": "not-derivable-passively"}
        assert entry["gateway"] == {"value": None, "provenance": "not-derivable-passively"}


def test_build_assets_with_only_response_events_gives_not_derivable_unit_ids():
    events = [_event(unit_id=1, direction="response", src_ip=SERVER_IP, dst_ip=CLIENT_IP)]

    assets = build_assets(segments=_client_server_segments(), events=events)

    for entry in assets:
        assert entry["unit_ids"] == {"value": None, "provenance": "not-derivable-passively"}
        assert entry["gateway"] == {"value": None, "provenance": "not-derivable-passively"}


def test_unit_ids_are_sorted_ascending_regardless_of_file_order():
    events = [
        _event(unit_id=3, packet_number=1),
        _event(unit_id=1, packet_number=3),
        _event(unit_id=2, packet_number=5),
    ]

    assets = build_assets(segments=_client_server_segments(), events=events)
    server = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)

    assert server["unit_ids"]["value"] == [1, 2, 3]


def test_unit_ids_are_collected_under_destination_and_carry_observed():
    events = [_event(unit_id=7)]

    assets = build_assets(segments=_client_server_segments(), events=events)
    server = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)

    assert server["unit_ids"] == {"value": [7], "provenance": "observed"}


def test_sender_of_requests_has_not_derivable_unit_ids():
    events = [_event(unit_id=7)]

    assets = build_assets(segments=_client_server_segments(), events=events)
    client = next(entry for entry in assets if entry["ip"]["value"] == CLIENT_IP)

    assert client["unit_ids"] == {"value": None, "provenance": "not-derivable-passively"}


def test_multi_unit_id_flags_probable_gateway():
    events = [_event(unit_id=1), _event(unit_id=2), _event(unit_id=3)]

    assets = build_assets(segments=_client_server_segments(), events=events)
    server = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)

    assert server["gateway"] == {
        "value": True,
        "provenance": "inferred:multiple-unit-ids",
    }


def test_single_unit_id_gives_gateway_none_never_false():
    events = [_event(unit_id=1), _event(unit_id=1)]

    assets = build_assets(segments=_client_server_segments(), events=events)
    server = next(entry for entry in assets if entry["ip"]["value"] == SERVER_IP)

    # Asercja na `is None`, nie na sama falszywosc: `False` i `None` sa w
    # Pythonie oba falszywe, wiec `assert not value` przepuscilaby dokladnie
    # ten blad, ktoremu zalozenie Z-25 zapobiega.
    assert server["gateway"]["value"] is None
    assert server["gateway"]["provenance"] == "not-derivable-passively"


def test_three_unit_ids_under_one_address_give_one_entry_not_three():
    events = [_event(unit_id=1), _event(unit_id=2), _event(unit_id=3)]

    assets = build_assets(segments=_client_server_segments(), events=events)

    assert [entry["ip"]["value"] for entry in assets] == [CLIENT_IP, SERVER_IP]


def test_event_address_absent_from_segments_never_creates_a_host_entry():
    events = [_event(unit_id=1, dst_ip=THIRD_IP)]

    assets = build_assets(segments=_client_server_segments(), events=events)

    assert THIRD_IP not in [entry["ip"]["value"] for entry in assets]


def test_assert_provenance_complete_passes_with_unit_ids_and_gateway():
    events = [_event(unit_id=1), _event(unit_id=2)]

    assets = build_assets(segments=_client_server_segments(), events=events)

    assert_provenance_complete(assets, path="assets")
