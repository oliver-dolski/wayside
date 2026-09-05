"""Dissector Telnet: rozpoznanie po sekwencji negocjacji opcji (CHECK-03).

Rozpoznanie idzie po ksztalcie pierwszych bajtow ladunku, nigdy po numerze
portu (zalozenie Z-46, wzorzec PROTO-01) - celem jest wykrycie OBECNOSCI
protokolu Telnet w ruchu, nie jego pelne dekodowanie. Dlugosc ladunku jest
sprawdzana PRZED kazdym indeksowaniem (zagrozenie T-4-06): funkcja
rozpoznajaca `_recognize` nie podnosi wyjatku na zadnym wejsciu, bo ladunek
pochodzi z pliku niezaufanego. Zdarzenie zwrocone przez `dissect` nie niesie
ani jednego bajtu ladunku - wylacznie metadane ksztaltu i stala nazwe
podstawy rozpoznania (zalozenie Z-45, zagrozenie T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "IAC",
    "NEGOTIATION_COMMANDS",
    "MIN_NEGOTIATION_LEN",
    "DETECTION_BASIS",
    "dissect",
]

IAC = 0xFF

# Polecenia negocjacji Telnet: WILL (0xFB), WONT (0xFC), DO (0xFD),
# DONT (0xFE), SB - poczatek subnegocjacji (0xFA). Zbior niemutowalny.
NEGOTIATION_COMMANDS: frozenset[int] = frozenset({0xFA, 0xFB, 0xFC, 0xFD, 0xFE})

MIN_NEGOTIATION_LEN = 3

DETECTION_BASIS = "telnet-iac-negotiation"


def _recognize(payload: bytes) -> str | None:
    """Sprawdza, czy `payload` zaczyna sie sekwencja negocjacji Telnet.
    Zwraca `DETECTION_BASIS` albo `None`, nigdy nie podnosi wyjatku - dlugosc
    jest sprawdzona przed jakimkolwiek indeksowaniem (zagrozenie T-4-06)."""
    if len(payload) < MIN_NEGOTIATION_LEN:
        return None
    if payload[0] != IAC:
        return None
    if payload[1] not in NEGOTIATION_COMMANDS:
        return None
    # Trzeci bajt (numer opcji) przyjmuje dowolna wartosc - to jest
    # rozstrzygniecie, nie pominiecie: numer opcji nie zawezenia zbioru
    # rozpoznawanych sekwencji.
    return DETECTION_BASIS


def dissect(segments: list[Segment]) -> list[dict]:
    """Iteruje PELNA liste `segments` w kolejnosci pliku, pomijajac kazdy
    segment, ktory nie zaczyna sie sekwencja negocjacji Telnet - zero
    zalozen o tym, czy inny dissector juz ten segment przetworzyl. Kierunek
    idzie z reguly pierwszego nadawcy ladunku w danej sesji, skopiowanej z
    `wayside.protocols.modbus_tcp.dissect_all`: strona, ktora w tej sesji
    pierwsza wyslala ladunek przechodzacy rozpoznanie, jest klientem."""
    events: list[dict] = []
    session_clients: dict[int, tuple[str, int]] = {}

    for segment in segments:
        basis = _recognize(segment.payload)
        if basis is None:
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

        events.append(
            {
                "packet_number": segment.packet_number,
                "session_id": segment.session_id,
                "direction": direction,
                "basis": basis,
                "src_ip": segment.src_ip,
                "dst_ip": segment.dst_ip,
                "timestamp": segment.timestamp,
            }
        )

    return events
