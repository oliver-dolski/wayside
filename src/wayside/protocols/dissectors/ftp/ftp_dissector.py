"""Dissector FTP: rozpoznanie kanalu kontrolnego po czasowniku polecenia
albo po kodzie odpowiedzi (CHECK-03).

Rozpoznanie idzie po ksztalcie pierwszych bajtow ladunku, nigdy po numerze
portu (zalozenie Z-46, wzorzec PROTO-01) - celem jest wykrycie OBECNOSCI
ruchu FTP, nie jego pelne dekodowanie. Dlugosc ladunku jest sprawdzana
PRZED kazdym indeksowaniem (zagrozenie T-4-06): funkcja rozpoznajaca
`_recognize` nie podnosi wyjatku na zadnym wejsciu, bo ladunek pochodzi z
pliku niezaufanego. Zdarzenie zwrocone przez `dissect` nie niesie ani
jednego bajtu ladunku - wylacznie metadane ksztaltu i stala nazwe podstawy
rozpoznania (zalozenie Z-45, zagrozenie T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "CONTROL_VERBS",
    "MIN_COMMAND_LEN",
    "DETECTION_BASIS_COMMAND",
    "DETECTION_BASIS_REPLY",
    "dissect",
]

# Czasowniki polecen kanalu kontrolnego FTP: podanie nazwy uzytkownika
# (USER), podanie hasla (PASS), pobranie pliku (RETR), zapis pliku (STOR),
# listowanie (LIST), zakonczenie sesji (QUIT), katalog biezacy (PWD), zmiana
# katalogu (CWD), typ transferu (TYPE), tryb aktywny (PORT), tryb pasywny
# (PASV). Zbior niemutowalny, porownanie bez zmiany wielkosci liter -
# protokol wymienia je wielkimi literami.
CONTROL_VERBS: frozenset[bytes] = frozenset(
    {
        b"USER",
        b"PASS",
        b"RETR",
        b"STOR",
        b"LIST",
        b"QUIT",
        b"PWD",
        b"CWD",
        b"TYPE",
        b"PORT",
        b"PASV",
    }
)

# Dlugosc najkrotszego czasownika (PWD/CWD, trzy bajty) plus jeden bajt
# delimitera - ta sama dlugosc minimalna dziala dla galezi kodu odpowiedzi
# (trzy cyfry plus jeden bajt delimitera).
MIN_COMMAND_LEN = 4

DETECTION_BASIS_COMMAND = "ftp-control-verb"
DETECTION_BASIS_REPLY = "ftp-reply-code"

_COMMAND_DELIMITERS = (0x20, 0x0D)  # spacja albo powrot karetki
_REPLY_DELIMITERS = (0x20, 0x2D)  # spacja albo minus


def _recognize(payload: bytes) -> str | None:
    """Sprawdza dwie galezie rozpoznania FTP nad `payload`. Zwraca podstawe
    rozpoznania albo `None`, nigdy nie podnosi wyjatku - dlugosc jest
    sprawdzona przed jakimkolwiek indeksowaniem (zagrozenie T-4-06)."""
    if len(payload) < MIN_COMMAND_LEN:
        return None

    for verb in CONTROL_VERBS:
        if not payload.startswith(verb):
            continue
        next_index = len(verb)
        if next_index < len(payload) and payload[next_index] in _COMMAND_DELIMITERS:
            return DETECTION_BASIS_COMMAND

    first_three = payload[:3]
    if first_three.isdigit() and payload[3] in _REPLY_DELIMITERS:
        return DETECTION_BASIS_REPLY

    return None


def dissect(segments: list[Segment]) -> list[dict]:
    """Iteruje PELNA liste `segments` w kolejnosci pliku, pomijajac kazdy
    segment, ktory nie zaczyna sie czasownikiem polecenia ani kodem
    odpowiedzi FTP - zero zalozen o tym, czy inny dissector juz ten segment
    przetworzyl. Kierunek idzie z reguly pierwszego nadawcy ladunku w danej
    sesji, skopiowanej z `wayside.protocols.modbus_tcp.dissect_all`: strona,
    ktora w tej sesji pierwsza wyslala ladunek przechodzacy rozpoznanie,
    jest klientem."""
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
