"""Dissector HTTP: rozpoznanie po linii zadania albo po linii statusu
odpowiedzi (CHECK-03).

Rozpoznanie idzie po ksztalcie pierwszych bajtow ladunku, nigdy po numerze
portu (zalozenie Z-46, wzorzec PROTO-01) - fixture tej fazy nadaje HTTP na
porcie niestandardowym wlasnie po to, zeby rozpoznanie po zawartosci bylo
jedynym wytlumaczeniem wyniku. Celem jest wykrycie OBECNOSCI ruchu HTTP, nie
jego pelne dekodowanie. Dlugosc ladunku jest sprawdzana PRZED kazdym
indeksowaniem (zagrozenie T-4-06): funkcja rozpoznajaca `_recognize` nie
podnosi wyjatku na zadnym wejsciu, bo ladunek pochodzi z pliku
niezaufanego. Zdarzenie zwrocone przez `dissect` nie niesie ani jednego
bajtu ladunku - wylacznie metadane ksztaltu i stala nazwe podstawy
rozpoznania (zalozenie Z-45, zagrozenie T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "REQUEST_METHODS",
    "VERSION_TOKENS",
    "MIN_REQUEST_LEN",
    "DETECTION_BASIS_REQUEST",
    "DETECTION_BASIS_STATUS",
    "dissect",
]

REQUEST_METHODS: frozenset[bytes] = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS"}
)

VERSION_TOKENS: frozenset[bytes] = frozenset({b"HTTP/1.0", b"HTTP/1.1"})

# Dlugosc najkrotszej mozliwej linii zadania: "GET / HTTP/1.1".
MIN_REQUEST_LEN = len(b"GET / HTTP/1.1")

DETECTION_BASIS_REQUEST = "http-request-line"
DETECTION_BASIS_STATUS = "http-status-line"

# Limit przeszukiwania pierwszej linii - bez niego ladunek bez ani jednego
# znaku nowej linii zamienilby wyszukanie tokenu wersji w skan calego
# ladunku (zagrozenie T-4-06).
_MAX_FIRST_LINE_SCAN_LEN = 256


def _first_line(payload: bytes) -> bytes:
    """Bajty do pierwszego wystapienia znaku nowej linii, przyciete do
    `_MAX_FIRST_LINE_SCAN_LEN`."""
    limit = min(len(payload), _MAX_FIRST_LINE_SCAN_LEN)
    newline_index = payload.find(b"\n", 0, limit)
    if newline_index == -1:
        return payload[:limit]
    return payload[:newline_index]


def _recognize(payload: bytes) -> str | None:
    """Sprawdza dwie galezie rozpoznania HTTP nad `payload`. Zwraca podstawe
    rozpoznania albo `None`, nigdy nie podnosi wyjatku - dlugosc jest
    sprawdzona przed jakimkolwiek indeksowaniem (zagrozenie T-4-06)."""
    if len(payload) < MIN_REQUEST_LEN:
        return None

    first_line = _first_line(payload)

    for method in REQUEST_METHODS:
        prefix = method + b" "
        if payload.startswith(prefix) and any(
            token in first_line for token in VERSION_TOKENS
        ):
            return DETECTION_BASIS_REQUEST

    for token in VERSION_TOKENS:
        prefix = token + b" "
        if payload.startswith(prefix):
            status_code = payload[len(prefix) : len(prefix) + 3]
            if len(status_code) == 3 and status_code.isdigit():
                return DETECTION_BASIS_STATUS

    return None


def dissect(segments: list[Segment]) -> list[dict]:
    """Iteruje PELNA liste `segments` w kolejnosci pliku, pomijajac kazdy
    segment, ktory nie zaczyna sie linia zadania ani linia statusu HTTP -
    zero zalozen o tym, czy inny dissector juz ten segment przetworzyl.
    Kierunek idzie z reguly pierwszego nadawcy ladunku w danej sesji,
    skopiowanej z `wayside.protocols.modbus_tcp.dissect_all`: strona, ktora
    w tej sesji pierwsza wyslala ladunek przechodzacy rozpoznanie, jest
    klientem."""
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
