"""Dyskryminator ramki Modbus RTU tunelowanej po TCP bez naglowka MBAP: drugi,
pozytywny test wolany WYLACZNIE po nieudanej walidacji MBAP
(`wayside.protocols.modbus_tcp.validate_mbap`, zalozenie Z-17 w 03-04-PLAN.md).

Ten modul NIE dekoduje natywnego Modbus/TCP - do tego sluzy
`wayside.protocols.modbus_tcp.dissect_all` - i NIE zwraca wynikow do
`protocol_events`: kazde rozpoznanie tego modulu idzie do OSOBNEGO typu
(`LowConfidenceEvent`), w OSOBNEJ liscie modelu (`analysis["low_confidence_events"]`),
bo dopasowanie sumy kontrolnej jest rozpoznaniem o niskiej pewnosci, nigdy pewnym
rozpoznaniem protokolu (zalozenie Z-18, zagrozenia T-3-13/T-3-16). Silnik checkow
z Fazy 2 czyta wylacznie `protocol_events` - rozdzielenie jest strukturalne, nie
flaga na wspolnej liscie.

Zrodlo zakresu bajtu adresu i parametrow sumy kontrolnej: "MODBUS over Serial Line
Specification and Implementation Guide V1.02" (Modbus.org, Dec 20, 2006), pobrane
2026-09-04 z archiwum Wayback Machine (strona live modbus.org/specs.php odmowila
polaczenia zapora WAF w tej sesji wykonawcy):
web.archive.org/web/20250910152913/https://www.modbus.org/docs/Modbus_over_serial_line_V1_02.pdf

[VERIFIED], nie [CITED] ani [ASSUMED] - badanie fazy (03-RESEARCH.md Pattern 3,
Assumption A3) oznaczylo obie wartosci jako niepotwierdzone wobec zrodla
pierwotnego; to zadanie domyka te weryfikacje bezposrednim odczytem dokumentu:

- Zakres bajtu adresu (rozdzial 2.2 "MODBUS Addressing rules", str. 8): przestrzen
  adresowania obejmuje 256 wartosci - 0 jest adresem rozgloszeniowym, od 1 do 247
  sa adresy indywidualne urzadzen ("Slave individual addresses"), od 248 do 255
  sa zarezerwowane.
- Algorytm CRC16 (rozdzial 6.2.2 "CRC Generation", str. 39, "A procedure for
  generating a CRC"): rejestr poczatkowy `0xFFFF`; kazdy bajt wiadomosci idzie
  przez XOR z bajtem mlodszym rejestru; potem osiem przesuniec rejestru w prawo,
  a gdy bit wypychany przez przesuniecie jest jedynka, rejestr idzie dodatkowo
  przez XOR z wielomianem w postaci odwroconej `0xA001`; przy wstawieniu do ramki
  bajt mlodszy CRC idzie pierwszy, bajt starszy drugi (Figure 30 "CRC Byte
  Sequence", str. 39).
- Wektor testowy: ten sam dokument, "Example of CRC calculation (frame 02 07)"
  (str. 41) razem z Figure 30 (str. 39) - dla ramki o dwoch bajtach `0x02 0x07`
  rejestr CRC koncowy wynosi `0x1241`, wystawiany w ramce jako bajty `0x41 0x12`
  (bajt mlodszy pierwszy). Ten sam wektor jest bramka maszynowa PROTO-03 w
  `tests/test_modbus_rtu_tunnel.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from wayside.decode import Segment  # noqa: F401 - typ parametru detect_all
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

# Adres 1B + kod funkcji 1B + suma kontrolna 2B - ramka RTU krotsza od tego nie
# niesie nawet minimalnych pol wymaganych do rozpoznania (T-3-14).
RTU_MIN_FRAME_LEN = 4

# Zakres adresu jednostki (Unit ID) dla ramki kierowanej do jednego urzadzenia -
# zrodlo w docstringu modulu, rozdzial 2.2.
RTU_ADDRESS_MIN = 1
RTU_ADDRESS_MAX = 247

# Poziom pewnosci rozpoznania - dyskryminator dopasowuje sume kontrolna, nie
# strukture ramki wprost, wiec rozpoznanie nigdy nie jest pewne (zalozenie Z-18).
CONFIDENCE_LOW = "low"

# Nazwa podstawy rozpoznania, powtorzona w kazdym LowConfidenceEvent i w tresci
# ostrzezenia raportu - jedna nazwana stala, nie literal rozsiany po kodzie.
RTU_DETECTION_BASIS = "crc16-modbus-match"

# Nazwa protokolu wpisywana do LowConfidenceEvent.protocol - jedno miejsce, zeby
# pipeline.py i testy nie musialy powtarzac literalu.
_RTU_PROTOCOL_NAME = "modbus-rtu-over-tcp"

# Wielomian CRC16/Modbus w postaci odwroconej i rejestr poczatkowy - zrodlo w
# docstringu modulu, rozdzial 6.2.2.
_CRC_INITIAL_REGISTER = 0xFFFF
_CRC_POLYNOMIAL_REVERSED = 0xA001


@dataclass(frozen=True)
class LowConfidenceEvent:
    """Rozpoznanie ramki Modbus RTU tunelowanej po TCP, oparte WYLACZNIE na
    dopasowaniu sumy kontrolnej.

    Ten typ celowo NIE jest zdarzeniem protokolu w sensie `ModbusEvent`: nie
    wchodzi do `protocol_events`, nie jest wejsciem dla silnika checkow i nie
    niesie zadnego bajtu ladunku (ten sam powod co `Evidence` w `model.py`).
    `confidence` i `basis` sa zawsze rowne odpowiednio `CONFIDENCE_LOW` i
    `RTU_DETECTION_BASIS` - pola istnieja na rekordzie, zeby kazdy konsument
    modelu (raport, przyszly check) mial poziom pewnosci pod reka bez
    odwolania do stalej modulowej.
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
    """Liczy CRC16/Modbus nad `data`. Funkcja czysta, bez stanu.

    Rejestr poczatkowy, wielomian w postaci odwroconej i kolejnosc przesuniec
    zgodnie z procedura opisana w docstringu modulu (rozdzial 6.2.2). Dla
    ciagu pustego zwraca rejestr poczatkowy nietkniety - petla po bajtach nie
    wykonuje sie ani razu.
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
    """Sprawdza, czy `raw` wyglada jak surowa ramka Modbus RTU z poprawna
    suma kontrolna. Zwraca `bool`, nigdy nie podnosi wyjatku.

    Kolejnosc sprawdzen jest wymagana (zagrozenie T-3-14, ten sam porzadek co
    `validate_mbap`): dlugosc PRZED jakimkolwiek odwolaniem indeksowym, potem
    bajt adresu, potem bajt kodu funkcji, na koncu suma kontrolna - kazdy
    wczesniejszy warunek konczy funkcje zwrotem `False` zanim dojdzie do
    kosztowniejszego sprawdzenia.
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
    transmitted = crc_bytes[0] | (crc_bytes[1] << 8)  # bajt mlodszy pierwszy
    return computed == transmitted


def detect_all(segments: list[Segment]) -> list[LowConfidenceEvent]:
    """Dyskryminator RTU-po-TCP nad PELNA lista segmentow, w kolejnosci pliku.

    Dla kazdego segmentu NAJPIERW wola `validate_mbap` i pomija segment, gdy
    walidacja zwrocila cokolwiek innego niz `None` - to jest wlasnosc TEGO
    modulu (zalozenie Z-17), nie obowiazek wywolujacego: `pipeline.py` woala
    `detect_all` na tej samej liscie segmentow co `modbus_tcp.dissect_all`,
    a wzajemne wykluczenie miedzy nimi jest gwarantowane tutaj.
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
