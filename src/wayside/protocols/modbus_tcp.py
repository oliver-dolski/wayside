"""Warstwa Modbus/TCP nad scapy: walidacja MBAP jako brama, klasyfikacja
kodow funkcji i rekonstrukcja kierunku zadanie/odpowiedz bez odwolania do
numeru portu.

Rozpoznanie protokolu idzie po ksztalcie naglowka MBAP na dowolnym porcie
TCP (PROTO-01) - scapy wiaze Modbusa na sztywno z portem 502 przez
`bind_layers` (02-RESEARCH.md, Pitfall 2), wiec ten modul nigdy nie polega na
automatycznej dissekcji `pkt[TCP].payload`. `validate_mbap` jest brama:
naglowek niepoprawny nie dochodzi do klasyfikacji funkcjonalnej (PROTO-02) -
scapy samo NIE waliduje ani `protoId`, ani spojnosci pola `len`
(zweryfikowane w 02-RESEARCH.md).

Kody funkcji sa klasyfikowane wg pelnej tabeli Modbus Application Protocol
odtworzonej z `scapy.contrib.modbus` (PROTO-04) - lista kodow jest odczytem
publicznie udokumentowanej specyfikacji, nie zgadywaniem.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass

import wayside.pcap  # noqa: F401  - izolacja cache scapy PRZED importem warstw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse  # noqa: E402

from wayside.decode import Segment  # noqa: E402

__all__ = [
    "MBAP_HEADER_LEN",
    "MIN_ADU_LEN",
    "FUNCTION_CODE_KIND",
    "FUNCTION_CODE_NAME",
    "MbapHeader",
    "ModbusEvent",
    "validate_mbap",
    "classify_function_code",
    "dissect_all",
]

MBAP_HEADER_LEN = 7
MIN_ADU_LEN = 8  # 7 bajtow MBAP + minimum 1 bajt kodu funkcji

# Tabela kodow funkcji Modbus Application Protocol, odtworzona z
# `scapy.contrib.modbus` (02-RESEARCH.md, Pattern 3). Dokladnie 19 wpisow.
FUNCTION_CODE_KIND: dict[int, str] = {
    0x01: "read",
    0x02: "read",
    0x03: "read",
    0x04: "read",
    0x05: "write",
    0x06: "write",
    0x07: "read",
    0x08: "other",  # Diagnostics - efekt zalezny od subFunc
    0x0B: "read",
    0x0C: "read",
    0x0F: "write",
    0x10: "write",
    0x11: "read",
    0x14: "read",
    0x15: "write",
    0x16: "write",
    0x17: "write",  # Read/Write Multiple Registers - zawiera zapis w PDU
    0x18: "read",
    0x2B: "read",
}

FUNCTION_CODE_NAME: dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Slave Id",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Read Device Identification",
}


@dataclass(frozen=True)
class MbapHeader:
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int


@dataclass(frozen=True)
class ModbusEvent:
    packet_number: int
    session_id: int
    unit_id: int
    transaction_id: int
    function_code: int
    function_name: str
    kind: str
    direction: str
    src_ip: str
    dst_ip: str


def validate_mbap(raw: bytes) -> MbapHeader | None:
    """Waliduje naglowek MBAP jako brama przed parsowaniem funkcjonalnym.

    Kolejnosc sprawdzen jest wymagana (zagrozenie T-2-01): dlugosc jest
    sprawdzana PRZED jakimkolwiek indeksowaniem opartym o pole dlugosci.
    `scapy` nie waliduje zadnego z tych trzech warunkow samo z siebie
    (zweryfikowane w 02-RESEARCH.md).
    """
    if len(raw) < MIN_ADU_LEN:
        return None

    protocol_id = struct.unpack(">H", raw[2:4])[0]
    if protocol_id != 0:
        return None

    length_field = struct.unpack(">H", raw[4:6])[0]
    if length_field != len(raw) - 6:
        return None

    transaction_id = struct.unpack(">H", raw[0:2])[0]
    unit_id = raw[6]

    return MbapHeader(
        transaction_id=transaction_id,
        protocol_id=protocol_id,
        length=length_field,
        unit_id=unit_id,
    )


def classify_function_code(code: int) -> str:
    """Klasyfikuje kod funkcji. Kod poza tabela zwraca `unknown`, nigdy nie
    podnosi `KeyError` i nigdy nie zwraca `read` domyslnie."""
    return FUNCTION_CODE_KIND.get(code, "unknown")


def dissect_all(segments: list[Segment]) -> list[ModbusEvent]:
    """Dysekcja Modbus/TCP nad lista segmentow, w kolejnosci pliku.

    Kierunek jest rozstrzygany BEZ odwolania do portu 502: strona, ktora w
    danej sesji pierwsza wyslala ladunek przechodzacy `validate_mbap`, jest
    klientem - jej segmenty sa `request`, segmenty drugiej strony `response`
    (PROTO-01). `ModbusADURequest`/`ModbusADUResponse` sa konstruowane
    recznie z surowych bajtow, zgodnie z rozstrzygnietym kierunkiem,
    wylacznie jako dodatkowa brama (blad `struct.error` odrzuca segment) -
    kod funkcji idzie z bajtu surowego na pozycji `MBAP_HEADER_LEN`, nie
    z atrybutu obiektu scapy.
    """
    events: list[ModbusEvent] = []
    session_clients: dict[int, tuple[str, int]] = {}

    for segment in segments:
        header = validate_mbap(segment.payload)
        if header is None:
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

        try:
            if direction == "request":
                ModbusADURequest(segment.payload)
            else:
                ModbusADUResponse(segment.payload)
        except struct.error:
            continue

        function_code = segment.payload[MBAP_HEADER_LEN]
        events.append(
            ModbusEvent(
                packet_number=segment.packet_number,
                session_id=segment.session_id,
                unit_id=header.unit_id,
                transaction_id=header.transaction_id,
                function_code=function_code,
                function_name=FUNCTION_CODE_NAME.get(function_code, "Unknown"),
                kind=classify_function_code(function_code),
                direction=direction,
                src_ip=segment.src_ip,
                dst_ip=segment.dst_ip,
            )
        )

    return events
