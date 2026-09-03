"""Deterministyczny generator syntetycznych zrzutow pcap Modbus/TCP.

Uzycie:
    uv run python scripts/gen_fixtures.py            # regeneruje fixture'y w miejscu
    uv run python scripts/gen_fixtures.py --check    # regeneruje do katalogu tymczasowego
                                                       # i porownuje sume sha256 z plikami
                                                       # w repozytorium

Adresacja pochodzi wylacznie z zakresu dokumentacyjnego RFC 5737 (192.0.2.0/24).
Adresy MAC sa lokalnie administrowane i wymyslone, nie naleza do zadnego realnego
urzadzenia. Znaczniki czasu sa stale (`BASE_TIMESTAMP + i * 0.01`), nigdy
`time.time()` - patrz Pitfall 5 w 01-RESEARCH.md. `wrpcap()` domyslnie zapisuje
klasyczny format pcap (nie pcapng), wiec plik nie ma miejsca na metadane maszyny.

Kazdy generator jest funkcja `gen_*(output_dir: Path) -> Path` odwzorowana w
`GENERATORS` razem z docelowa nazwa pliku - `_check()` i `main()` iteruja po
tej krotce, wiec dodanie nowego fixture'a nie wymaga zmiany ani jednej z tych
dwoch funkcji.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import struct
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.contrib.modbus import (  # noqa: E402
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU06WriteSingleRegisterResponse,
)
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

# Adresacja dokumentacyjna, RFC 5737.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
MODBUS_PORT = 502
MODBUS_NON_STANDARD_PORT = 10502
BASE_TIMESTAMP = 1700000000.0

# Nagłówek globalny klasycznego pcapa, mikrosekundowy, little-endian
# (zgodne z `PCAP_MAGICS` w `wayside.pcap` po Task 2 tego planu).
PCAP_CLASSIC_MAGIC_LE = 0xA1B2C3D4

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "pcap"

__all__ = [
    "GENERATORS",
    "gen_modbus_write_single_register",
    "gen_modbus_non_standard_port",
    "gen_modbus_malformed_mbap",
    "gen_truncated_mid_record",
    "gen_empty_valid_header",
    "main",
]


def gen_modbus_write_single_register(output_dir: Path) -> Path:
    """Generuje jedna wymiane Modbus/TCP (zadanie i odpowiedz 0x06) do pliku pcap.

    Zwraca sciezke do wygenerowanego pliku. Dwa kolejne wywolania produkuja
    bajtowo identyczny plik (stale adresy, stale znaczniki czasu).
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_single_register.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_non_standard_port(output_dir: Path) -> Path:
    """Ta sama wymiana zapisu 0x06 co fixture bazowy, ale serwer nasluchuje
    na `MODBUS_NON_STANDARD_PORT` zamiast `MODBUS_PORT`.

    Dowod dla PROTO-01: rozpoznanie protokolu idzie po ksztalcie naglowka
    MBAP, niezaleznie od numeru portu. Fixture konsumowany przez plan 02-04.
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_NON_STANDARD_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_NON_STANDARD_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_non_standard_port.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_malformed_mbap(output_dir: Path) -> Path:
    """Dwie ramki, kazda lamiaca inny warunek walidacji MBAP z
    `wayside.protocols.modbus_tcp.validate_mbap`.

    scapy nie pozwala zbudowac niepoprawnego naglowka MBAP przez zwykle
    pola konstruktora `ModbusADURequest` - trzeba zbudowac poprawny pakiet,
    wyciagnac jego ladunek TCP jako surowe bajty, podmienic konkretne bajty
    i zlozyc pakiet z powrotem z warstwa `Raw` nad TCP.

    Ramka pierwsza (transId=1): identyfikator protokolu w bajtach 2:4
    ladunku ustawiony na wartosc niezerowa (`0x0001`) - lamie warunek
    `protocol_id == 0`.

    Ramka druga (transId=2): pole dlugosci w bajtach 4:6 ladunku ustawione
    na wartosc niespojna z faktyczna liczba pozostalych bajtow - lamie
    warunek `length_field == len(raw) - 6`.
    """
    valid_request_1 = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50001, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    raw_1 = bytearray(bytes(valid_request_1[TCP].payload))
    raw_1[2:4] = struct.pack(">H", 1)  # protoId niezerowy - lamie warunek protoId==0
    frame_bad_proto_id = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50001, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes(raw_1))
    )

    valid_request_2 = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50002, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=2, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    raw_2 = bytearray(bytes(valid_request_2[TCP].payload))
    raw_2[4:6] = struct.pack(">H", 999)  # dlugosc niespojna z faktycznymi bajtami
    frame_bad_length = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50002, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes(raw_2))
    )

    packets = [frame_bad_proto_id, frame_bad_length]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_malformed_mbap.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_truncated_mid_record(output_dir: Path) -> Path:
    """Plik pcap poprawny do naglowka, obciety w srodku ostatniego rekordu.

    Zrodlem tresci jest ten sam zapis co fixture bazowy - zbudowany przez
    `gen_modbus_write_single_register` do katalogu tymczasowego, zeby
    zrodlo bajtow bylo jedno. Magic globalny pozostaje poprawny, wiec
    `rdpcap` nie podnosi wyjatku na tym pliku (Pitfall 3, 02-RESEARCH.md):
    to jest dokladnie ten ksztalt wejscia, na ktorym Faza 1 dawala cicha
    zielona odpowiedz. `wayside.pcap.audit_capture_structure` (Task 2 tego
    planu) ma wykryc to obciecie strukturalnie, nie po liczbie pakietow.
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_single_register(Path(tmp))
        full_bytes = full_path.read_bytes()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "truncated_mid_record.pcap"
    output_path.write_bytes(full_bytes[:-10])
    return output_path


def gen_empty_valid_header(output_dir: Path) -> Path:
    """Plik zawierajacy WYLACZNIE dwudziestoczterobajtowy naglowek globalny
    klasycznego pcapa, zero rekordow.

    Nie polega na `wrpcap` z pusta lista pakietow: pisarz scapy zapisuje
    naglowek dopiero przy pierwszym pakiecie, wiec wynikiem bylby plik
    zerowej dlugosci - inny przypadek testowy niz zamierzony. Ten plik jest
    strukturalnie poprawny i legalnie pusty (D-01): `read_capture` na nim
    zwraca zero pakietow bez podnoszenia wyjatku.
    """
    header = struct.pack(
        "<IHHiIII",
        PCAP_CLASSIC_MAGIC_LE,
        2,  # wersja glowna
        4,  # wersja podrzedna
        0,  # strefa czasowa
        0,  # dokladnosc znacznikow czasu
        262144,  # snaplen
        1,  # typ warstwy lacza: Ethernet
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "empty_valid_header.pcap"
    output_path.write_bytes(header)
    return output_path


GENERATORS: tuple[tuple[str, Callable[[Path], Path]], ...] = (
    ("modbus_write_single_register.pcap", gen_modbus_write_single_register),
    ("modbus_write_non_standard_port.pcap", gen_modbus_non_standard_port),
    ("modbus_malformed_mbap.pcap", gen_modbus_malformed_mbap),
    ("truncated_mid_record.pcap", gen_truncated_mid_record),
    ("empty_valid_header.pcap", gen_empty_valid_header),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check() -> int:
    ok = True
    for name, generator in GENERATORS:
        repo_file = FIXTURE_DIR / name
        if not repo_file.exists():
            print(f"Brak pliku fixture w repozytorium: {repo_file}", file=sys.stderr)
            ok = False
            continue

        with tempfile.TemporaryDirectory() as tmp:
            generated = generator(Path(tmp))
            repo_hash = _sha256(repo_file)
            generated_hash = _sha256(generated)
            if repo_hash != generated_hash:
                print(
                    f"Rozjazd sumy sha256 dla {name}: "
                    f"repo={repo_hash} wygenerowano={generated_hash}",
                    file=sys.stderr,
                )
                ok = False

    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Regeneruj do katalogu tymczasowego i porownaj sume sha256 z repozytorium.",
    )
    args = parser.parse_args()

    if args.check:
        return _check()

    for name, generator in GENERATORS:
        output_path = generator(FIXTURE_DIR)
        print(f"Wygenerowano: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
