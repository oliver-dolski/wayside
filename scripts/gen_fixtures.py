"""Deterministyczny generator syntetycznych zrzutow pcap Modbus/TCP.

Uzycie:
    uv run python scripts/gen_fixtures.py            # regeneruje fixture'y w miejscu
    uv run python scripts/gen_fixtures.py --check    # regeneruje do katalogu tymczasowego
                                                       # i porownuje sume sha256 z plikami
                                                       # w repozytorium

Adresacja pochodzi wylacznie z zakresu dokumentacyjnego RFC 5737 (192.0.2.0/24).
Adresy MAC sa lokalnie administrowane i wymyslone, nie naleza do zadnego realnego
urzadzenia. Znaczniki czasu sa stale (`BASE_TIMESTAMP + i * 0.01`), nigdy
zegar systemowy (funkcja `time` z modulu `time`) - patrz Pitfall 5
w 01-RESEARCH.md. `wrpcap()` domyslnie zapisuje
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

_PCAPNG_SHB_TYPE = 0x0A0D0D0A
_PCAPNG_IDB_TYPE = 0x00000001
_PCAPNG_EPB_TYPE = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC_LE = 0x1A2B3C4D

# Snaplen dla fixture'u uciecia ramek: czternascie bajtow warstwy Ethernet
# plus dwadziescia bajtow naglowka IP plus dwadziescia bajtow naglowka TCP
# daje pelne naglowki i pusty ladunek - to jest rozstrzygniecie (zalozenie
# Z-07 w 03-02-PLAN.md), nie liczba przypadkowa. Snaplen mniejszy zostawilby
# scapy niekompletny naglowek TCP i zamienil test uciecia w test odpornosci
# dysektora na smiec.
SNAPLEN_TRUNCATION_LEN = 54

__all__ = [
    "GENERATORS",
    "gen_modbus_write_single_register",
    "gen_modbus_non_standard_port",
    "gen_modbus_malformed_mbap",
    "gen_truncated_mid_record",
    "gen_empty_valid_header",
    "gen_modbus_write_pcapng",
    "gen_truncated_mid_block",
    "gen_snaplen_truncated_frames",
    "gen_corrupted_record_length",
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


def _pcapng_section_header_block() -> bytes:
    """Section Header Block minimalny (28 bajtow, bez opcji), little-endian."""
    total_length = 28
    return struct.pack(
        "<IIIHHqI",
        _PCAPNG_SHB_TYPE,
        total_length,
        _PCAPNG_BYTE_ORDER_MAGIC_LE,
        1,  # wersja glowna
        0,  # wersja podrzedna
        -1,  # dlugosc sekcji nieznana
        total_length,
    )


def _pcapng_interface_description_block() -> bytes:
    """Interface Description Block minimalny (20 bajtow, bez opcji)."""
    total_length = 20
    return struct.pack(
        "<IIHHII",
        _PCAPNG_IDB_TYPE,
        total_length,
        1,  # typ warstwy lacza: Ethernet (LINKTYPE_ETHERNET)
        0,  # zarezerwowane
        65535,  # snaplen
        total_length,
    )


def _pcapng_enhanced_packet_block(data: bytes, timestamp_s: float) -> bytes:
    """Enhanced Packet Block: dlugosc = 32 + dane dopelnione do wielokrotnosci 4."""
    pad_len = (-len(data)) % 4
    padded_data = data + b"\x00" * pad_len
    total_length = 32 + len(padded_data)

    timestamp_us = round(timestamp_s * 1_000_000)
    timestamp_high = (timestamp_us >> 32) & 0xFFFFFFFF
    timestamp_low = timestamp_us & 0xFFFFFFFF

    header = struct.pack(
        "<IIIIIII",
        _PCAPNG_EPB_TYPE,
        total_length,
        0,  # identyfikator interfejsu
        timestamp_high,
        timestamp_low,
        len(data),  # dlugosc przechwycona
        len(data),  # dlugosc oryginalna
    )
    return header + padded_data + struct.pack("<I", total_length)


def gen_modbus_write_pcapng(output_dir: Path) -> Path:
    """Ta sama wymiana zapisu 0x06 co fixture klasyczny, zapisana jako
    pcapng zamiast klasycznego pcapa.

    Bajty sa budowane jawnie przez `struct.pack` w porzadku little-endian,
    zgodnym z bajtem porzadku Section Header Block - `scapy` nie jest
    uzywane do zapisu formatu pcapng (droga niegwarantowana w tej wersji),
    ale bajty kazdego pakietu (`bytes(pkt)`) pochodza z tych samych
    obiektow scapy co fixture klasyczny (D-04): zrodlo tresci jest jedno.
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

    blocks = [_pcapng_section_header_block(), _pcapng_interface_description_block()]
    for i, pkt in enumerate([request, response]):
        timestamp = BASE_TIMESTAMP + i * 0.01
        blocks.append(_pcapng_enhanced_packet_block(bytes(pkt), timestamp))

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_single_register.pcapng"
    output_path.write_bytes(b"".join(blocks))
    return output_path


def gen_truncated_mid_block(output_dir: Path) -> Path:
    """Bajty poprawnego pcapng, zapisane bez ostatnich dziesieciu bajtow,
    tak zeby plik konczyl sie w srodku ostatniego Enhanced Packet Block.

    Odpowiednik `gen_truncated_mid_record` dla formatu pcapng - dowod, ze
    audyt strukturalny (Task 2 tego planu) wykrywa obciecie takze w tym
    formacie, nie tylko w klasycznym pcapie.
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_pcapng(Path(tmp))
        full_bytes = full_path.read_bytes()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "truncated_mid_block.pcapng"
    output_path.write_bytes(full_bytes[:-10])
    return output_path


# --- Faza 3: fixture'y budowane struktura bajtowa (Task 1, 03-02-PLAN.md) ---


def gen_snaplen_truncated_frames(output_dir: Path) -> Path:
    """Dwa rekordy uciete przez snaplen rowny `SNAPLEN_TRUNCATION_LEN`.

    Ta sama wymiana zapisu 0x06 co fixture bazowy, zbudowana bajtowo zamiast
    przez `wrpcap`: pisarz scapy zapisuje pelna ramke i nie potrafi
    wyprodukowac rekordu, w ktorym dlugosc przechwycona jest mniejsza od
    dlugosci oryginalnej. Naglowek globalny niesie snaplen rowny
    `SNAPLEN_TRUNCATION_LEN` zamiast domyslnego; kazdy rekord niesie dlugosc
    przechwycona rowna dlugosci ucietej ramki i dlugosc oryginalna rowna
    pelnej dlugosci ramki przed obcieciem.

    Uciecie przez snaplen jest przypadkiem LEGALNYM - rozpoznawanym w
    `wayside.pcap._audit_pcap_classic` po warunku dlugosc przechwycona
    mniejsza od oryginalnej - a nie tym samym co korupcja pola dlugosci,
    rozpoznawana po warunku dlugosc przechwycona wieksza od snaplenu
    (patrz `gen_corrupted_record_length` nizej). `audit_capture_structure`
    na tym pliku nie podnosi wyjatku (INGEST-03).
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

    global_header = struct.pack(
        "<IHHiIII",
        PCAP_CLASSIC_MAGIC_LE,
        2,  # wersja glowna
        4,  # wersja podrzedna
        0,  # strefa czasowa
        0,  # dokladnosc znacznikow czasu
        SNAPLEN_TRUNCATION_LEN,  # snaplen
        1,  # typ warstwy lacza: Ethernet
    )

    records = bytearray()
    for i, pkt in enumerate([request, response]):
        # Znacznik czasu wyprowadzony z BASE_TIMESTAMP, nigdy z zegara
        # systemowego - dokladnie jak reszta generatorow tego pliku.
        timestamp = BASE_TIMESTAMP + i * 0.01
        ts_sec = int(timestamp)
        ts_usec = round((timestamp - ts_sec) * 1_000_000)

        full_frame = bytes(pkt)
        truncated_frame = full_frame[:SNAPLEN_TRUNCATION_LEN]
        records += struct.pack(
            "<IIII", ts_sec, ts_usec, len(truncated_frame), len(full_frame)
        )
        records += truncated_frame

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "snaplen_truncated_frames.pcap"
    output_path.write_bytes(bytes(global_header) + bytes(records))
    return output_path


def gen_corrupted_record_length(output_dir: Path) -> Path:
    """Plik uszkodzony strukturalnie przy pelnej, spojnej dlugosci pliku -
    rozny od pliku obcietego.

    Zbudowany z tych samych bajtow co fixture bazowy
    (`gen_modbus_write_single_register`, zapisany do katalogu tymczasowego
    tak jak robi to `gen_truncated_mid_record`), z jedna zmiana W MIEJSCU:
    pole dlugosci przechwyconej w naglowku PIERWSZEGO rekordu jest
    podmienione na wartosc 300000, wieksza od snaplenu z naglowka globalnego.
    Naglowek globalny ma dwadziescia cztery bajty, naglowek rekordu
    szesnascie, wiec pole dlugosci przechwyconej pierwszego rekordu lezy na
    przesunieciu od 32 do 36 bajtow od poczatku pliku (uklad potwierdzony
    odczytem `wayside.pcap._audit_pcap_classic`). Dlugosc zapisanego pliku
    pozostaje identyczna z dlugoscia pliku zrodlowego - to jest cala tresc
    tego fixture'a: struktura jest niespojna, ale plik NIE jest obciety.

    Ten plik wymusza wejscie w blok kontroli zakresu `incl_len > snaplen`
    w `wayside.pcap`, ktory istnieje od Fazy 2, ale do tej pory nie byl
    wywolywany przez zaden fixture ani test (INGEST-05).
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_single_register(Path(tmp))
        full_bytes = bytearray(full_path.read_bytes())

    global_header_len = 24  # magic+wersje+strefa+dokladnosc+snaplen+network
    incl_len_offset = global_header_len + 8  # ts_sec(4) + ts_usec(4)
    full_bytes[incl_len_offset : incl_len_offset + 4] = struct.pack("<I", 300000)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "corrupted_record_length.pcap"
    output_path.write_bytes(bytes(full_bytes))
    return output_path


GENERATORS: tuple[tuple[str, Callable[[Path], Path]], ...] = (
    ("modbus_write_single_register.pcap", gen_modbus_write_single_register),
    ("modbus_write_non_standard_port.pcap", gen_modbus_non_standard_port),
    ("modbus_malformed_mbap.pcap", gen_modbus_malformed_mbap),
    ("truncated_mid_record.pcap", gen_truncated_mid_record),
    ("empty_valid_header.pcap", gen_empty_valid_header),
    ("modbus_write_single_register.pcapng", gen_modbus_write_pcapng),
    ("truncated_mid_block.pcapng", gen_truncated_mid_block),
    ("snaplen_truncated_frames.pcap", gen_snaplen_truncated_frames),
    ("corrupted_record_length.pcap", gen_corrupted_record_length),
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
