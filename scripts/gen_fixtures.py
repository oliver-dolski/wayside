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
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU03ReadHoldingRegistersResponse,
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

# Port docelowy fixture'u Modbus RTU tunelowanego po TCP (plan 03-04),
# zgodnie z blokiem <interfaces> planu - liczbowo taki sam jak
# MODBUS_NON_STANDARD_PORT, ale to dwa osobne pliki fixture o zupelnie
# roznym ladunku (naglowek MBAP kontra surowa ramka RTU bez naglowka), wiec
# kolizja portu miedzy nimi nie ma znaczenia.
RTU_TUNNEL_PORT = 10502

# Porty trzech protokolow jawnotekstowych (plan 04-02, Task 1).
TELNET_PORT = 23
FTP_CONTROL_PORT = 21
# Port HTTP niestandardowy: rozpoznanie w tym projekcie idzie po zawartosci
# ladunku, nigdy po numerze portu (PROTO-01) - port 8080 zamiast 80 jest tym
# samym dowodem, ktory `gen_modbus_non_standard_port` niesie od Fazy 2
# (zalozenie Z-49).
HTTP_PORT = 8080

# Porty zrodlowe klienta trzech sesji jawnotekstowych, z zakresu
# efemerycznego - stale, nie literaly powtorzone w trzech miejscach.
TELNET_CLIENT_PORT = 49600
FTP_CLIENT_PORT = 49601
HTTP_CLIENT_PORT = 49602

# Wartosci jawnie testowe fixture'u jawnotekstowego (zalozenie Z-50): nazwa
# uzytkownika i haslo w kanale kontrolnym FTP nie naleza do zadnego konta,
# opisane jako testowe we wpisie manifestu. `tests/test_dissectors_cleartext.py`
# importuje te same stale zamiast powielac ich wartosc.
FTP_TEST_USERNAME = "testuser"
FTP_TEST_PASSWORD = "testpass123"
HTTP_TEST_PATH = "/status.json"

# Adres poczatkowy i wartosc rejestru trzymajacego zwracana przez kazda z
# trzech odpowiedzi odczytu fixture'u sesji zlozonej wylacznie z odczytow
# (plan 04-04, Task 1). Wartosc stala, nigdy losowa ani wyliczana - inaczej
# determinizm bajtowy generatora bylby zlamany.
MODBUS_READ_ONLY_START_ADDR = 0x0000
MODBUS_READ_ONLY_REGISTER_VALUE = 0x00AA

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

# Brama Modbus z wieloma Unit ID (Faza 3) - trzeci adres, rozny od adresu
# serwera bazowego, zeby test bramy nie przechodzil przypadkiem na danych
# innego testu (zalozenie Z-10).
GATEWAY_IP = "192.0.2.30"
GATEWAY_MAC = "02:00:00:00:00:03"

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
    "gen_modbus_poll_cycle_short_window",
    "gen_modbus_poll_cycle_full_window",
    "gen_modbus_gateway_multi_unit_id",
    "gen_modbus_tcp_handshake",
    "gen_modbus_rtu_over_tcp",
    "gen_cleartext_telnet_ftp_http",
    "gen_modbus_read_only_session",
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


# --- Faza 3: fixture'y budowane przez scapy (Task 2, 03-02-PLAN.md) --------


def gen_modbus_poll_cycle_short_window(output_dir: Path) -> Path:
    """Cztery pakiety, dwa zadania Modbus odlegle o piec sekund w oknie
    zrzutu krotszym niz dziesiec sekund.

    Zadanie pierwsze w chwili `BASE_TIMESTAMP`, odpowiedz pierwsza w chwili
    `BASE_TIMESTAMP + 0.01`, zadanie drugie w chwili `BASE_TIMESTAMP + 5.0`,
    odpowiedz druga w chwili `BASE_TIMESTAMP + 5.01`. Najdluzszy odstep
    miedzy zadaniami wynosi piec sekund, okno zrzutu 5.01 sekundy - okno
    jest wiec krotsze niz dwa pelne odstepy i krotsze niz trzy pelne odstepy,
    wiec ten plik wywoluje warunek ostrzezenia niezaleznie od tego, ktory
    mnoznik progu z zakresu od dwoch do trzech zostanie wybrany w planie
    03-03 (zalozenie Z-08).
    """
    packets = []
    for i, (offset, trans_id) in enumerate([(0.0, 1), (5.0, 2)]):
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50200, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50200, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + offset
        response.time = BASE_TIMESTAMP + offset + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_poll_cycle_short_window.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_poll_cycle_full_window(output_dir: Path) -> Path:
    """Dwanascie pakietow, szesc zadan Modbus odleglych o jedna sekunde,
    w oknie zrzutu obejmujacym wiele powtorzen cyklu odpytywania.

    Szesc zadan w chwilach `BASE_TIMESTAMP + n` dla n od zera do pieciu,
    kazda odpowiedz w chwili zadania powiekszonej o `0.01`. Najdluzszy
    odstep miedzy zadaniami wynosi jedna sekunde, okno zrzutu 5.01 sekundy,
    wiec okno obejmuje piec pelnych odstepow - ten plik NIE wywoluje
    warunku ostrzezenia dla zadnego mnoznika progu z zakresu od dwoch do
    pieciu, czyli jest przypadkiem negatywnym odpornym na wynik checkpointu
    z planu 03-03.
    """
    packets = []
    for n in range(6):
        trans_id = n + 1
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50201, dport=MODBUS_PORT, seq=2 * n + 1, ack=2 * n, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50201, seq=2 * n + 1, ack=2 * n + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + n
        response.time = BASE_TIMESTAMP + n + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_poll_cycle_full_window.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_gateway_multi_unit_id(output_dir: Path) -> Path:
    """Szesc pakietow, trzy wymiany Modbus do jednego adresu serwera z trzema
    roznymi wartosciami Unit ID - brama wystawiajaca trzy adresy logiczne.

    Sesja miedzy `CLIENT_IP`/`CLIENT_MAC` i `GATEWAY_IP`/`GATEWAY_MAC`. Trzy
    zadania z `unitId` rownym kolejno 1, 2 i 3, kazde z rosnacym `transId`,
    trzy odpowiedzi o tych samych wartosciach `unitId`/`transId`.

    Ten plik reprezentuje jeden host sieciowy wystawiajacy trzy adresy
    logiczne za soba, NIE trzy hosty - to jest dokladnie ten ksztalt danych,
    na ktorym naiwny inwentarz produkuje trzy wpisy zamiast jednego z
    podadresami (ASSET-05).
    """
    packets = []
    for i, unit_id in enumerate([1, 2, 3]):
        trans_id = unit_id
        request = (
            Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
            / IP(src=CLIENT_IP, dst=GATEWAY_IP, id=1)
            / TCP(sport=50300, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=unit_id)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
            / IP(src=GATEWAY_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50300, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=unit_id)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + i * 0.01
        response.time = BASE_TIMESTAMP + i * 0.01 + 0.005
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_gateway_multi_unit_id.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_tcp_handshake(output_dir: Path) -> Path:
    """Piec pakietow: uzgodnienie trojetapowe TCP jawnie przed wymiana
    Modbus, jedyny pasywny dowod strony inicjujacej sesje.

    Kolejnosc: pakiet z `TCP(flags="S")` od klienta do serwera; pakiet z
    `TCP(flags="SA")` od serwera do klienta; pakiet z `TCP(flags="A")` od
    klienta do serwera; zadanie Modbus z `flags="PA"` od klienta; odpowiedz
    Modbus z `flags="PA"` od serwera. Trzy pierwsze pakiety nie niosa zadnej
    warstwy ponad TCP, wiec ich ladunek jest pusty - `decode_segments`
    dzisiaj odrzuca kazdy segment bez ladunku, wiec te trzy pakiety sa
    niewidoczne dla reszty potoku, ale pakiet z flaga SYN bez flagi ACK
    pozostaje jedynym pasywnym dowodem inicjatora (FLOW-02). Fixture'y z
    Fazy 2 nie zawieraja uzgodnienia polaczenia w ogole, wiec az do tego
    pliku projekt nie ma materialu na przypadek pozytywny FLOW-02
    (zalozenie Z-09).
    """
    syn = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src=CLIENT_IP, dst=SERVER_IP, id=1
    ) / TCP(sport=50400, dport=MODBUS_PORT, seq=0, ack=0, flags="S")
    syn_ack = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src=SERVER_IP, dst=CLIENT_IP, id=1
    ) / TCP(sport=MODBUS_PORT, dport=50400, seq=0, ack=1, flags="SA")
    ack = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src=CLIENT_IP, dst=SERVER_IP, id=1
    ) / TCP(sport=50400, dport=MODBUS_PORT, seq=1, ack=1, flags="A")
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50400, dport=MODBUS_PORT, seq=1, ack=1, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50400, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [syn, syn_ack, ack, request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_tcp_handshake.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Faza 3: fixture Modbus RTU tunelowany po TCP (plan 03-04, Task 2) -----


def _rtu_crc16(data: bytes) -> int:
    """Implementacja LOKALNA sumy kontrolnej CRC16/Modbus, NIEZALEZNA od
    `wayside.protocols.modbus_rtu_tunnel.modbus_crc16` (zalozenie Z-16).

    Import z `wayside` wciagnalby do tego skryptu caly graf importow warstwy
    odczytu (scapy.layers.*, izolacja cache) razem z jej wlasnymi efektami
    ubocznymi importu, ktore ten skrypt dzis wykonuje inaczej. Poza tym dwie
    niezalezne implementacje, ktore musza sie zgodzic na kazdym wektorze
    testowym `tests/test_modbus_rtu_tunnel.py`, sa mocniejszym dowodem
    poprawnosci niz jedna wspolna, ktorej blad zgodzilby sie sam ze soba.
    Parametry algorytmu (rejestr poczatkowy `0xFFFF`, wielomian odwrocony
    `0xA001`) pochodza z tego samego zrodla co w module produkcyjnym -
    "MODBUS over Serial Line Specification and Implementation Guide V1.02",
    rozdzial 6.2.2, patrz docstring `wayside/protocols/modbus_rtu_tunnel.py`.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def gen_modbus_rtu_over_tcp(output_dir: Path) -> Path:
    """Konwerter szeregowo-sieciowy, ktory przekazuje surowa ramke Modbus RTU
    z magistrali wprost do gniazda TCP, bez rekonstrukcji naglowka MBAP.

    Dwa pakiety w jednej sesji TCP: zadanie klienta i odpowiedz serwera, oba
    o identycznym osmiobajtowym ladunku - Write Single Register dla tego
    kodu funkcji odsyla ta sama tresc bez zmian. Cialo ramki: bajt adresu
    `0x01`, bajt kodu funkcji `0x06`, adres rejestru `0x0001` i wartosc
    rejestru `0x002A` w porzadku bajtu starszego jako pierwszego (cztery
    bajty), suma kontrolna `_rtu_crc16` nad tymi szescioma bajtami, zapisana
    w porzadku bajtu mlodszego jako pierwszego. Port docelowy jest
    niestandardowy (`RTU_TUNNEL_PORT`) celowo: rozpoznanie w tym projekcie
    nie zalezy od numeru portu (PROTO-01, Faza 2), a numer inny niz 502
    zdejmuje pokuse napisania testu, ktory przechodzi z powodu portu, nie
    z powodu ksztaltu ramki.
    """
    body = struct.pack(">BBHH", 0x01, 0x06, 0x0001, 0x002A)
    frame = body + struct.pack("<H", _rtu_crc16(body))

    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50500, dport=RTU_TUNNEL_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=frame)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=RTU_TUNNEL_PORT, dport=50500, seq=1, ack=1, flags="PA")
        / Raw(load=frame)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_rtu_over_tcp.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Faza 4: fixture jawnotekstowy Telnet/FTP/HTTP (plan 04-02, Task 1) ----


def gen_cleartext_telnet_ftp_http(output_dir: Path) -> Path:
    """Trzy sesje TCP jawnotekstowe: Telnet, kanal kontrolny FTP, HTTP na
    porcie niestandardowym (CHECK-03, material dowodowy kryterium 1 fazy).

    Kazda sesja niesie ruch rozpoznawalny po ksztalcie pierwszych bajtow
    ladunku, nigdy po numerze portu ani po pelnym dekodowaniu protokolu -
    HTTP nasluchuje na `HTTP_PORT` niestandardowym wlasnie po to, zeby
    rozpoznanie po zawartosci bylo jedynym wytlumaczeniem wyniku (PROTO-01
    jako wzorzec, zalozenie Z-49). Nazwa uzytkownika i haslo w kanale
    kontrolnym FTP sa jawnie wymyslone i testowe (zalozenie Z-50) -
    `tests/test_dissectors_cleartext.py` importuje te same stale zamiast
    powielac ich wartosc, zeby sprawdzic ich nieobecnosc w artefaktach.
    """
    # Sesja Telneta, dwa pakiety: kazdy niesie trzybajtowa sekwencje
    # negocjacji opcji. Bajt 0: IAC (0xFF, interpretacja polecenia jako
    # polecenie, nie jako dane). Bajt 1: polecenie negocjacji (klient: WILL
    # / 0xFB, serwer: DO / 0xFD - odpowiedz na inne polecenie, tak jak
    # prawdziwa negocjacja Telneta). Bajt 2: numer opcji (0x01 = echo) -
    # wartosc dowolna, dissector jej nie sprawdza (rozstrzygniecie, nie
    # pominiecie).
    telnet_client = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=TELNET_CLIENT_PORT, dport=TELNET_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes([0xFF, 0xFB, 0x01]))
    )
    telnet_server = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=TELNET_PORT, dport=TELNET_CLIENT_PORT, seq=1, ack=1, flags="PA")
        / Raw(load=bytes([0xFF, 0xFD, 0x01]))
    )

    # Sesja FTP, kanal kontrolny, trzy pakiety: odpowiedz powitalna serwera
    # (kod liczbowy 220, spacja, wlasny wymyslony tekst), potem polecenie
    # klienta z nazwa uzytkownika, potem polecenie klienta z haslem.
    ftp_welcome = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=FTP_CONTROL_PORT, dport=FTP_CLIENT_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=b"220 Test FTP service ready\r\n")
    )
    ftp_user = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=FTP_CLIENT_PORT, dport=FTP_CONTROL_PORT, seq=1, ack=1, flags="PA")
        / Raw(load=f"USER {FTP_TEST_USERNAME}\r\n".encode("ascii"))
    )
    ftp_pass = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=FTP_CLIENT_PORT, dport=FTP_CONTROL_PORT, seq=2, ack=1, flags="PA")
        / Raw(load=f"PASS {FTP_TEST_PASSWORD}\r\n".encode("ascii"))
    )

    # Sesja HTTP, dwa pakiety: linia zadania (metoda, sciezka, wersja) z
    # naglowkiem nazwy hosta, potem linia statusu odpowiedzi z naglowkiem
    # typu tresci i krotkim cialem.
    http_request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=HTTP_CLIENT_PORT, dport=HTTP_PORT, seq=1, ack=0, flags="PA")
        / Raw(
            load=(
                f"GET {HTTP_TEST_PATH} HTTP/1.1\r\n"
                f"Host: {SERVER_IP}\r\n\r\n"
            ).encode("ascii")
        )
    )
    http_response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=HTTP_PORT, dport=HTTP_CLIENT_PORT, seq=1, ack=1, flags="PA")
        / Raw(
            load=(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n\r\nOK"
            ).encode("ascii")
        )
    )

    packets = [
        telnet_client,
        telnet_server,
        ftp_welcome,
        ftp_user,
        ftp_pass,
        http_request,
        http_response,
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cleartext_telnet_ftp_http.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Faza 4: fixture sesji Modbusa zlozonej wylacznie z odczytow (plan 04-04, Task 1) ---


def gen_modbus_read_only_session(output_dir: Path) -> Path:
    """Jedna sesja Modbus/TCP, trzy wymiany zadanie-odpowiedz, wszystkie
    zadania kodu funkcji odczytu rejestrow trzymajacych (0x03).

    Przypadek rozdzielajacy CHECK-05 od CHECK-04 (zalozenie Z-62,
    04-RESEARCH.md Pitfall 9): fixture daje finding za uzycie protokolu
    przemyslowego bez mechanizmu uwierzytelnienia i NIE daje findingu za
    zapis do sterownika, bo nie zawiera ani jednej operacji zapisu - check
    zaimplementowany jako filtr na findingu za zapis rozjechalby sie
    dokladnie tutaj.

    Identyfikator transakcji rosnie z kazda wymiana (1, 2, 3), identyfikator
    jednostki jest staly. Odstep miedzy kolejnymi zadaniami jest krotki
    (0.02 s), tak zeby okno zrzutu (0.05 s) bylo dluzsze niz podwojony
    zmierzony odstep miedzy zadaniami (0.04 s) - inaczej fixture zapaliby
    ostrzezenie o oknie zrzutu za krotkim wobec zmierzonego cyklu
    odpytywania, co byloby zaklaceniem niezwiazanym z CHECK-05.
    """
    packets = []
    for i in range(3):
        trans_id = i + 1
        offset = i * 0.02
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50300, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU03ReadHoldingRegistersRequest(
                startAddr=MODBUS_READ_ONLY_START_ADDR, quantity=1
            )
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50300, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU03ReadHoldingRegistersResponse(
                registerVal=[MODBUS_READ_ONLY_REGISTER_VALUE]
            )
        )
        request.time = BASE_TIMESTAMP + offset
        response.time = BASE_TIMESTAMP + offset + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_read_only_session.pcap"
    wrpcap(str(output_path), packets)
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
    ("modbus_poll_cycle_short_window.pcap", gen_modbus_poll_cycle_short_window),
    ("modbus_poll_cycle_full_window.pcap", gen_modbus_poll_cycle_full_window),
    ("modbus_gateway_multi_unit_id.pcap", gen_modbus_gateway_multi_unit_id),
    ("modbus_tcp_handshake.pcap", gen_modbus_tcp_handshake),
    ("modbus_rtu_over_tcp.pcap", gen_modbus_rtu_over_tcp),
    ("cleartext_telnet_ftp_http.pcap", gen_cleartext_telnet_ftp_http),
    ("modbus_read_only_session.pcap", gen_modbus_read_only_session),
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
