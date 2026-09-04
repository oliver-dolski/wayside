"""Odczyt pliku pcap i podsumowanie zrzutu bez zaleznosci od libpcap/Npcap.

Ten modul importuje `rdpcap`/`wrpcap` WYLACZNIE z `scapy.utils`, nigdy z
`scapy.all` ani z modulow warstwy `scapy.layers.*` (np. `Ether`, `IP`). To
drugie ograniczenie nie jest kosmetyczne: `scapy.layers.l2` importuje
`scapy.arch`, ktory na Windows bezwarunkowo inicjalizuje `scapy.arch.libpcap`
(patrz Pitfall 3 w 01-RESEARCH.md) - zweryfikowane empirycznie w tej fazie,
ze samo `from scapy.utils import rdpcap` NIE pociaga za soba tego importu,
a `from scapy.layers.l2 import Ether` JUZ tak. Konsekwencja dla przyszlych faz:
dekodowanie protokolow (Ether/IP/TCP/Modbus) bedzie musialo albo zaakceptowac
zaleznosc od `scapy.arch.libpcap` przy imporcie, albo znalezc inna sciezke
dekodowania bez warstw `scapy.layers.*`. Odczyt i zapis plikow pcap same w
sobie sa operacjami czysto plikowymi i nie wymagaja libpcap/Npcap - to jest
granica, ktorej ten modul pilnuje.

`PcapReader` bez zarejestrowanej klasy `Ether` (bo jej import jest tu
zabroniony) nie rozpoznaje typu linku i wypisuje ostrzezenie "unknown LL
type - Using Raw packets" na `stderr` przez logger `scapy.runtime`. To
ostrzezenie jest nieszkodliwe dla tego modulu (liczba pakietow i znaczniki
czasu pochodza z ramki, nie z dekodowanej tresci), wiec jest wyciszane
analogicznie do zalecenia z Pitfall 3.
"""

from __future__ import annotations

import logging
import os
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# scapy przy imporcie buduje cache slownikow danych (`services.pickle` i
# pokrewne) w katalogu wyliczanym raz, w `scapy.main`, z `XDG_CACHE_HOME`
# albo z `~/.cache`. Zapis do tego cache'u scapy obsluguje lagodnie, ale
# sprawdzenie `cachepath.exists()` w `scapy.data.scapy_data_cache` NIE jest
# oslonione - a `pathlib.Path.exists()` na katalogu, ktorego ACL zabrania
# nawet przejscia, podnosi `PermissionError`, zamiast zwrocic `False`. Dosc
# jednego `~/.cache/scapy` z restrykcyjnym ACL (typowo: zostawionego przez
# wczesniejsze uruchomienie scapy z podniesionymi uprawnieniami), zeby kazdy
# import tego modulu konczyl sie wyjatkiem.
#
# FOUND-02 obiecuje pakiet testow przechodzacy na czystym klonie, a nie na
# maszynie o wlasciwym stanie katalogu domowego, wiec cache scapy dostaje
# deterministyczna lokalizacje w katalogu tymczasowym. Cache jest wylacznie
# optymalizacja czasu startu - jego utrata nie zmienia wyniku odczytu.
#
# Nadpisanie obowiazuje TYLKO na czas importu scapy: `XDG_CACHE_HOME` jest
# zmienna procesu, a scapy czyta ja raz, wiec po imporcie wracamy do
# poprzedniej wartosci i nie przekierowujemy cache'u innym bibliotekom.
# Jawnie ustawiony `XDG_CACHE_HOME` (np. w CI) ma pierwszenstwo i nie jest
# ruszany. Warunek dziala, dopoki ten modul jest jedynym miejscem w pakiecie
# importujacym scapy - patrz `tests/test_no_external_dissector.py`.
_SCAPY_CACHE_FALLBACK = str(Path(tempfile.gettempdir()) / "wayside-scapy-cache")
_XDG_CACHE_HOME_BEFORE_IMPORT = os.environ.get("XDG_CACHE_HOME")

if _XDG_CACHE_HOME_BEFORE_IMPORT is None:
    os.environ["XDG_CACHE_HOME"] = _SCAPY_CACHE_FALLBACK

try:
    from scapy.utils import rdpcap  # noqa: E402
finally:
    if _XDG_CACHE_HOME_BEFORE_IMPORT is None:
        os.environ.pop("XDG_CACHE_HOME", None)
    else:
        os.environ["XDG_CACHE_HOME"] = _XDG_CACHE_HOME_BEFORE_IMPORT

__all__ = [
    "CaptureSummary",
    "read_capture",
    "summarize",
    "PCAP_GLOBAL_HEADER_LEN",
    "PCAP_RECORD_HEADER_LEN",
    "PCAPNG_BLOCK_HEADER_LEN",
    "PCAP_MAGICS",
    "PCAPNG_MAGIC",
    "CaptureTruncatedError",
    "CaptureFormatError",
    "CaptureStructure",
    "audit_capture_structure",
]


@dataclass(frozen=True)
class CaptureSummary:
    """Podsumowanie jednego zrzutu pcap."""

    path: Path
    packet_count: int
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    duration_s: float


def read_capture(path: Path):
    """Wczytuje zrzut pcap z podanej sciezki.

    Podnosi `FileNotFoundError`, gdy pliku nie ma - nigdy nie zwraca cichej
    pustej listy dla brakujacego pliku.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"Plik zrzutu nie istnieje: {path}")
    return rdpcap(str(path))


def summarize(path: Path) -> CaptureSummary:
    """Zwraca `CaptureSummary` dla zrzutu pod podana sciezka."""
    packets = read_capture(path)
    packet_count = len(packets)

    if packet_count == 0:
        return CaptureSummary(
            path=Path(path),
            packet_count=0,
            first_timestamp=None,
            last_timestamp=None,
            duration_s=0.0,
        )

    timestamps = sorted(float(pkt.time) for pkt in packets)
    first_timestamp = datetime.fromtimestamp(timestamps[0], tz=timezone.utc)
    last_timestamp = datetime.fromtimestamp(timestamps[-1], tz=timezone.utc)
    duration_s = timestamps[-1] - timestamps[0]

    return CaptureSummary(
        path=Path(path),
        packet_count=packet_count,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        duration_s=duration_s,
    )


# --- Audyt strukturalny (D-01) -----------------------------------------------
#
# Wszystko ponizej stoi wylacznie na bibliotece standardowej (struct, pathlib) -
# audyt strukturalny nie dociaga zadnej warstwy scapy (D-04). `rdpcap` odczytuje
# naglowek pliku poprawnie i po prostu przestaje czytac rekordy, gdy strumien
# konczy sie w srodku rekordu - nie traktuje tego jako blad formatu (Pitfall 3,
# 02-RESEARCH.md). Ten audyt wykrywa dokladnie ten przypadek, przez porownanie
# pol dlugosci z faktyczna liczba bajtow pozostajacych w pliku, ZANIM
# `read_capture`/`rdpcap` w ogole dostanie plik do rak (brama w `pipeline.py`).

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16
PCAPNG_BLOCK_HEADER_LEN = 8  # typ bloku (4) + calkowita dlugosc (4)

# Bajty magic klasycznego pcapa (4 warianty: mikrosekundowy/nanosekundowy,
# kazdy w porzadku little/big-endian) -> (format, porzadek bajtow). Wartosci
# zweryfikowane przez `struct.pack` w tej sesji, nie z pamieci.
PCAP_MAGICS: dict[bytes, tuple[str, str]] = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "little"),  # mikrosekundowy, little-endian
    b"\xa1\xb2\xc3\xd4": ("pcap", "big"),  # mikrosekundowy, big-endian
    b"\x4d\x3c\xb2\xa1": ("pcap", "little"),  # nanosekundowy, little-endian
    b"\xa1\xb2\x3c\x4d": ("pcap", "big"),  # nanosekundowy, big-endian
}

# Typ bloku Section Header Block pcapng - palindrom bajtowy, wiec ta sama
# sekwencja niezaleznie od porzadku bajtow pliku (RFC 9-tcpdump/libpcap
# "pcapng"). To jest jedyny sposob rozpoznania formatu PRZED ustaleniem
# porzadku bajtow, ktory pcapng niesie w kolejnym polu (byte order magic).
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_PCAPNG_BYTE_ORDER_MAGIC: dict[bytes, str] = {
    b"\x4d\x3c\x2b\x1a": "little",
    b"\x1a\x2b\x3c\x4d": "big",
}

_PCAPNG_EPB_TYPE = 0x00000006  # Enhanced Packet Block - rekord z pakietem
_PCAPNG_IDB_TYPE = 0x00000001  # Interface Description Block - niesie snaplen
_PCAPNG_IDB_MIN_LEN = 20  # naglowek(8) + linktype(2) + rezerwa(2) + snaplen(4) + trailer(4)


class CaptureTruncatedError(Exception):
    """Zrzut ma poprawny magic formatu, ale strumien konczy sie w srodku
    rekordu/bloku - obciecie wykryte strukturalnie (D-01), nie przez liczbe
    pakietow zwrocona przez `rdpcap`."""


class CaptureFormatError(Exception):
    """Plik ma magic nierozpoznany przez zaden obslugiwany format (klasyczny
    pcap albo pcapng)."""


@dataclass(frozen=True)
class CaptureStructure:
    """Wynik audytu strukturalnego zrzutu, bez interpretacji tresci pakietow."""

    capture_format: str  # "pcap" | "pcapng"
    endianness: str  # "little" | "big"
    record_count: int  # rekordy pcap albo bloki EPB pcapng
    is_structurally_empty: bool  # naglowek poprawny, zero rekordow z pakietem
    snaplen: int | None  # None, gdy niejednoznaczny (patrz snaplen_note)
    snaplen_note: str | None  # niepuste WYLACZNIE gdy snaplen jest None


def _audit_pcap_classic(path: Path, total_size: int, endianness: str) -> CaptureStructure:
    order = "<" if endianness == "little" else ">"
    with open(path, "rb") as handle:
        global_header = handle.read(PCAP_GLOBAL_HEADER_LEN)
        if len(global_header) < PCAP_GLOBAL_HEADER_LEN:
            raise CaptureTruncatedError(
                f"{path}: naglowek globalny pcap obciety na {len(global_header)} bajtach"
            )
        (_magic, _ver_major, _ver_minor, _thiszone, _sigfigs, snaplen, _network) = (
            struct.unpack(order + "IHHiIII", global_header)
        )

        pos = PCAP_GLOBAL_HEADER_LEN
        record_count = 0
        while pos < total_size:
            remaining = total_size - pos
            if remaining < PCAP_RECORD_HEADER_LEN:
                raise CaptureTruncatedError(
                    f"{path}: naglowek rekordu obciety na przesunieciu {pos} bajtow "
                    f"({remaining} z {PCAP_RECORD_HEADER_LEN} bajtow dostepnych)"
                )
            handle.seek(pos)
            record_header = handle.read(PCAP_RECORD_HEADER_LEN)
            (_ts_sec, _ts_frac, incl_len, _orig_len) = struct.unpack(
                order + "IIII", record_header
            )

            # Wartosc z pliku niezaufanego nie jest indeksem, dopoki nie
            # przejdzie kontroli zakresu (T-2-02) - snaplen PRZED skokiem.
            if incl_len > snaplen:
                raise CaptureTruncatedError(
                    f"{path}: dlugosc przechwycona {incl_len} na przesunieciu {pos} "
                    f"bajtow przekracza snaplen {snaplen} z naglowka globalnego"
                )

            pos += PCAP_RECORD_HEADER_LEN
            data_remaining = total_size - pos
            if incl_len > data_remaining:
                raise CaptureTruncatedError(
                    f"{path}: dane rekordu obciete na przesunieciu {pos} bajtow "
                    f"(oczekiwano {incl_len}, dostepne {data_remaining})"
                )
            pos += incl_len
            record_count += 1

        return CaptureStructure(
            capture_format="pcap",
            endianness=endianness,
            record_count=record_count,
            is_structurally_empty=record_count == 0,
            snaplen=snaplen,
            snaplen_note=None,
        )


def _audit_pcapng(path: Path, total_size: int) -> CaptureStructure:
    with open(path, "rb") as handle:
        first_block_probe = handle.read(12)
        if len(first_block_probe) < 12:
            raise CaptureTruncatedError(
                f"{path}: Section Header Block obciety na {len(first_block_probe)} bajtach"
            )

        byte_order_magic = first_block_probe[8:12]
        endianness = _PCAPNG_BYTE_ORDER_MAGIC.get(byte_order_magic)
        if endianness is None:
            raise CaptureFormatError(
                f"{path}: nierozpoznany bajt porzadku {byte_order_magic!r} w "
                "Section Header Block"
            )
        order = "<" if endianness == "little" else ">"

        pos = 0
        record_count = 0
        idb_snaplens: list[int] = []
        while pos < total_size:
            remaining = total_size - pos
            if remaining < PCAPNG_BLOCK_HEADER_LEN:
                raise CaptureTruncatedError(
                    f"{path}: naglowek bloku pcapng obciety na przesunieciu {pos} "
                    f"bajtow ({remaining} z {PCAPNG_BLOCK_HEADER_LEN} bajtow dostepnych)"
                )
            handle.seek(pos)
            block_header = handle.read(PCAPNG_BLOCK_HEADER_LEN)
            block_type, total_length = struct.unpack(order + "II", block_header)

            if total_length < 12 or total_length % 4 != 0:
                raise CaptureTruncatedError(
                    f"{path}: dlugosc bloku {total_length} na przesunieciu {pos} "
                    "bajtow nie jest wielokrotnoscia czterech albo jest mniejsza niz 12"
                )
            if total_length > remaining:
                raise CaptureTruncatedError(
                    f"{path}: blok na przesunieciu {pos} bajtow (dlugosc "
                    f"{total_length}) wykracza poza koniec pliku ({remaining} "
                    "bajtow dostepnych)"
                )

            handle.seek(pos + total_length - 4)
            trailing_raw = handle.read(4)
            (trailing_length,) = struct.unpack(order + "I", trailing_raw)
            if trailing_length != total_length:
                raise CaptureTruncatedError(
                    f"{path}: niezgodnosc dlugosci bloku na przesunieciu {pos} "
                    f"bajtow (poczatek {total_length}, koniec {trailing_length})"
                )

            if block_type == _PCAPNG_EPB_TYPE:
                record_count += 1
            elif block_type == _PCAPNG_IDB_TYPE:
                # Kontrola zakresu PRZED odczytem (T-3-01): blok krotszy niz
                # dwadziescia bajtow nie ma miejsca na pole snaplen na
                # przesunieciu od 12 do 16, wiec konczy sie tu, nie przy
                # sprobie odczytu spoza bloku. Komunikat niesie wylacznie
                # przesuniecie w bajtach, nigdy zawartosc bloku.
                if total_length < _PCAPNG_IDB_MIN_LEN:
                    raise CaptureTruncatedError(
                        f"{path}: blok Interface Description Block na "
                        f"przesunieciu {pos} bajtow (dlugosc {total_length}) "
                        "jest za krotki, zeby zawierac pole snaplen"
                    )
                handle.seek(pos + 12)
                (idb_snaplen,) = struct.unpack(order + "I", handle.read(4))
                idb_snaplens.append(idb_snaplen)
            pos += total_length

        if not idb_snaplens:
            snaplen: int | None = None
            snaplen_note: str | None = (
                f"{path}: brak bloku Interface Description Block w pliku "
                "pcapng - snaplen nie zostal ustalony"
            )
        else:
            unique_snaplens = set(idb_snaplens)
            if len(unique_snaplens) == 1:
                snaplen = idb_snaplens[0]
                snaplen_note = None
            else:
                snaplen = None
                snaplen_note = (
                    f"{path}: {len(unique_snaplens)} blokow Interface "
                    "Description Block niosa rozny snaplen - wartosc nie "
                    "jest jednoznaczna"
                )

        return CaptureStructure(
            capture_format="pcapng",
            endianness=endianness,
            record_count=record_count,
            is_structurally_empty=record_count == 0,
            snaplen=snaplen,
            snaplen_note=snaplen_note,
        )


def audit_capture_structure(path: Path) -> CaptureStructure:
    """Audytuje strukture zrzutu bez interpretacji tresci pakietow.

    Kolejnosc: brak pliku daje `FileNotFoundError` z tym samym komunikatem
    co `read_capture`; plik krotszy niz magic formatu (4 bajty) daje
    `CaptureTruncatedError`; magic nierozpoznany przez zaden obslugiwany
    format daje `CaptureFormatError`; magic rozpoznany, ale naglowek albo
    ktorykolwiek rekord/blok obciety, daje `CaptureTruncatedError`.

    Zaden komunikat wyjatku nie niesie surowych bajtow pliku ani tresci
    ladunku - wylacznie sciezke, przesuniecie w bajtach i nazwe naruszonego
    warunku (T-2-10), analogicznie do `Violation` bez pola tekstowego w
    `scripts/confidentiality_guard.py`.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Plik zrzutu nie istnieje: {path}")

    total_size = path.stat().st_size
    with open(path, "rb") as handle:
        magic_probe = handle.read(4)

    if len(magic_probe) < 4:
        raise CaptureTruncatedError(
            f"{path}: plik krotszy niz magic number formatu (4 bajty, "
            f"znaleziono {len(magic_probe)})"
        )

    if magic_probe == PCAPNG_MAGIC:
        return _audit_pcapng(path, total_size)

    if magic_probe in PCAP_MAGICS:
        _capture_format, endianness = PCAP_MAGICS[magic_probe]
        return _audit_pcap_classic(path, total_size, endianness)

    raise CaptureFormatError(
        f"{path}: magic {magic_probe!r} nie odpowiada zadnemu obslugiwanemu "
        "formatowi (pcap klasyczny ani pcapng)"
    )
