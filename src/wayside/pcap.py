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

__all__ = ["CaptureSummary", "read_capture", "summarize"]


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
