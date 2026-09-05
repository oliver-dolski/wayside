"""Pobranie podzbioru publicznego zbioru 4SICS (REPORT-05, rekord decyzji `0005`).

Uzycie:
    uv run python scripts/fetch_4sics_sample.py
        Pobiera `DATASET_FILE_URL` przez siec, weryfikuje jego sume sha256
        wobec `DATASET_SHA256` PRZED jakimkolwiek dalszym uzyciem pliku,
        buduje deterministyczny podzbior `SLICE_FILENAME` i weryfikuje jego
        sume wobec `SLICE_SHA256`. Oba pliki laduja w `DATASET_DIR`,
        katalogu ignorowanym przez gita.

    uv run python scripts/fetch_4sics_sample.py --source sciezka/do/pliku.pcap
        Buduje podzbior z pliku juz lezacego na dysku - zero polaczen
        sieciowych. Droga zapasowa dla maszyny odcietej od sieci
        (`04-RESEARCH.md`, sekcja "Environment Availability").

    uv run python scripts/fetch_4sics_sample.py --skip-download
        Pomija pobranie i uzywa pliku zrodlowego juz lezacego w
        `DATASET_DIR` (z poprzedniego uruchomienia tego skryptu).

    uv run python scripts/fetch_4sics_sample.py --output-dir sciezka/wyjsciowa
        Nadpisuje katalog wyjsciowy - uzyteczne przy budowie podzbioru do
        katalogu tymczasowego na potrzeby testu.

Ten skrypt jest operacja DEWELOPERSKA, uruchamiana recznie. `wayside analyze`
nigdy go nie wola i nigdy nie siega do sieci - pobrany plik zrodlowy i plik
podzbioru NIE wchodza do repozytorium (rekord decyzji `0005`): oba laduja
w `DATASET_DIR`, wpisanym do `.gitignore` z podanym powodem. Suma kontrolna
pobranego pliku jest sprawdzana PRZED jego uzyciem do budowy podzbioru -
cicha podmiana zbioru u zrodla jest nazwanym ryzykiem rezydualnym rekordu
decyzji `0005` (zagrozenie T-4-28), wiec ten skrypt nigdy nie uzywa pliku,
ktorego suma nie zgadza sie ze stala.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

import wayside.pcap  # noqa: F401 - izolacja cache scapy PRZED importem warstw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.utils import PcapWriter, RawPcapReader  # noqa: E402

__all__ = [
    "DATASET_NAME",
    "DATASET_PAGE_URL",
    "DATASET_FILE_URL",
    "DATASET_FILENAME",
    "DATASET_SHA256",
    "SLICE_FILENAME",
    "SLICE_PACKET_COUNT",
    "SLICE_SHA256",
    "DATASET_DIR",
    "DatasetIntegrityError",
    "fetch_dataset",
    "build_slice",
    "main",
]

# Nazwa zbioru razem z instytucja, ktorej nalezy sie atrybucja (rekord decyzji
# `0005`) - ruch pochodzi z laboratorium konferencji przemyslowej 4SICS,
# udostepniony publicznie przez Netresec za zgoda CS3Sthlm (nastepcy 4SICS).
DATASET_NAME = "4SICS 2015 Geek Lounge (CS3Sthlm, udostepnione przez Netresec)"

# Adres strony zbioru, do ktorej odsyla atrybucja [CITED: WebFetch 2026-09-05].
DATASET_PAGE_URL = "https://www.netresec.com/?page=PCAP4SICS"

# Adres pobrania jednego pliku zrzutu - trzeci z trzech plikow wymienionych
# na stronie zbioru (200 MB). Adres jest tokenem podpisanym u zrodla
# (`share.netresec.com`), wiec badanie fazy nadaje mu waznosc siedmiu dni -
# jesli przestanie dzialac, nowy adres trzeba odczytac ze strony
# `DATASET_PAGE_URL` (zalozenie Z-75).
DATASET_FILE_URL = (
    "https://share.netresec.com/s/gw6Y2QzJHqDD5pr/download/"
    "4SICS-GeekLounge-151022.pcap"
)

# Nazwa pliku u zrodla - potwierdzona pobraniem, nie zgadywana.
DATASET_FILENAME = "4SICS-GeekLounge-151022.pcap"

# Suma kontrolna pliku zrodlowego, ustalona przy pierwszym pobraniu
# (2026-09-05, 209 236 002 bajty). Cicha podmiana pliku u zrodla jest
# ryzykiem rezydualnym nazwanym wprost w rekordzie decyzji `0005` -
# ta stala jest jedyna obrona przed nim (zagrozenie T-4-28).
DATASET_SHA256 = "82529c23906416dc73d7f1926a0d38b82527f1f2a7ff8c6f755ce3208feb9643"

SLICE_FILENAME = "4sics-slice.pcap"

# Liczba pakietow podzbioru: pierwsze `SLICE_PACKET_COUNT` pakietow pliku
# zrodlowego (zalozenie Z-69).
SLICE_PACKET_COUNT = 2000

# Suma kontrolna pliku podzbioru, zbudowanego z pierwszych
# `SLICE_PACKET_COUNT` pakietow `DATASET_FILENAME` (2026-09-05).
SLICE_SHA256 = "2665c898fb6eccad6bef669a3d0eb5cbf1ac1fe39f9168b98584f698b57aadb8"

# Katalog pobrania, wyprowadzony z polozenia skryptu - nie z katalogu
# uruchomienia procesu. Ignorowany przez gita (`.gitignore`, rekord decyzji
# `0005`): zbior zewnetrzny wazacy rzad setek megabajtow nie wchodzi do
# repozytorium.
DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "4sics"

_CHUNK_SIZE = 1024 * 1024


class DatasetIntegrityError(Exception):
    """Podnoszony w trzech przypadkach: stala sumy kontrolnej jest pusta
    (bootstrap - pierwsze pobranie, zanim ktokolwiek wpisal wartosc do tego
    modulu), suma pliku zrodlowego nie zgadza sie ze stala, albo suma pliku
    podzbioru nie zgadza sie ze stala. Zaden z tych przypadkow nie konczy
    sie cichym uzyciem pliku - to jest cala racja bytu tej klasy."""


def _verify_checksum(path: Path, expected: str, *, what: str, constant_name: str) -> None:
    """Liczy sume sha256 `path` strumieniowo i porownuje ja z `expected`.

    `expected` puste: sciezka bootstrapu (zalozenie Z-75) - konczy sie
    `DatasetIntegrityError` niosacym policzona sume, zeby dala sie wpisac
    jako wartosc stalej `constant_name`. `expected` niezgodne z policzona
    suma: `DatasetIntegrityError` niosacy oba skroty (zagrozenie T-4-28)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()

    if not expected:
        raise DatasetIntegrityError(
            f"Stala {constant_name} jest pusta - to jest pierwsze uzycie tego "
            f"pliku. Suma sha256 {what} ({path}): {actual}. Wpisz ta wartosc "
            f"jako {constant_name} w tym module, zeby kazde kolejne uruchomienie "
            "sprawdzalo ja normalnie."
        )
    if actual != expected:
        raise DatasetIntegrityError(
            f"Suma kontrolna {what} niezgodna: oczekiwano {expected}, otrzymano "
            f"{actual}. Plik ({path}) mogl zostac cicho podmieniony u zrodla - "
            "to jest dokladnie ryzyko rezydualne nazwane w rekordzie decyzji "
            "`0005`."
        )


def fetch_dataset(
    *,
    url: str = DATASET_FILE_URL,
    source_path: Path | None = None,
    output_dir: Path = DATASET_DIR,
) -> Path:
    """Zwraca sciezke pliku zrodlowego zbioru pod `output_dir`.

    `source_path` podany: kopiuje plik z dysku strumieniowo, nie dotyka
    sieci - droga zapasowa dla maszyny odcietej, ten sam wzorzec, ktory
    `scripts/gen_oui_db.py` niesie dla rejestru producentow. `source_path`
    pominiety: pobiera `url` strumieniowo przez biblioteke standardowa,
    wylacznie po protokole szyfrowanym, bez przekierowania na protokol
    nieszyfrowany. W obu przypadkach: zapis do pliku tymczasowego w
    `output_dir` i podmiana atomowa (`os.replace`) po zakonczeniu - pobranie
    przerwane w polowie nie zostawia pliku wygladajacego na kompletny. Suma
    sha256 jest sprawdzona PRZED zwroceniem sciezki wywolujacemu (zagrozenie
    T-4-28).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    target_path = output_dir / DATASET_FILENAME

    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(output_dir), prefix=f".{DATASET_FILENAME}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            if source_path is not None:
                with Path(source_path).open("rb") as source_handle:
                    while True:
                        chunk = source_handle.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        handle.write(chunk)
            else:
                if not url.startswith("https://"):
                    raise ValueError(
                        f"Adres pobrania {url!r} nie uzywa protokolu "
                        "szyfrowanego (https)."
                    )
                request = urllib.request.Request(
                    url, headers={"User-Agent": "wayside-fetch-4sics-sample/1.0"}
                )
                with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
                    while True:
                        chunk = response.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        handle.write(chunk)
        os.replace(tmp_path_str, target_path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise

    _verify_checksum(
        target_path, DATASET_SHA256, what="pliku zrodlowego", constant_name="DATASET_SHA256"
    )
    return target_path


def build_slice(source: Path, output_dir: Path = DATASET_DIR) -> Path:
    """Buduje plik podzbioru pod `output_dir` z pierwszych `SLICE_PACKET_COUNT`
    pakietow `source`.

    Czyta `source` STRUMIENIOWO (`RawPcapReader`, bez dekodowania warstw) -
    odczyt calego pliku o rozmiarze rzedu setek megabajtow przez warstwe
    odczytu tego projektu (`wayside.pcap`/scapy) zajalby minuty i gigabajty
    pamieci (zalozenie Z-69). Zapisuje pierwsze `SLICE_PACKET_COUNT`
    pakietow do pliku podzbioru, zachowujac oryginalne znaczniki czasu i
    oryginalny typ warstwy drugiej (`reader.linktype`) - podzbior ma niesc
    prawdziwy ruch z prawdziwymi znacznikami, bo to jest cala jego wartosc.
    Suma sha256 pliku podzbioru jest sprawdzona PRZED zwroceniem sciezki
    wywolujacemu.
    """
    source = Path(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    target_path = output_dir / SLICE_FILENAME

    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(output_dir), prefix=f".{SLICE_FILENAME}.", suffix=".tmp"
    )
    os.close(fd)
    try:
        written = 0
        with RawPcapReader(str(source)) as reader, PcapWriter(
            tmp_path_str, linktype=reader.linktype
        ) as writer:
            writer.write_header(None)
            for raw_bytes, metadata in reader:
                if written >= SLICE_PACKET_COUNT:
                    break
                writer.write_packet(
                    raw_bytes,
                    sec=metadata.sec,
                    usec=metadata.usec,
                    caplen=metadata.caplen,
                    wirelen=metadata.wirelen,
                )
                written += 1
        os.replace(tmp_path_str, target_path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise

    _verify_checksum(
        target_path, SLICE_SHA256, what="pliku podzbioru", constant_name="SLICE_SHA256"
    )
    return target_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help=(
            "Sciezka do pliku zrodlowego juz lezacego na dysku. Podana: "
            "zero polaczen sieciowych. Pominieta: pobranie przez "
            f"{DATASET_FILE_URL}."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DATASET_DIR,
        help=f"Katalog wyjsciowy (domyslnie {DATASET_DIR}).",
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help=(
            "Pomija pobranie i uzywa pliku zrodlowego juz lezacego w "
            "katalogu wyjsciowym z poprzedniego uruchomienia."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)

    try:
        if args.skip_download:
            source_path = output_dir / DATASET_FILENAME
            if not source_path.is_file():
                print(
                    f"--skip-download podany, ale {source_path} nie istnieje - "
                    "uruchom najpierw bez tej flagi.",
                    file=sys.stderr,
                )
                return 1
            _verify_checksum(
                source_path,
                DATASET_SHA256,
                what="pliku zrodlowego",
                constant_name="DATASET_SHA256",
            )
        else:
            source_path = fetch_dataset(source_path=args.source, output_dir=output_dir)
        slice_path = build_slice(source_path, output_dir=output_dir)
    except DatasetIntegrityError as exc:
        print(f"Blad integralnosci zbioru: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Nie udalo sie pobrac albo przetworzyc zbioru: {exc}", file=sys.stderr)
        return 1

    print(f"Zapisano plik zrodlowy: {source_path}")
    print(f"Zapisano podzbior: {slice_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
