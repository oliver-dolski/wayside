"""Lookup producenta urzadzenia z prefiksu adresu MAC wobec tabeli lokalnej,
wyprowadzonej z rejestru IEEE (ASSET-02).

Trzy rzeczy wprost, tak jak wymaga tego dokumentacja tego modulu w calym
projekcie:

1. Dane pochodza z jednorazowego pobrania rejestru IEEE OUI, wykonanego
   recznie przez `scripts/gen_oui_db.py` - skrypt deweloperski, ktory NIGDY
   nie jest wolany przez ta warstwe uruchomieniowa.
2. Ta warstwa czyta wylacznie plik lokalny z dysku (`OUI_TABLE_PATH`) i
   NIGDY nie wykonuje zadnego zapytania sieciowego - `wayside analyze`
   pozostaje pasywne i zdatne do pracy w sieci odcietej.
3. Producent jest WNIOSKIEM wyprowadzonym z tabeli, nie obserwacja z ruchu
   (zalozenie Z-23): nazwa organizacji moze byc nieaktualna albo dotyczyc
   dostawcy ukladu, nie producenta finalnego urzadzenia. Kazdy wynik tego
   modulu jest wiec przeznaczony do niesienia znacznika rodziny `inferred`,
   nigdy `observed` - ten modul sam znacznika nie przypisuje, robi to
   wywolujacy (`wayside.assets.inventory.build_assets`).

`OUI_TABLE_PATH` jest wyprowadzona z `Path(__file__).resolve().parent`,
nigdy z katalogu biezacego procesu - ta sama zasada, ktora `CATALOG_ROOT`
niesie w `wayside.standards.mapper`.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "OUI_TABLE_PATH",
    "OUI_PREFIX_LEN",
    "PROVENANCE_METHOD_OUI",
    "OuiTableError",
    "normalize_mac_prefix",
    "load_oui_table",
    "lookup_vendor",
]

OUI_TABLE_PATH = Path(__file__).resolve().parent / "oui_table.tsv"
OUI_PREFIX_LEN = 6
PROVENANCE_METHOD_OUI = "oui-lookup"

_HEX_DIGITS = frozenset("0123456789ABCDEF")
_SEPARATOR_TRANSLATION = str.maketrans("", "", ":-.")


class OuiTableError(Exception):
    """Tabela producentow nieczytelna, nieobecna na dysku, albo niosaca
    wiersz naruszajacy format dwukolumnowy rozdzielony tabulatorem."""


def normalize_mac_prefix(mac: str) -> str | None:
    """Zwraca prefiks adresu MAC jako szesc wielkich znakow szesnastkowych,
    bez separatorow, albo `None` dla wejscia niepoprawnego.

    Zdejmuje dwukropek, myslnik i kropke, zamienia litery na wielkie i
    sprawdza, ze wynik ma co najmniej `OUI_PREFIX_LEN` znakow oraz ze kazdy
    ze znakow prefiksu jest cyfra szesnastkowa. Adres MAC pochodzi z ramki,
    czyli z wejscia niezaufanego - funkcja NIGDY nie podnosi wyjatku:
    wartosc niepoprawna jest wejsciem spodziewanym, nie bledem programu.
    """
    stripped = mac.translate(_SEPARATOR_TRANSLATION).upper()
    if len(stripped) < OUI_PREFIX_LEN:
        return None
    prefix = stripped[:OUI_PREFIX_LEN]
    if not all(ch in _HEX_DIGITS for ch in prefix):
        return None
    return prefix


def load_oui_table(path: Path = OUI_TABLE_PATH) -> dict[str, str]:
    """Wczytuje tabele prefiks-producent z pliku tekstowego pod `path`,
    z jawnym `encoding="utf-8"`.

    Wiersze puste i wiersze zaczynajace sie od znaku hash sa pomijane.
    Kazdy pozostaly wiersz musi miec dokladnie dwie czesci rozdzielone
    tabulatorem (prefiks, nazwa organizacji) i prefiks musi przejsc przez
    `normalize_mac_prefix`; kazda inna liczba czesci albo prefiks
    niepoprawny podnosi `OuiTableError` z NUMEREM WIERSZA w komunikacie -
    ciche pomijanie wiersza uszkodzonego zamienialoby plik danych
    uszkodzony w cicha, niepelna odpowiedz. Sciezka nieistniejaca podnosi
    `OuiTableError` z komunikatem nazywajacym brak tabeli w tym drzewie
    (zalozenie Z-21) - `wayside.pipeline.analyze` zamienia to na jawne
    ostrzezenie, nigdy na ciche pole nieustalone.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OuiTableError(
            f"Tabela producentow nie zostala odczytana ze sciezki {path} - "
            "plik nie zostal dolaczony do tego drzewa repozytorium."
        ) from exc

    table: dict[str, str] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            raise OuiTableError(
                f"Tabela producentow {path}, wiersz {line_no}: oczekiwano "
                f"dwoch kolumn rozdzielonych tabulatorem, znaleziono "
                f"{len(parts)}."
            )
        raw_prefix, vendor_name = parts
        prefix = normalize_mac_prefix(raw_prefix)
        if prefix is None:
            raise OuiTableError(
                f"Tabela producentow {path}, wiersz {line_no}: prefiks "
                f"{raw_prefix!r} nie jest poprawnym zapisem szesnastkowym."
            )
        table[prefix] = vendor_name
    return table


def lookup_vendor(mac: str, table: dict[str, str]) -> str | None:
    """Zwraca nazwe organizacji dla adresu `mac` wobec `table`, albo `None`
    gdy adres jest niepoprawny albo jego prefiks nie ma dopasowania w
    tabeli. Sklada `normalize_mac_prefix` z odczytem ze slownika przez
    `.get` - nigdy nie podnosi wyjatku."""
    prefix = normalize_mac_prefix(mac)
    if prefix is None:
        return None
    return table.get(prefix)
