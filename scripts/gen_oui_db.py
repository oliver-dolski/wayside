"""Generator jednorazowy tabeli producentow z rejestru IEEE OUI (ASSET-02).

Uzycie:
    uv run python scripts/gen_oui_db.py
        Pobiera `IEEE_OUI_CSV_URL` przez siec i zapisuje
        `src/wayside/assets/oui_table.tsv` (sciezka domyslna).

    uv run python scripts/gen_oui_db.py --source sciezka/do/oui.csv
        Buduje tabele z pliku CSV juz lezacego na dysku - zerowych polaczen
        sieciowych. Droga zapasowa dla maszyny odcietej od sieci
        (`03-RESEARCH.md`, sekcja "Environment Availability").

    uv run python scripts/gen_oui_db.py --output sciezka/wyjsciowa.tsv
        Nadpisuje sciezke wyjsciowa - uzyteczne przy budowaniu pliku do
        katalogu tymczasowego na potrzeby testu albo porownania.

Ten skrypt jest operacja DEWELOPERSKA, uruchamiana recznie. `wayside analyze`
nigdy go nie wola i nigdy nie siega do sieci - warstwa uruchomieniowa
(`src/wayside/assets/oui.py`) czyta wylacznie plik wyprodukowany tutaj,
juz lezacy na dysku (Pattern 6, `03-RESEARCH.md`).

Dwa uruchomienia z tym samym zrodlem CSV, tego samego dnia, daja plik
wyjsciowy bajtowo identyczny - komentarz naglowka niesie date wygenerowania
pliku, wiec odtwarzalnosc bajtowa jest ograniczona do jednego dnia
kalendarzowego (zalozenie Z-24 z PLAN.md: ten plik NIE wchodzi pod bramke
determinizmu `scripts/gen_fixtures.py --check`, bo dane pochodza od strony
trzeciej, nie sa fixture'em generowanym z samego repozytorium).
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import sys
import urllib.request
from pathlib import Path

from wayside.assets.oui import OUI_TABLE_PATH, normalize_mac_prefix

__all__ = [
    "IEEE_OUI_CSV_URL",
    "fetch_oui_csv",
    "build_table",
    "write_table",
    "main",
]

# Adres potwierdzony jako oficjalny endpoint rejestru IEEE Registration
# Authority [CITED: WebSearch 2026-09-04, 03-RESEARCH.md Pattern 6].
IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# Nazwy kolumn oczekiwane w naglowku CSV rejestru. Uzywane wylacznie do
# odczytu wartosci PO tym, jak `csv.DictReader` sam wyprowadzil naglowek
# z pierwszego wiersza pliku zrodlowego - format pliku dostawcy nie jest
# kontraktem tego projektu, wiec kolejnosc kolumn nigdy nie jest zakladana.
_COLUMN_PREFIX = "Assignment"
_COLUMN_ORGANIZATION = "Organization Name"


def fetch_oui_csv(*, url: str = IEEE_OUI_CSV_URL, source_path: Path | None = None) -> str:
    """Zwraca tresc pliku CSV rejestru IEEE OUI jako lancuch.

    `source_path` podany: czyta plik z dysku, jawnym `encoding="utf-8"`,
    i NIE dotyka sieci - droga zapasowa dla maszyny odcietej. `source_path`
    pominiety: pobiera `url` przez `urllib.request` z biblioteki standardowej,
    wylacznie po protokole szyfrowanym, bez przekierowania na protokol
    nieszyfrowany.
    """
    if source_path is not None:
        return Path(source_path).read_text(encoding="utf-8")

    if not url.startswith("https://"):
        raise ValueError(
            f"Adres zrodla {url!r} nie uzywa protokolu szyfrowanego (https)."
        )

    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset)


def build_table(csv_text: str) -> list[tuple[str, str]]:
    """Parsuje CSV rejestru IEEE OUI do listy par (prefiks, nazwa organizacji).

    Nazwy kolumn sa odczytywane z pierwszego wiersza pliku zrodlowego przez
    `csv.DictReader` - format pliku dostawcy nie jest kontraktem, ktory ten
    projekt kontroluje. Prefiks jest normalizowany przez
    `wayside.assets.oui.normalize_mac_prefix` (ta sama funkcja, ktora
    warstwa uruchomieniowa uzywa do lookupu - jedno zrodlo prawdy o
    ksztalcie prefiksu). Nazwa organizacji jest oczyszczona ze znakow
    tabulacji i konca linii przez zwiniecie bialych znakow - tabulator
    w nazwie zlamalby format wyjsciowy tabeli.

    Wiersz o prefiksie niepoprawnym albo o pustej nazwie jest pomijany, ale
    LICZBA pominietych wierszy jest wypisywana na stderr - cicha strata
    wierszy przy transformacji danych jest tym samym trybem porazki co ciche
    pominiecie hosta w inwentarzu.

    Prefiks wystepujacy w zrodle wiecej niz raz (rejestr IEEE zawiera takie
    przypadki - reassygnacja tego samego zakresu w czasie) zachowuje
    OSTATNIA napotkana nazwe organizacji: to jest ten sam porzadek
    pierwszenstwa, ktory `load_oui_table` przyjmuje przy budowie slownika
    z pliku, wiec plik wyjsciowy generatora i jego odczyt w warstwie
    uruchomieniowej sa spojne.

    Zwraca liste par posortowana rosnaco po prefiksie.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    fieldnames = reader.fieldnames or []
    if _COLUMN_PREFIX not in fieldnames or _COLUMN_ORGANIZATION not in fieldnames:
        raise ValueError(
            f"Zrodlo CSV nie ma oczekiwanych kolumn {_COLUMN_PREFIX!r} i "
            f"{_COLUMN_ORGANIZATION!r} w pierwszym wierszu - znaleziono "
            f"{fieldnames!r}."
        )

    table: dict[str, str] = {}
    skipped = 0
    for row in reader:
        raw_prefix = (row.get(_COLUMN_PREFIX) or "").strip()
        raw_name = (row.get(_COLUMN_ORGANIZATION) or "").strip()
        prefix = normalize_mac_prefix(raw_prefix)
        cleaned_name = " ".join(raw_name.split())
        if prefix is None or not cleaned_name:
            skipped += 1
            continue
        table[prefix] = cleaned_name

    if skipped:
        print(
            f"Pominieto {skipped} wiersz(y) zrodla o prefiksie niepoprawnym "
            "albo o pustej nazwie organizacji.",
            file=sys.stderr,
        )

    return sorted(table.items())


def write_table(rows: list[tuple[str, str]], output_path: Path, *, source: str) -> Path:
    """Zapisuje tabele prefiks-producent pod `output_path`.

    Jawny `encoding="utf-8"` i jawny `newline="\\n"` - ta sama dyscyplina co
    `model.write_atomic` z Fazy 2: plik zapisany na Windows nie moze
    rozjechac sie koncem linii z plikiem zapisanym gdzie indziej. Pierwsze
    trzy wiersze sa komentarzami niosacymi zrodlo, date wygenerowania pliku
    i liczbe wpisow; potem wiersze danych, prefiks i nazwa rozdzielone
    tabulatorem, w kolejnosci juz posortowanej przez `build_table`.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_on = datetime.date.today().isoformat()
    lines = [
        f"# zrodlo: {source}\n",
        f"# data wygenerowania: {generated_on}\n",
        f"# wpisow: {len(rows)}\n",
    ]
    lines.extend(f"{prefix}\t{name}\n" for prefix, name in rows)

    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(lines)
    return output_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help=(
            "Sciezka do pliku CSV rejestru IEEE OUI juz lezacego na dysku. "
            "Podana: zero polaczen sieciowych. Pominieta: pobranie przez "
            f"{IEEE_OUI_CSV_URL}."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUI_TABLE_PATH,
        help=f"Sciezka pliku wyjsciowego (domyslnie {OUI_TABLE_PATH}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        csv_text = fetch_oui_csv(source_path=args.source)
    except (OSError, ValueError) as exc:
        print(f"Nie udalo sie odczytac zrodla rejestru IEEE OUI: {exc}", file=sys.stderr)
        return 1

    try:
        rows = build_table(csv_text)
    except ValueError as exc:
        print(f"Zrodlo CSV ma nieoczekiwany ksztalt: {exc}", file=sys.stderr)
        return 1

    if not rows:
        print("Zrodlo nie zawieralo zadnego poprawnego wiersza danych.", file=sys.stderr)
        return 1

    source_label = str(args.source) if args.source is not None else IEEE_OUI_CSV_URL
    output_path = write_table(rows, args.output, source=source_label)
    print(f"Zapisano {len(rows)} wpisow producentow do {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
