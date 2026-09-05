"""Wygenerowanie przykladowego raportu z podzbioru zbioru 4SICS (REPORT-05).

Uzycie:
    uv run python scripts/gen_example_report.py
        Uruchamia pelna analize na pliku podzbioru zbudowanym przez
        `scripts/fetch_4sics_sample.py` i zapisuje trzy artefakty pod
        `examples/4sics/`: `analysis.json`, `report.md`, `report.pdf`.

    uv run python scripts/gen_example_report.py --slice sciezka/do/podzbioru.pcap
        Nadpisuje sciezke pliku podzbioru.

    uv run python scripts/gen_example_report.py --output-dir sciezka/wyjsciowa
        Nadpisuje katalog wyjsciowy - uzyteczne przy porownaniu wyniku z
        plikami juz lezacymi w repozytorium (test odtwarzalnosci).

Dwie rzeczy, ktore ten skrypt niesie i ktore MUSZA pozostac prawdziwe:

1. Znacznik czasu wygenerowania jest STALA (`FIXED_GENERATED_AT`), nigdy
   odczytem zegara systemowego - dwa uruchomienia w roznych momentach daja
   wiec ten sam plik (04-RESEARCH.md, Pitfall 7; D-02 z Fazy 2).
2. Trzy artefakty tego katalogu sa porownywane bajtowo z plikami
   swiezo wygenerowanymi (test odtwarzalnosci, tests/test_example_report.py)
   - `examples/4sics/report.md` i `examples/4sics/analysis.json` sa dlatego
   wylaczone z normalizacji konca linii w `.gitattributes` (zalozenie Z-72):
   bez tego wylaczenia plik zacommitowany przechodzilby przez normalizacje
   gita przy checkoucie, a plik swiezo wygenerowany nie, i porownanie
   bajtowe zestawialoby dwie rozne rzeczy.

Ten skrypt jest operacja DEWELOPERSKA. `wayside analyze` nigdy go nie wola.
Odtwarzalnosc tego skryptu jest ograniczona do pliku podzbioru lezacego na
dysku pod ta sama sciezka i o tej samej tresci - zbuduj go najpierw przez
`scripts/fetch_4sics_sample.py`, jesli go nie masz.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fetch_4sics_sample import DATASET_DIR, SLICE_FILENAME  # noqa: E402

from wayside.model import write_atomic_bytes  # noqa: E402
from wayside.pipeline import analyze  # noqa: E402
from wayside.report_pdf import render_pdf  # noqa: E402

__all__ = ["FIXED_GENERATED_AT", "EXAMPLE_DIR", "generate", "main"]

# Data rekordu decyzji `0005` (ten, ktory rozstrzygnal zbior 4SICS jako
# zrodlo przykladowego raportu), w strefie czasowej uniwersalnej - stala
# dowolna byla by wartoscia bez znaczenia, ktorej nikt nie umie uzasadnic
# przy pierwszej korekcie; ta data wiaze artefakt z decyzja, ktora go
# powolala (zalozenie Z-74).
FIXED_GENERATED_AT = datetime(2026, 9, 4, tzinfo=timezone.utc)

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "4sics"

DEFAULT_SLICE_PATH = DATASET_DIR / SLICE_FILENAME


def generate(slice_path: Path, output_dir: Path = EXAMPLE_DIR) -> tuple[Path, Path, Path]:
    """Generuje trzy artefakty przykladowego raportu pod `output_dir` z
    pliku podzbioru `slice_path`. Zwraca trojke sciezek
    (analysis_path, report_path, pdf_path).

    Wola `wayside.pipeline.analyze` z `FIXED_GENERATED_AT` - ta funkcja
    zapisuje pierwsze dwa artefakty (`analysis.json`, `report.md`) sama, wiec
    ten skrypt ich nie zapisuje po raz drugi. `render_pdf` jest wolane
    WPROST na TYM SAMYM slowniku modelu, z TYM SAMYM znacznikiem czasu i
    z TYMI SAMYMI ostrzezeniami, ktore zwrocila analiza - nigdy przez
    podproces komendy CLI (04-RESEARCH.md, Open Question 2: komenda CLI
    bierze znacznik czasu z zegara, a ten skrypt potrzebuje stalej)."""
    result = analyze(Path(slice_path), out_dir=Path(output_dir), generated_at=FIXED_GENERATED_AT)

    pdf_bytes = render_pdf(
        result.analysis, generated_at=FIXED_GENERATED_AT, warnings=result.warnings
    )
    pdf_path = Path(output_dir) / "report.pdf"
    write_atomic_bytes(pdf_path, pdf_bytes)

    return result.analysis_path, result.report_path, pdf_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slice",
        type=Path,
        default=DEFAULT_SLICE_PATH,
        help=f"Sciezka pliku podzbioru (domyslnie {DEFAULT_SLICE_PATH}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=EXAMPLE_DIR,
        help=f"Katalog wyjsciowy (domyslnie {EXAMPLE_DIR}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if not args.slice.is_file():
        print(
            f"Plik podzbioru {args.slice} nie istnieje. Zbuduj go najpierw: "
            "uv run python scripts/fetch_4sics_sample.py",
            file=sys.stderr,
        )
        return 1

    analysis_path, report_path, pdf_path = generate(args.slice, args.output_dir)
    print(f"Zapisano: {analysis_path}")
    print(f"Zapisano: {report_path}")
    print(f"Zapisano: {pdf_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
