"""Bramka maszynowa rekordu decyzji `0004` (sygnatura CLC/TS 50701) i rekordu
`0006` (weryfikacja powolan wobec egzemplarza normy).

Rekord decyzji `0004`, sekcja "Sposob egzekwowania", zapisuje wprost: bramka
maszynowa dla tego rozstrzygniecia NIE ISTNIEJE w chwili jego zapisu i
powstaje razem z planem tej fazy. Ten plik jest ta bramka.

Wartosc `FORBIDDEN_DESIGNATION` jest WZIETA z sekcji "Odrzucone alternatywy"
rekordu `0004`, nie wpisana z pamieci - rekord jest zrodlem prawdy dla tego,
co bramka ma zakazac.

**Bramka nad tekstem PDF jest pominieta (skip), nie fikcyjna.** Plan `04-03`
(eksport do PDF) jest zaparkowany na bramce dla czlowieka (legalnosc pakietu)
i nie wykonal sie przed tym planem, wiec `wayside.report_pdf` i `pypdf` nie
istnieja jeszcze w tym drzewie. Test importuje oba przez `pytest.importorskip`
- gdy plan `04-03` wyladuje, ten sam test zacznie sie faktycznie wykonywac bez
zadnej zmiany tego pliku. Zarejestrowane w `.planning/WINDOWS.md`.
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

DECISION_RECORD_PATH = REPO_ROOT / "docs" / "decisions" / "0004-sygnatura-clc-ts-50701.md"

# Wartosc oczekiwana pola `resolved_option` z frontmatteru rekordu decyzji
# powyzej. Test pierwszy odczytuje frontmatter i porownuje z ta stala - bez
# tego bramka nie jest zwiazana z rekordem i przestanie miec sens w dniu,
# w ktorym rekord zostanie zrewidowany, nie zauwazajac tego.
EXPECTED_RESOLVED_OPTION = "clc-ts-50701-2023"

# Wziete z sekcji "Odrzucone alternatywy" rekordu 0004: "`EN 50701` bez roku
# (odrzucona, bo cytuje dokument, ktory nie istnieje...)" - postac bez roku,
# dokladnie tak, jak tam stoi.
FORBIDDEN_DESIGNATION = "EN 50701"

# Katalog dokumentow, katalog planowania i katalog testow sa POZA zakresem,
# kazdy z osobnego powodu:
# - docs/decisions/ musi wolno nazwac po imieniu oznaczenie odrzucone
#   (rekord 0004 sam je cytuje w sekcji "Odrzucone alternatywy");
# - .planning/ niesie notatki planistyczne, w tym STATE.md i badanie fazy,
#   ktore rowniez cytuja oznaczenie odrzucone jako zapis stanu wiedzy sprzed
#   korekty (ten sam powod co w tests/test_no_external_dissector.py);
# - tests/ niesie ten wlasny plik, ktory musi wolno niesc stala
#   FORBIDDEN_DESIGNATION jako WARTOSC PYTHONA, nie jako tekst prozy - gdyby
#   ten katalog byl w zakresie, ten plik lamalby wlasna bramke.
SCAN_SCOPE: tuple[str, ...] = ("src", "scripts", "examples", "README.md")

# Czlon sygnatury specyfikacji technicznej CENELEC - kazdy wpis katalogu norm
# zaczynajacy sie od tego czlonu ma niesc rok edycji, bo dwie edycje tego
# dokumentu roznia sie trescia (rekord 0004, sekcja "Sposob egzekwowania").
RAILWAY_STANDARD_PREFIX = "CLC/TS"
EXPECTED_RAILWAY_EDITION = "2023"

_RESOLVED_OPTION_RE = re.compile(r"^resolved_option:\s*(\S+)\s*$", re.MULTILINE)


# --- Test pierwszy: pole rozstrzygniecia frontmatteru rekordu 0004 ---------


def test_decision_record_resolved_option_matches_expected():
    text = DECISION_RECORD_PATH.read_text(encoding="utf-8")
    match = _RESOLVED_OPTION_RE.search(text)
    assert match is not None, (
        f"Rekord decyzji {DECISION_RECORD_PATH} nie niesie pola "
        "'resolved_option' w frontmatterze."
    )
    assert match.group(1) == EXPECTED_RESOLVED_OPTION, (
        f"Pole 'resolved_option' rekordu {DECISION_RECORD_PATH} niesie "
        f"{match.group(1)!r}, oczekiwano {EXPECTED_RESOLVED_OPTION!r}."
    )


# --- Funkcje pomocnicze wspolne dla testow ponizej --------------------------
#
# Wzorzec skanu drzewa skopiowany z
# tests/test_no_external_dissector.py::scan_tree - dopasowanie podciagu bez
# rozrozniania wielkosci liter, pliki niedekodowalne jako tekst pomijane.


def _scan_tree_for_designation(root: Path, designation: str) -> list[tuple[Path, int]]:
    pattern = re.compile(re.escape(designation), re.IGNORECASE)

    if root.is_file():
        targets = [root]
    elif root.is_dir():
        targets = [p for p in root.rglob("*") if p.is_file()]
    else:
        return []

    hits: list[tuple[Path, int]] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append((path, line_no))
    return hits


def _scan_scope_for_designation(designation: str) -> list[tuple[Path, int]]:
    hits: list[tuple[Path, int]] = []
    for rel in SCAN_SCOPE:
        target = REPO_ROOT / rel
        if target.exists():
            hits.extend(_scan_tree_for_designation(target, designation))
    return hits


def _format_hits(hits: list[tuple[Path, int]]) -> str:
    # Komunikat niesie sciezke i numer linii, nigdy tresc linii - ta sama
    # dyscyplina co w tests/test_standards_catalog.py i
    # scripts/confidentiality_guard.py.
    return "\n".join(f"  {path}:{line}" for path, line in hits)


def analyzable_fixtures() -> list[Path]:
    """Kazdy fixture z katalogu, ktory konczy analize bez wyjatku. Wzorzec
    `tests/test_standards_catalog.py::analyzable_fixtures`."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} nie produkuje artefaktow (brama D-01)")


# --- Test drugi: brak oznaczenia odrzuconego w kodzie, skryptach, ----------
# --- przykladach i README ---------------------------------------------------


def test_scan_scope_carries_no_forbidden_designation():
    hits = _scan_scope_for_designation(FORBIDDEN_DESIGNATION)
    assert hits == [], (
        f"Oznaczenie odrzucone w rekordzie decyzji {DECISION_RECORD_PATH} "
        f"znalezione w:\n{_format_hits(hits)}"
    )


# --- Test trzeci: brak oznaczenia odrzuconego w wyrenderowanym raporcie ----
# --- markdown kazdego analizowalnego fixture'u ------------------------------


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_rendered_report_carries_no_forbidden_designation(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    assert FORBIDDEN_DESIGNATION not in result.report_markdown, (
        f"{fixture.name}: raport markdown niesie oznaczenie odrzucone "
        f"w rekordzie decyzji {DECISION_RECORD_PATH}."
    )


# --- Test czwarty: brak oznaczenia odrzuconego w warstwie tekstowej PDF ----
#
# Pominiety (skip), nie fikcyjny - patrz docstring modulu.


def test_pdf_text_layer_carries_no_forbidden_designation(tmp_path):
    report_pdf = pytest.importorskip("wayside.report_pdf")
    pypdf = pytest.importorskip("pypdf")

    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    result = _analyze_or_skip(fixture, tmp_path)

    pdf_bytes = report_pdf.render_pdf(
        result.analysis, generated_at=GENERATED_AT, warnings=result.warnings
    )
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert FORBIDDEN_DESIGNATION not in text, (
        "Warstwa tekstowa pliku PDF niesie oznaczenie odrzucone w rekordzie "
        f"decyzji {DECISION_RECORD_PATH}."
    )


# --- Test piaty: kazdy wpis katalogu norm o sygnaturze specyfikacji -------
# --- technicznej niesie edycje oczekiwana -----------------------------------


def test_every_railway_catalog_entry_has_expected_edition():
    catalog = mapper.load_catalog()
    railway_entries = {
        key: entry
        for key, entry in catalog.items()
        if key[0].startswith(RAILWAY_STANDARD_PREFIX)
    }
    assert railway_entries, (
        f"Zaden wpis katalogu norm nie zaczyna sie od {RAILWAY_STANDARD_PREFIX!r} "
        "- bramka nie ma czego pilnowac."
    )
    for key, entry in railway_entries.items():
        assert entry["edition"] == EXPECTED_RAILWAY_EDITION, (
            f"Wpis {key} niesie edycje {entry['edition']!r}, oczekiwano "
            f"{EXPECTED_RAILWAY_EDITION!r}."
        )


# --- Test szosty: katalog rekordow decyzji bez kolizji prefiksu numeru -----


def test_decision_records_have_no_colliding_numeric_prefix():
    names = [p.name for p in (REPO_ROOT / "docs" / "decisions").glob("*.md")]
    prefixes = [re.match(r"^(\d+)", name).group(1) for name in names]
    assert len(set(prefixes)) == len(prefixes), (
        f"Kolizja prefiksu numeru w katalogu rekordow decyzji: {sorted(names)}"
    )


# --- Grupa README (Task 3): sekcja o stanie weryfikacji powolan na normy ---
#
# Sekcja NIE jest PUB-03 (Intended Use, Faza 5) - jest wlasna, mala sekcja
# tej fazy. Wyodrebniona po naglowku, wzorem
# tests/test_report_forbidden_phrases.py::_section_body, zeby test sprawdzal
# obecnosc lancuchow W JEJ CIELE, nie w calym README - test nad calym plikiem
# przeszedlby takze wtedy, gdyby te lancuchy stanely w innej sekcji.

README_PATH = REPO_ROOT / "README.md"
README_SECTION_HEADER = "## Stan weryfikacji powolan na normy"
VERIFICATION_MARKER_STRING = "verified: no"

_HEADER_LINE_RE = re.compile(r"^## .+$", re.MULTILINE)


def _readme_section_body(header: str) -> str:
    text = README_PATH.read_text(encoding="utf-8")
    headers = list(_HEADER_LINE_RE.finditer(text))
    for index, match in enumerate(headers):
        if match.group(0).strip() != header:
            continue
        start = match.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        return text[start:end]
    raise AssertionError(f"README nie ma sekcji '{header}'")


def test_readme_has_standard_verification_section_header():
    text = README_PATH.read_text(encoding="utf-8")
    assert README_SECTION_HEADER in text


def test_readme_verification_section_carries_verification_marker():
    body = _readme_section_body(README_SECTION_HEADER)
    assert VERIFICATION_MARKER_STRING in body, (
        "Sekcja README o stanie weryfikacji nie niesie lancucha znacznika "
        f"weryfikacji {VERIFICATION_MARKER_STRING!r} w dokladnej postaci "
        "z pliku katalogu."
    )


def test_readme_verification_section_links_both_decision_records():
    body = _readme_section_body(README_SECTION_HEADER)
    assert "0004-sygnatura-clc-ts-50701.md" in body
    assert "0006-weryfikacja-powolan-wobec-egzemplarza-normy.md" in body
