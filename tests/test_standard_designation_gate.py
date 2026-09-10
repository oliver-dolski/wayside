"""Bramka maszynowa rekordu decyzji `0004` (sygnatura CLC/TS 50701) i rekordu
`0006` (weryfikacja powolan wobec egzemplarza normy).

Rekord decyzji `0004`, sekcja "Sposob egzekwowania", zapisuje wprost: bramka
maszynowa dla tego rozstrzygniecia NIE ISTNIEJE w chwili jego zapisu i
powstaje razem z planem tej fazy. Ten plik jest ta bramka.

Wartosc `FORBIDDEN_DESIGNATION` jest WZIETA z sekcji "Odrzucone alternatywy"
rekordu `0004`, nie wpisana z pamieci - rekord jest zrodlem prawdy dla tego,
co bramka ma zakazac.

**Bramka obejmuje takze pliki binarne sledzone przez gita w zakresie skanu**
(plan `04-07`, zamkniecie WR-03 z `04-VERIFICATION.md`). Skan tekstowy
`_scan_tree_for_designation` pomija kazdy plik nieodczytywalny jako UTF-8 -
dokladnie ta droga, przez ktora `examples/4sics/report.pdf` wypadal z zasiegu
bramki mimo bycia sledzonym przez gita. `BINARY_SCAN_TARGETS` deklaruje po
nazwie strategie przeszukania kazdego takiego pliku, a test kompletnosci
zaczerwienia sie na kazdym pliku binarnym niezadeklarowanym. Plan `04-03`
(eksport do PDF) wyladowal 2026-09-05, wiec `wayside.report_pdf` i `pypdf` sa
dzis zaleznosciami tego drzewa - import obu jest bezwarunkowy, nie ma juz w
tym module zadnej sciezki cichego pominiecia.
"""

from __future__ import annotations

import io
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pypdf
import pytest

from wayside import report_pdf
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

DECISION_RECORD_PATH = (
    REPO_ROOT / "docs" / "decisions" / "0004-clc-ts-50701-designation.md"
)

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


def test_pdf_text_layer_carries_no_forbidden_designation(tmp_path):
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
README_SECTION_HEADER = "## Citation verification status"
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
    assert "0004-clc-ts-50701-designation.md" in body
    assert "0006-verification-of-citations-against-a-copy-of-the-standard.md" in body


# --- Grupa nowa (plan 04-07): bramka obejmuje pliki binarne sledzone przez -
# --- gita w zakresie skanu, WR-03 z 04-VERIFICATION.md ----------------------
#
# Sledzony plik binarny w zakresie skanu jest albo przeszukiwalny po warstwie
# tekstowej, albo po surowych bajtach - nie ma trzeciej mozliwosci ani listy
# wykluczen (zalozenie Z-79). Lista wykluczen jest dokladnie tym mechanizmem,
# przez ktory `examples/4sics/report.pdf` wypadl z zasiegu tej bramki.
BINARY_SCAN_TARGETS: dict[str, str] = {
    "examples/4sics/report.pdf": "pdf-text",
    "src/wayside/assets/fonts/DejaVuSans.ttf": "raw-bytes",
    "src/wayside/assets/fonts/DejaVuSans-Bold.ttf": "raw-bytes",
}


def _tracked_files_in_scope() -> list[Path]:
    """Pliki SLEDZONE przez gita w `SCAN_SCOPE`, nie pliki lezace na dysku
    (zalozenie Z-78): drzewo robocze niesie katalogi skompilowanego kodu
    posredniego, ktorych w repozytorium nie ma, a pytanie rekordu decyzji
    `0004` dotyczy zawartosci repozytorium. Niezerowy kod wyjscia gita konczy
    ten test porazka niosaca wyjscie bledu, nigdy pominieciem - wzorzec
    `tests/test_example_report.py::_git_tracked_files`."""
    result = subprocess.run(
        ["git", "ls-files", "--", *SCAN_SCOPE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"git ls-files zakonczyl sie kodem {result.returncode}: {result.stderr}"
    )
    return [REPO_ROOT / line for line in result.stdout.splitlines() if line]


def _undecodable_tracked_files() -> list[Path]:
    """Z plikow sledzonych w zakresie skanu, dokladnie te, ktorych proba
    odczytu jako tekst UTF-8 konczy sie bledem dekodowania - czyli dokladnie
    ten zbior, ktory `_scan_tree_for_designation` dzis po cichu pomija."""
    undecodable: list[Path] = []
    for path in _tracked_files_in_scope():
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            undecodable.append(path)
    return undecodable


def test_binary_scan_targets_declare_every_undecodable_tracked_file():
    undecodable = {
        p.relative_to(REPO_ROOT).as_posix() for p in _undecodable_tracked_files()
    }
    declared = set(BINARY_SCAN_TARGETS)

    undeclared = sorted(undecodable - declared)
    orphaned = sorted(declared - undecodable)

    assert not undeclared and not orphaned, (
        "Niezadeklarowane pliki binarne sledzone przez gita: "
        f"{undeclared}; sciezki zadeklarowane bez odpowiadajacego pliku: "
        f"{orphaned}"
    )


_FORBIDDEN_PATTERN = re.compile(re.escape(FORBIDDEN_DESIGNATION), re.IGNORECASE)


@pytest.mark.parametrize(
    ("relative_path", "strategy"),
    sorted(BINARY_SCAN_TARGETS.items()),
    ids=list(sorted(BINARY_SCAN_TARGETS)),
)
def test_declared_binaries_carry_no_forbidden_designation(relative_path, strategy):
    target = REPO_ROOT / relative_path
    assert target.is_file(), f"Zadeklarowany plik nie istnieje: {relative_path}"

    if strategy == "pdf-text":
        reader = pypdf.PdfReader(str(target))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        assert not _FORBIDDEN_PATTERN.search(text), (
            f"{relative_path}: warstwa tekstowa niesie oznaczenie odrzucone "
            f"(strategia {strategy!r})."
        )
    elif strategy == "raw-bytes":
        # Dwa kodowania: ASCII i UTF-16BE - tablica nazw pliku czcionki
        # (tabela `name` formatu TrueType/OpenType) trzyma lancuchy w
        # UTF-16BE na platformie Microsoft.
        data = target.read_bytes()
        ascii_needle = FORBIDDEN_DESIGNATION.encode("ascii")
        utf16be_needle = FORBIDDEN_DESIGNATION.encode("utf-16-be")
        assert ascii_needle not in data, (
            f"{relative_path}: bajty ASCII niosa oznaczenie odrzucone "
            f"(strategia {strategy!r})."
        )
        assert utf16be_needle not in data, (
            f"{relative_path}: bajty UTF-16BE niosa oznaczenie odrzucone "
            f"(strategia {strategy!r})."
        )
    else:  # pragma: no cover - zabezpieczenie przed trzecia strategia
        raise AssertionError(f"Nieznana strategia przeszukania: {strategy!r}")
