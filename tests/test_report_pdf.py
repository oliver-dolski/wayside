"""Bramka maszynowa REPORT-03: eksport raportu do PDF (plan 04-03).

Grupa pierwsza (jednostkowa) buduje model recznie, wzorem
`tests/test_report_render.py::_finding` - `render_pdf` jest funkcja nad
slownikiem, dowod przez caly potok (plik pcap -> CLI -> report.pdf) stoi w
grupie czwartej (integracyjnej) nizej. Rationale/paraphrase testowego
findingu niesie pangram "Zazolc gesla jazn" - dokladnie dziewiec polskich
znakow diakrytycznych naraz (ą c ę l n o s z z), zeby test kodowania mial
zrodlo, na ktorym stoi, niezalezne od tresci prawdziwego katalogu norm.

Grupa druga (brak pliku fontu), grupa trzecia (brak odczytu zegara, przez
drzewo skladni - ta sama dyscyplina co `tests/test_no_external_dissector.py`,
bo docstring modulu OPISUJE brak odczytu zegara i naiwny skan tekstowy
zlapalby wlasna dokumentacje), grupa czwarta (integracyjna w podprocesie,
wzorem `tests/test_determinism.py::_run_analyze`) i grupa piata (brak nowej
zaleznosci na sciezce domyslnej, wzorem
`tests/test_scapy_cache_isolation.py`) domykaja Task 3. Parytet findingow
miedzy PDF i markdown oraz pomiar determinizmu bajtowego (Task 4) stoja w
dalszej czesci tego pliku.
"""

from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pypdf import PdfReader

from wayside import report_pdf
from wayside.model import write_atomic_bytes
from wayside.report import SECTIONS, render_markdown
from wayside.report_pdf import PdfRenderError, render_pdf

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
FIXTURE_WRITE = FIXTURE_DIR / "modbus_write_single_register.pcap"
FIXTURE_EMPTY = FIXTURE_DIR / "empty_valid_header.pcap"

GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Zestaw kanoniczny wszystkich dziewieciu polskich znakow diakrytycznych -
# zrodlo prawdy szersze niz podzbior omiu uzyty przez
# tests/test_determinism.py::_POLISH_DIACRITICS (ten plik potrzebuje
# kompletu, nie probki).
POLISH_DIACRITICS: tuple[str, ...] = ("ą", "ć", "ę", "ł", "ń", "ó", "ś", "ź", "ż")

# Pangram niosacy komplet dziewieciu znakow w jednym, krotkim zdaniu -
# powszechnie znany polski odpowiednik "the quick brown fox".
PANGRAM = "Zażółć gęślą jaźń"

PDF_SIGNATURE = b"%PDF-"


def _finding(**overrides) -> dict:
    """Buduje jeden finding w ksztalcie slownika, wzorem
    `tests/test_report_render.py::_finding`. `rationale` niesie `PANGRAM`,
    zeby test kodowania mial zrodlo niezalezne od tresci prawdziwego
    katalogu norm."""
    base = {
        "check_id": "modbus-unauthenticated-write",
        "title": "Operacja zapisu do sterownika przez Modbus/TCP bez uwierzytelnienia",
        "severity": "high",
        "risk": "wysokie",
        "rationale": f"Wlasna analiza zaobserwowanego ruchu. {PANGRAM}.",
        "standard_refs": [
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "paraphrase": "Parafraza punktu normy, nie cytat oryginalu.",
                "verified": False,
                "verification_note": "Numeracja prowizoryczna, czeka na zestawienie z legalnym egzemplarzem normy.",
            }
        ],
        "evidence": {"packet_number": 1, "session_id": 0},
        "remediation": "Ograniczyc mozliwosc wysylania kodow zapisu do znanych hostow inzynierskich.",
    }
    base.update(overrides)
    return base


def _analysis(*, findings: list[dict] | None = None) -> dict:
    return {
        "capture": {"filename": "test.pcap", "packet_count": 2},
        "findings": findings if findings is not None else [],
    }


def _extract_text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# --- Grupa pierwsza: unit nad modelem budowanym recznie ---------------------


def test_render_pdf_returns_bytes_with_pdf_signature():
    pdf_bytes = render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes[:5] == PDF_SIGNATURE


def test_render_pdf_without_findings_is_nonzero_length_with_same_sentence_as_markdown():
    analysis = _analysis(findings=[])

    pdf_bytes = render_pdf(analysis, generated_at=GENERATED_AT)
    assert len(pdf_bytes) > 0

    pdf_text = _extract_text(pdf_bytes)
    markdown_text = render_markdown(analysis, generated_at=GENERATED_AT)

    # Zdanie o braku findingow (sekcja Streszczenie) jest DOKLADNIE tym samym
    # lancuchem w obu formatach - krawedz empty z must_haves planu.
    empty_sentence = (
        "Analiza zrzutu `test.pcap` nie wykazala zadnego findingu w tym przebiegu."
    )
    assert empty_sentence in markdown_text
    assert empty_sentence in pdf_text
    assert "Brak findingow w tym przebiegu." in pdf_text


def test_render_pdf_with_one_finding_carries_expected_fields():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    assert "modbus-unauthenticated-write" in pdf_text
    assert "high" in pdf_text
    assert "wysokie" in pdf_text
    assert "pakiet nr 1" in pdf_text
    assert "sesja nr 0" in pdf_text
    assert "SR 1.1" in pdf_text
    assert "Human user identification and authentication" in pdf_text
    assert "Parafraza punktu normy" in pdf_text
    assert "Ograniczyc mozliwosc wysylania kodow zapisu" in pdf_text


def test_render_pdf_unverified_reference_carries_same_status_text_as_markdown():
    analysis = _analysis(findings=[_finding()])

    pdf_text = _extract_text(render_pdf(analysis, generated_at=GENERATED_AT))
    markdown_text = render_markdown(analysis, generated_at=GENERATED_AT)

    assert "PROWIZORYCZNE" in markdown_text and "NIEZWERYFIKOWANE" in markdown_text
    assert "PROWIZORYCZNE" in pdf_text
    assert "NIEZWERYFIKOWANE" in pdf_text
    assert "Numeracja prowizoryczna, czeka na zestawienie" in pdf_text


def test_render_pdf_verified_reference_carries_verified_status_text():
    verified_finding = _finding(
        standard_refs=[
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "paraphrase": "Parafraza punktu normy, nie cytat oryginalu.",
                "verified": True,
                "verification_note": "",
            }
        ]
    )

    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[verified_finding]), generated_at=GENERATED_AT)
    )

    assert "zweryfikowane" in pdf_text
    assert "PROWIZORYCZNE" not in pdf_text


def test_text_layer_carries_all_nine_polish_diacritics_as_single_codepoints():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    for letter in POLISH_DIACRITICS:
        assert letter in pdf_text, f"Znak {letter!r} nieobecny w warstwie tekstowej PDF"


def test_text_layer_diacritics_are_never_decomposed_into_base_plus_combining():
    """Krawedz encoding: kazdy z dziewieciu znakow ma byc pojedynczym punktem
    kodowym w postaci znormalizowanej ZLOZONEJ (NFC), nigdy para znaku
    podstawowego i znaku laczacego (NFD) - porownanie tekstu przed i po
    normalizacji do NFC musi dac ten sam tekst w zakresie tych znakow."""
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    # Test na calym tekscie: gdyby jakikolwiek znak byl rozlozony (NFD),
    # normalizacja do NFC zmienilaby tekst - rownosc dowodzi braku
    # rozlozenia GDZIEKOLWIEK, nie tylko w tych dziewieciu znakach.
    assert unicodedata.normalize("NFC", pdf_text) == pdf_text

    # Sprawdzenie punktowe ma sens wylacznie dla znakow z WLASCIWA
    # dekompozycja kanoniczna w Unicode (baza + znak laczacy) - "l"/"L"
    # (lslash) nie ma zadnej dekompozycji kanonicznej (przekreslenie nie
    # jest znakiem diakrytycznym w sensie Unicode), wiec
    # `unicodedata.normalize("NFD", "l") == "l"` i test punktowy dla niego
    # bylby tautologia (zawsze prawdziwy, gdy sam znak jest obecny).
    for letter in POLISH_DIACRITICS:
        decomposed = unicodedata.normalize("NFD", letter)
        if decomposed == letter:
            continue
        assert decomposed not in pdf_text, (
            f"Znak {letter!r} wystepuje w postaci rozlozonej (NFD) w warstwie "
            "tekstowej PDF"
        )


def test_text_layer_carries_eight_section_headers_in_order():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    positions = [pdf_text.find(section) for section in SECTIONS]
    assert all(position != -1 for position in positions), (
        f"Nie wszystkie naglowki sekcji obecne: {list(zip(SECTIONS, positions))}"
    )
    assert positions == sorted(positions)


def test_render_pdf_signature_is_identical_to_render_markdown():
    import inspect

    markdown_params = list(inspect.signature(render_markdown).parameters)
    pdf_params = list(inspect.signature(render_pdf).parameters)

    assert markdown_params == pdf_params


# --- Grupa druga: brak pliku fontu ------------------------------------------


def test_missing_font_file_raises_pdf_render_error_with_expected_path(monkeypatch, tmp_path):
    missing_path = tmp_path / "no-such-font.ttf"
    monkeypatch.setattr(report_pdf, "FONT_REGULAR_PATH", missing_path)

    with pytest.raises(PdfRenderError) as excinfo:
        render_pdf(_analysis(findings=[]), generated_at=GENERATED_AT)

    assert str(missing_path) in str(excinfo.value)


def test_missing_bold_font_file_raises_pdf_render_error_with_expected_path(monkeypatch, tmp_path):
    missing_path = tmp_path / "no-such-bold-font.ttf"
    monkeypatch.setattr(report_pdf, "FONT_BOLD_PATH", missing_path)

    with pytest.raises(PdfRenderError) as excinfo:
        render_pdf(_analysis(findings=[]), generated_at=GENERATED_AT)

    assert str(missing_path) in str(excinfo.value)


# --- Grupa trzecia: brak odczytu zegara, przez drzewo skladni --------------


_CLOCK_ATTRIBUTES = {"now", "utcnow", "time", "today"}


def test_module_source_never_calls_a_clock_function():
    """Ten sam wzorzec co `tests/test_no_external_dissector.py::scan_tree`:
    sprawdzenie przez drzewo skladni, nie przez wyszukiwanie tekstowe -
    docstring modulu OPISUJE brak odczytu zegara, wiec naiwny skan
    tekstowy zlapalby wlasna dokumentacje jako falszywy alarm."""
    source = Path(report_pdf.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offending_calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CLOCK_ATTRIBUTES
    ]

    assert offending_calls == []


def test_module_source_never_imports_re():
    source = Path(report_pdf.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported_modules = [
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ] + [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]

    assert "re" not in imported_modules


# --- write_atomic_bytes: zapis bez zmiany, brak pliku czesciowego ----------


def test_write_atomic_bytes_roundtrip(tmp_path):
    target = tmp_path / "out.pdf"
    payload = b"%PDF-1.4\n...bajty...\n"

    write_atomic_bytes(target, payload)

    assert target.read_bytes() == payload


def test_write_atomic_bytes_interrupted_write_leaves_no_target_file(tmp_path, monkeypatch):
    target = tmp_path / "out.pdf"

    def _boom(*args, **kwargs):
        raise RuntimeError("przerwanie symulowane w tescie")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(RuntimeError):
        write_atomic_bytes(target, b"cokolwiek")

    assert not target.exists()
    # Zaden plik tymczasowy nie zostaje w katalogu docelowym.
    assert list(tmp_path.iterdir()) == []


# --- Grupa czwarta: integracyjna w podprocesie ------------------------------


def _run_analyze(
    fixture: Path, out_dir: Path, *, pdf: bool
) -> subprocess.CompletedProcess:
    args = [
        sys.executable,
        "-m",
        "wayside.cli",
        "analyze",
        str(fixture),
        "--out-dir",
        str(out_dir),
    ]
    if pdf:
        args.append("--pdf")
    return subprocess.run(
        args, cwd=str(REPO_ROOT), capture_output=True, text=True
    )


def test_analyze_without_pdf_flag_writes_two_artifacts_and_no_pdf(tmp_path):
    result = _run_analyze(FIXTURE_WRITE, tmp_path, pdf=False)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "analysis.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert not (tmp_path / "report.pdf").exists()


def test_analyze_with_pdf_flag_writes_three_artifacts_and_exits_zero(tmp_path):
    result = _run_analyze(FIXTURE_WRITE, tmp_path, pdf=True)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "analysis.json").is_file()
    assert (tmp_path / "report.md").is_file()
    pdf_path = tmp_path / "report.pdf"
    assert pdf_path.is_file()
    assert pdf_path.read_bytes()[:5] == PDF_SIGNATURE
    assert str(pdf_path) in result.stdout


def test_analyze_with_pdf_flag_on_empty_fixture_exits_zero_with_nonzero_pdf(tmp_path):
    result = _run_analyze(FIXTURE_EMPTY, tmp_path, pdf=True)

    assert result.returncode == 0, result.stderr
    pdf_path = tmp_path / "report.pdf"
    assert pdf_path.is_file()
    assert len(pdf_path.read_bytes()) > 0


# --- Grupa piata: brak nowej zaleznosci na sciezce domyslnej ---------------


_PROBE = (
    "import contextlib\n"
    "import json\n"
    "import sys\n"
    "sys.argv = ['wayside', 'analyze', sys.argv[1], '--out-dir', sys.argv[2]]\n"
    "from wayside.cli import app\n"
    "with contextlib.suppress(SystemExit):\n"
    "    app()\n"
    "print(json.dumps({'fpdf_imported': 'fpdf' in sys.modules}))\n"
)


def test_pdf_library_not_imported_by_default_analyze_run(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, str(FIXTURE_WRITE), str(tmp_path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    probe = json.loads(result.stdout.strip().splitlines()[-1])

    assert probe["fpdf_imported"] is False
