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
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pypdf import PdfReader

from wayside import report_pdf
from wayside.model import dump_deterministic, write_atomic_bytes
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze as pipeline_analyze
from wayside.report import (
    CITATION_SCOPE_LABEL,
    SECTIONS,
    citation_line,
    citation_scope_line,
    render_markdown,
)
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
                "clause_title_source": "egzemplarz",
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
        "Analiza zrzutu `test.pcap` nie wykazała żadnego findingu w tym przebiegu."
    )
    assert empty_sentence in markdown_text
    assert empty_sentence in pdf_text
    assert "Brak findingów w tym przebiegu." in pdf_text


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
                "clause_title_source": "egzemplarz",
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


def test_pdf_finding_block_uses_shared_citation_functions_not_own_copy():
    """T-4-40: rendering pdf i markdown przez te same dwie funkcje czyste -
    dowod na drzewie skladni, nie na zgadywaniu (G-04-3c)."""
    import inspect

    src = inspect.getsource(report_pdf)
    assert "citation_line" in src
    assert "citation_scope_line" in src


def test_pdf_wlasny_provenance_finding_carries_scope_label_not_title_inline():
    finding = _finding(
        standard_refs=[
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Tytul opisu wlasnego",
                "clause_title_source": "wlasny",
                "paraphrase": "Parafraza punktu normy, nie cytat oryginalu.",
                "verified": False,
                "verification_note": "Numeracja prowizoryczna.",
            }
        ]
    )

    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[finding]), generated_at=GENERATED_AT)
    )

    assert CITATION_SCOPE_LABEL in pdf_text
    for line in pdf_text.splitlines():
        if "SR 1.1" in line:
            assert "Tytul opisu wlasnego" not in line


def test_citation_line_and_scope_line_match_report_module_contract():
    """Sanity: `report_pdf` uzywa DOKLADNIE tych samych funkcji, ktore
    importuje z `wayside.report` - zaimportowana funkcja i wywolanie w tym
    module daja identyczny wynik."""
    ref_egzemplarz = {
        "standard": "IEC-62443-3-3",
        "clause": "SR 1.1",
        "clause_title": "Tytul",
        "clause_title_source": "egzemplarz",
    }
    ref_wlasny = dict(ref_egzemplarz, clause_title_source="wlasny")

    assert "Tytul" in citation_line(ref_egzemplarz)
    assert "Tytul" not in citation_line(ref_wlasny)
    assert citation_scope_line(ref_egzemplarz) is None
    assert citation_scope_line(ref_wlasny) is not None


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


# =============================================================================
# Task 4: parytet findingow miedzy PDF, markdown i analysis.json, oraz
# pomiar determinizmu bajtowego PDF w dwoch osobnych podprocesach.
# =============================================================================


def _analyzable_fixtures() -> list[Path]:
    """Kazdy fixture, ktory konczy analize bez wyjatku. Wzorzec
    `tests/test_report_forbidden_phrases.py::_analyzable_fixtures` -
    lista budowana GLOBEM, nie recznym wyliczeniem nazw, zeby fixture
    dodany w przyszlosci trafil do bramki bez zmiany tego pliku."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return pipeline_analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} nie produkuje artefaktow (brama D-01)")


# Etykieta identyfikatora checka jest ZAKOTWICZONA na tej samej fladze w obu
# formatach ("Identyfikator checka: "), z opcjonalnymi cudzyslowami wstecznymi
# (markdown niesie je, PDF nie) - jeden wzorzec dla obu wyciagniety wprost z
# TEKSTU artefaktu, nigdy z kodu renderujacego.
_CHECK_ID_PATTERN = re.compile(r"Identyfikator checka: `?([a-z0-9-]+)`?")


def _check_ids_in_text(text: str) -> list[str]:
    return _CHECK_ID_PATTERN.findall(text)


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_check_id_set_is_identical_across_pdf_markdown_and_analysis_json(
    fixture, tmp_path
):
    result = _analyze_or_skip(fixture, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    ids_from_pdf = set(_check_ids_in_text(pdf_text))
    ids_from_markdown = set(_check_ids_in_text(result.report_markdown))
    ids_from_model = {f["check_id"] for f in result.analysis["findings"]}

    # Roznica symetryczna w komunikacie asercji nazywa brakujacy finding,
    # nie tylko fakt niezgodnosci (04-03-PLAN.md, Task 4).
    assert ids_from_pdf == ids_from_markdown, (
        f"{fixture.name}: roznica PDF/markdown = "
        f"{ids_from_pdf ^ ids_from_markdown}"
    )
    assert ids_from_pdf == ids_from_model, (
        f"{fixture.name}: roznica PDF/model = {ids_from_pdf ^ ids_from_model}"
    )


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_check_id_label_count_equals_finding_count(fixture, tmp_path):
    """Rownosc zbiorow NIE wystarcza (krawedz adjacency): dwa findingi o
    identycznym identyfikatorze daja ten sam zbior przy jednym i przy dwoch
    blokach w tekscie. Liczba wystapien etykiety musi byc rowna liczbie
    findingow w modelu."""
    result = _analyze_or_skip(fixture, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    assert len(_check_ids_in_text(pdf_text)) == len(result.analysis["findings"])


def test_two_findings_with_identical_title_yield_two_separate_blocks_in_pdf():
    """Krawedz adjacency, nad modelem recznym: zaden fixture projektu nie
    daje dwoch findingow o identycznym tytule (04-03-PLAN.md, Task 4)."""
    duplicate_finding = _finding()
    analysis = _analysis(findings=[duplicate_finding, duplicate_finding])

    pdf_text = _extract_text(render_pdf(analysis, generated_at=GENERATED_AT))

    check_ids = _check_ids_in_text(pdf_text)
    assert len(check_ids) == 2
    assert check_ids == ["modbus-unauthenticated-write", "modbus-unauthenticated-write"]
    # Tytul findingu (naglowek pogrubiony) wystepuje tez dwa razy, nie raz -
    # scalenie dwoch findingow w jeden blok jest realnym trybem porazki
    # renderowania (fpdf2 nie odrzuca dwoch identycznych multi_cell).
    assert pdf_text.count(duplicate_finding["title"]) == 2


def test_check_id_first_occurrence_order_matches_model_order(tmp_path):
    """Krawedz ordering: kolejnosc pierwszych wystapien identyfikatorow w
    tekscie PDF ma byc identyczna z kolejnoscia w modelu (kolejnosc ustalona
    przez `checks.engine.run_checks` po trojce kluczy)."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    order_in_model = [f["check_id"] for f in result.analysis["findings"]]
    first_occurrences: list[str] = []
    for check_id in _check_ids_in_text(pdf_text):
        if check_id not in first_occurrences:
            first_occurrences.append(check_id)

    assert first_occurrences == order_in_model


# --- Pomiar determinizmu bajtowego PDF w dwoch osobnych podprocesach -------
#
# Zbudowana raz per test, ta sama sonda uzyta w dwoch wywolaniach subprocess -
# dwa OSOBNE procesy sa tu wymagane, nie dwa wywolania w jednym: identyfikator
# plikowy dokumentu i subsetting fontu moga byc stabilne w jednym procesie i
# rozne miedzy procesami (04-RESEARCH.md, Pitfall 8).

_DETERMINISM_PROBE = (
    "import json, sys\n"
    "from datetime import datetime, timezone\n"
    "from wayside.report_pdf import render_pdf\n"
    "analysis_path, output_path = sys.argv[1], sys.argv[2]\n"
    "with open(analysis_path, 'r', encoding='utf-8') as f:\n"
    "    analysis = json.load(f)\n"
    "generated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)\n"
    "pdf_bytes = render_pdf(analysis, generated_at=generated_at)\n"
    "with open(output_path, 'wb') as f:\n"
    "    f.write(pdf_bytes)\n"
)


def _render_pdf_via_subprocess(
    analysis_path: Path, output_path: Path, *, pythonhashseed: str
) -> str:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = pythonhashseed
    result = subprocess.run(
        [sys.executable, "-c", _DETERMINISM_PROBE, str(analysis_path), str(output_path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, (
        f"sonda determinizmu PDF nie zwrocila kodu 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    return hashlib.sha256(output_path.read_bytes()).hexdigest()


@pytest.mark.parametrize("pythonhashseed", ["0", "1337"])
def test_pdf_bytes_are_identical_across_two_subprocesses(tmp_path, pythonhashseed):
    """Dwa wywolania renderowania PDF w dwoch OSOBNYCH podprocesach, z
    identycznym modelem i identycznym znacznikiem czasu, daja bajty o tej
    samej sumie sha256 - miara empiryczna, nie zalozenie (04-RESEARCH.md,
    Pitfall 8; 04-03-PLAN.md, Task 4)."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path / "prep")
    analysis_path = tmp_path / "analysis_for_probe.json"
    analysis_path.write_text(dump_deterministic(result.analysis), encoding="utf-8")

    hash_a = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "a.pdf", pythonhashseed=pythonhashseed
    )
    hash_b = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "b.pdf", pythonhashseed=pythonhashseed
    )

    assert hash_a == hash_b


def test_pdf_bytes_are_identical_across_pythonhashseed_values(tmp_path):
    """Ten sam pomiar co wyzej, powtorzony z dwoma ROZNYMI wartosciami
    ziarna hashowania procesu - dowod, ze wynik nie jest artefaktem
    jednego, przypadkowo stabilnego ziarna."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path / "prep")
    analysis_path = tmp_path / "analysis_for_probe.json"
    analysis_path.write_text(dump_deterministic(result.analysis), encoding="utf-8")

    hash_seed_0 = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "seed_0.pdf", pythonhashseed="0"
    )
    hash_seed_1337 = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "seed_1337.pdf", pythonhashseed="1337"
    )

    assert hash_seed_0 == hash_seed_1337
