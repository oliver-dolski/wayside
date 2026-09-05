"""Bramka maszynowa REPORT-05: przykladowy raport wygenerowany z podzbioru
zbioru publicznego 4SICS (rekord decyzji `0005`).

Podzial, na ktorym stoi caly ten plik: WSZYSTKIE testy PONIZEJ grupy
odtwarzalnosci chodza bez dostepu do sieci i bez pobranego zbioru - sprawdzaja
artefakty juz lezace w repozytorium (`examples/4sics/*`) i ksztalt wpisu
manifestu. Jeden test, ten o odtwarzalnosci (grupa osma), wymaga pliku
podzbioru na maszynie i jest pomijany z jawnym powodem, gdy go nie ma. Bez
tego podzialu caly ten plik bylby pomijany na czystym klonie i bramka
REPORT-05 nie istnialaby w praktyce.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "examples" / "4sics"
ANALYSIS_PATH = EXAMPLE_DIR / "analysis.json"
REPORT_MD_PATH = EXAMPLE_DIR / "report.md"
REPORT_PDF_PATH = EXAMPLE_DIR / "report.pdf"
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "pcap" / "manifest.yaml"

# Stale skryptu pobierajacego i skryptu generujacego zaimportowane, nie
# powielone - dwie kopie tej samej nazwy/wartosci rozjadaby sie przy
# pierwszej korekcie (dokladnie tak jak tests/test_standards_catalog.py
# importuje bramke poufnosci ze scripts/).
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import fetch_4sics_sample as fetch_sample  # noqa: E402
import gen_example_report as gen_report  # noqa: E402

# Funkcje wyciagajace warstwe tekstowa PDF i wyrazenie regularne wyciagajace
# identyfikatory checkow sa juz funkcjami modulowymi w tests/test_report_pdf.py
# - zaimportowane stad, nie wydzielone drugi raz (plan Task 3, 04-06-PLAN.md).
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import test_report_pdf as pdf_test_helpers  # noqa: E402

REQUIRED_EXTERNAL_DATASET_FIELDS: tuple[str, ...] = (
    "name",
    "page_url",
    "url",
    "filename",
    "sha256",
    "slice_filename",
    "slice_sha256",
    "slice_packet_count",
    "source",
    "license",
    "attribution",
    "description",
    "fetch_script",
)


def _load_manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def _external_dataset_entry() -> dict:
    manifest = _load_manifest()
    entries = manifest["external_datasets"]
    assert len(entries) == 1, f"Oczekiwano dokladnie jednego wpisu, znaleziono {len(entries)}"
    return entries[0]


def _git_tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


# --- Grupa pierwsza: istnienie i ksztalt trzech artefaktow -------------------


def test_three_artifacts_exist_and_have_nonzero_length():
    for path in (ANALYSIS_PATH, REPORT_MD_PATH, REPORT_PDF_PATH):
        assert path.is_file(), f"Artefakt nie istnieje: {path}"
        assert path.stat().st_size > 0, f"Artefakt ma zerowa dlugosc: {path}"


def test_report_pdf_has_valid_format_signature():
    assert REPORT_PDF_PATH.read_bytes()[:5] == pdf_test_helpers.PDF_SIGNATURE


def test_analysis_json_has_at_least_one_finding():
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    assert len(analysis["findings"]) >= 1


# --- Grupa druga: parytet trzech artefaktow ----------------------------------


def test_check_id_set_is_identical_across_three_artifacts():
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    ids_from_model = {finding["check_id"] for finding in analysis["findings"]}

    report_text = REPORT_MD_PATH.read_text(encoding="utf-8")
    ids_from_markdown = set(pdf_test_helpers._check_ids_in_text(report_text))

    pdf_text = pdf_test_helpers._extract_text(REPORT_PDF_PATH.read_bytes())
    ids_from_pdf = set(pdf_test_helpers._check_ids_in_text(pdf_text))

    assert ids_from_model == ids_from_markdown == ids_from_pdf


# --- Grupa trzecia: warstwa normatywna przykladu (powtorzenie bramki --------
# --- STD-03/STD-05 nad artefaktem lezacym w repozytorium, nie wygenerowanym -
# --- w trakcie testu) --------------------------------------------------------


def _example_findings() -> list[dict]:
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    return analysis["findings"]


def test_every_finding_has_nonempty_standard_refs():
    for finding in _example_findings():
        assert finding["standard_refs"], (
            f"Finding {finding['check_id']} nie niesie ani jednego powolania."
        )


def test_every_finding_has_iec_62443_3_3_reference():
    for finding in _example_findings():
        standards = {ref["standard"] for ref in finding["standard_refs"]}
        assert "IEC-62443-3-3" in standards, (
            f"Finding {finding['check_id']} nie niesie powolania na IEC-62443-3-3: {standards}"
        )


def test_every_reference_has_nonempty_edition():
    for finding in _example_findings():
        for ref in finding["standard_refs"]:
            assert ref["edition"], f"Powolanie findingu {finding['check_id']} bez edycji."


# --- Grupa czwarta: ksztalt wpisu zbioru zewnetrznego ------------------------


def test_external_datasets_block_has_exactly_one_entry():
    manifest = _load_manifest()
    assert len(manifest["external_datasets"]) == 1


def test_external_dataset_entry_has_required_nonempty_fields():
    entry = _external_dataset_entry()
    for field in REQUIRED_EXTERNAL_DATASET_FIELDS:
        assert entry.get(field), f"Pole '{field}' puste albo brakujace we wpisie zbioru zewnetrznego"


def test_external_dataset_in_repo_is_false():
    entry = _external_dataset_entry()
    assert entry["in_repo"] is False


def test_external_dataset_fetch_script_points_to_existing_file():
    entry = _external_dataset_entry()
    assert (REPO_ROOT / entry["fetch_script"]).is_file()


# --- Grupa piata: atrybucja licencyjna (bramka warunku licencyjnego, nie ----
# --- kontrola redakcyjna) ----------------------------------------------------


def test_attribution_string_present_in_both_readmes():
    entry = _external_dataset_entry()
    attribution = entry["attribution"].strip()
    example_readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    main_readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    # Manifest niesie tresc jako blok zlozony (`>-`), README powtarza ja z
    # dowolnym zawijaniem bialych znakow - porownanie idzie po zwinieciu
    # kazdej sekwencji bialych znakow do pojedynczej spacji, jedno zrodlo
    # prawdy (pole manifestu), nie literal powielony w tym tescie.
    def _collapse_whitespace(text: str) -> str:
        return " ".join(text.split())

    collapsed_attribution = _collapse_whitespace(attribution)
    assert collapsed_attribution in _collapse_whitespace(example_readme)
    assert collapsed_attribution in _collapse_whitespace(main_readme)


def test_page_url_present_in_both_readmes():
    entry = _external_dataset_entry()
    page_url = entry["page_url"]
    example_readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    main_readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert page_url in example_readme
    assert page_url in main_readme


def test_domain_boundary_sentence_present_in_example_readme():
    # Pole opisu wpisu manifestu nazywa granice dziedzinowa wprost: ruch NIE
    # pochodzi z instalacji kolejowej. Wystarczy obecnosc tego lancucha w
    # pliku README katalogu przykladu, odczytana z pola opisu - nie literal
    # powielony w tym tescie. Porownanie idzie po zwinieciu bialych znakow
    # (spacji i konca linii) do pojedynczej spacji - markdown zawija dlugie
    # zdania na wiele linii, a to jest kwestia zapisu, nie tresci.
    entry = _external_dataset_entry()
    description = entry["description"]
    marker = "NIE z instalacji kolejowej"
    assert marker in description, "Pole opisu manifestu nie niesie zdania o granicy dziedzinowej"
    example_readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    assert marker in " ".join(example_readme.split())


# --- Grupa szosta: brak zrzutu w drzewie sledzonym, katalog pobrania -------
# --- ignorowany --------------------------------------------------------------


def test_no_pcap_dump_file_tracked_outside_fixture_directory():
    tracked = _git_tracked_files()
    hits = [
        path
        for path in tracked
        if (path.endswith(".pcap") or path.endswith(".pcapng"))
        and not path.startswith("tests/fixtures/pcap/")
    ]
    assert hits == [], f"Plik zrzutu sledzony poza katalogiem fixture'ow: {hits}"


def test_dataset_download_directory_is_gitignored():
    # Ukosnik koncowy jest wymagany: bez niego `git check-ignore` na
    # sciezce, ktora nie istnieje jeszcze na dysku (czysty klon, przed
    # pierwszym uruchomieniem skryptu pobierajacego), nie wie, czy sciezka
    # jest katalogiem, i zwraca kod niezerowy niezaleznie od reguly w
    # .gitignore - zmierzone 2026-09-06, ten test ma dzialac takze na
    # czystym klonie, nie tylko po pobraniu zbioru.
    result = subprocess.run(
        ["git", "check-ignore", "-q", "datasets/"],
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, "Katalog 'datasets' nie jest ignorowany przez gita"


# --- Grupa siodma: reguly atrybutow gita dla trzech artefaktow --------------


def _git_check_attr(attribute: str, path: str) -> str:
    result = subprocess.run(
        ["git", "check-attr", attribute, "--", path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    # Format wyjscia: "sciezka: atrybut: wartosc"
    return result.stdout.strip().rsplit(":", 1)[-1].strip()


def test_report_md_and_analysis_json_have_text_normalization_disabled():
    for rel_path in ("examples/4sics/report.md", "examples/4sics/analysis.json"):
        value = _git_check_attr("text", rel_path)
        assert value == "unset", f"{rel_path}: atrybut text = {value!r}, oczekiwano 'unset'"


def test_report_pdf_has_binary_attribute_set():
    value = _git_check_attr("binary", "examples/4sics/report.pdf")
    assert value == "set", f"report.pdf: atrybut binary = {value!r}, oczekiwano 'set'"


# --- Grupa osma: odtwarzalnosc bajtowa, pomijana warunkowo -------------------


def test_example_artifacts_are_byte_reproducible_from_slice(tmp_path):
    slice_path = fetch_sample.DATASET_DIR / fetch_sample.SLICE_FILENAME
    if not slice_path.is_file():
        pytest.skip(
            f"Plik podzbioru {slice_path} nie lezy na maszynie - zbuduj go "
            "poleceniem: uv run python scripts/fetch_4sics_sample.py"
        )

    analysis_path, report_path, pdf_path = gen_report.generate(slice_path, tmp_path)

    assert analysis_path.read_bytes() == ANALYSIS_PATH.read_bytes()
    assert report_path.read_bytes() == REPORT_MD_PATH.read_bytes()
    # Kontrakt PDF: pomiar determinizmu bajtowego z 04-03-SUMMARY.md wypadl
    # POZYTYWNIE (dwa fixture'y, cztery wartosci PYTHONHASHSEED) - kryterium
    # 5 fazy nie wymaga zwezenia dla PDF, wiec porownanie idzie bajtowo tak
    # samo jak dla dwoch artefaktow tekstowych.
    assert pdf_path.read_bytes() == REPORT_PDF_PATH.read_bytes()


# --- AST: brak zaleznosci sieciowej w tym pliku testowym --------------------


def test_this_test_module_imports_no_network_library():
    import ast

    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    modules += [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    bad = [
        name
        for name in modules
        if name.startswith("urllib") or name.startswith("http") or name.startswith("requests")
    ]
    assert bad == [], bad
