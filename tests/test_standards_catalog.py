"""Bramka katalogu norm: parafraza, brak tekstu doslownego, wpis prowizoryczny
(STD-01, STD-02).

Zaden test w tym pliku nie zawiera fragmentu tekstu normy - testy badaja
ksztalt i pola, nigdy tresc. Linia naruszajaca, potrzebna do dowiedzenia,
ze `scan_text_structural` w ogole ma zeby, jest SKLEJONA w czasie dzialania
z osobnych zmiennych (numer klauzuli, termin modalny wzięty z
`guard.NORMATIVE_MODAL_TERMS`, dopelnienie dlugosci) - zaden pojedynczy
wiersz ZRODLA tego pliku nie niesie jednoczesnie kropkowanego numeru i
modalnosci normatywnej, wiec bramka poufnosci nie zapala sie na SAMYM
PLIKU TESTOWYM i nie trzeba dopisywac go do `.confidentiality-allow`
(ten plik ostrzega, ze wpis na cala sciezke zdejmuje warstwe strukturalna
z CALEGO pliku, takze z tresci dopisanej pozniej).
"""

from __future__ import annotations

import ast
import hashlib
import json
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from wayside import cli as cli_module
from wayside import zones
from wayside.checks import engine
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import confidentiality_guard as guard  # noqa: E402

CATALOG_PATH = REPO_ROOT / "src" / "wayside" / "standards" / "iec62443-3-3" / "catalog.yaml"
STANDARDS_ROOT = REPO_ROOT / "src" / "wayside" / "standards"
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

POLISH_DIACRITICS = "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ"

DEFAULT_ENTRY: dict = {
    "standard": "TEST-STANDARD",
    "edition": "2020",
    "clause": "T 1.1",
    "clause_title": "Tytul testowy",
    "clause_title_source": "wlasny",
    "paraphrase": "Testowa parafraza, nigdy cytat normy.",
    "verified": False,
    "verification_note": "Uwaga testowa, wpis prowizoryczny.",
}


def _write_catalog(
    catalog_root: Path,
    *,
    overrides: dict | None = None,
    remove_fields: list[str] | None = None,
) -> Path:
    """Zapisuje jeden `catalog.yaml` z jednym wpisem pod `catalog_root`.
    Wydzielona wspolna logika, zeby przypadek brakujacego i pustego pola
    wolal ta sama funkcje pomocnicza, wzorzec `tests/test_fixture_manifest.py`."""
    entry = dict(DEFAULT_ENTRY)
    if overrides:
        entry.update(overrides)
    if remove_fields:
        for field in remove_fields:
            entry.pop(field, None)

    catalog_root.mkdir(parents=True, exist_ok=True)
    catalog_path = catalog_root / "catalog.yaml"
    catalog_path.write_text(
        yaml.safe_dump({"entries": [entry]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return catalog_path


# --- Warstwa strukturalna bramki poufnosci wolana na tresci katalogu -------


def test_scan_text_structural_returns_empty_list_for_catalog_content():
    text = CATALOG_PATH.read_text(encoding="utf-8")
    assert guard.scan_text_structural(text, str(CATALOG_PATH)) == []


def test_scan_text_structural_flags_composed_clause_and_modal_line():
    # Sklejone z osobnych zmiennych - patrz docstring modulu. Zaden z tych
    # przypisan nie niesie jednoczesnie numeru i modalnosci na jednej linii.
    clause_prefix = "12"
    clause_suffix = "3.4"
    clause_number = f"{clause_prefix}.{clause_suffix}"
    modal_term = guard.NORMATIVE_MODAL_TERMS[0]
    padding = "x" * guard.MIN_STRUCTURAL_FRAGMENT_LENGTH
    composed_line = clause_number + " " + modal_term + " " + padding

    violations = guard.scan_text_structural(composed_line, "composed-test-line")

    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_STRUCTURAL_CLAUSE_MODAL


# --- Ksztalt wpisu w prawdziwym katalogu ------------------------------------


def test_catalog_entries_have_required_nonempty_fields():
    catalog = mapper.load_catalog()
    assert catalog
    for entry in catalog.values():
        for field in mapper.REQUIRED_CATALOG_FIELDS:
            assert field in entry, f"Brak pola {field} w {entry}"
            if field != "verified":
                assert entry[field], f"Puste pole {field} w {entry}"


def test_catalog_entries_are_provisional_with_nonempty_verification_note():
    catalog = mapper.load_catalog()
    for entry in catalog.values():
        assert entry["verified"] is False
        assert entry.get("verification_note")


def test_catalog_edition_and_clause_are_strings_not_numbers():
    catalog = mapper.load_catalog()
    for entry in catalog.values():
        assert isinstance(entry["edition"], str)
        assert isinstance(entry["clause"], str)


# --- Kontrakt schematu na katalogu tymczasowym: pole brakujace i puste -----


def test_load_catalog_rejects_missing_required_field(tmp_path):
    for field in mapper.REQUIRED_CATALOG_FIELDS:
        sub = tmp_path / f"missing_{field}"
        _write_catalog(sub, remove_fields=[field])
        with pytest.raises(mapper.StandardsError):
            mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_empty_paraphrase(tmp_path):
    sub = tmp_path / "empty_paraphrase"
    _write_catalog(sub, overrides={"paraphrase": ""})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_empty_string_field_same_as_missing(tmp_path):
    for field in mapper.REQUIRED_CATALOG_FIELDS:
        if field == "verified":
            # verified=False jest legalna, jedyna poprawna wartosc wpisu
            # prowizorycznego - nie moze byc traktowane jak brak pola.
            continue
        sub = tmp_path / f"empty_{field}"
        _write_catalog(sub, overrides={field: ""})
        with pytest.raises(mapper.StandardsError):
            mapper.load_catalog(catalog_root=sub)


def test_load_catalog_accepts_verified_false_without_raising(tmp_path):
    sub = tmp_path / "provisional"
    _write_catalog(sub, overrides={"verified": False})
    catalog = mapper.load_catalog(catalog_root=sub)
    assert catalog[("TEST-STANDARD", "T 1.1")]["verified"] is False


# --- Grupa nowa: bramka typu pola katalogu (STD-03, STD-05, G-04-2) --------
#
# Zamyka luke UAT G-04-2: wpis z polem `verified` zapisanym jako napis albo
# liczba wczytywal sie bez bledu, a `resolve` zamienial kazdy niepusty napis
# w `True` przez `bool(...)`. Testy nizej dowodza, ze bramka siedzi w warstwie
# WCZYTUJACEJ, nie tylko w tym pakiecie testow.


def test_load_catalog_rejects_verified_as_string(tmp_path):
    sub = tmp_path / "verified_string"
    _write_catalog(sub, overrides={"verified": "prawda"})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_verified_as_int(tmp_path):
    sub = tmp_path / "verified_int"
    _write_catalog(sub, overrides={"verified": 1})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_accepts_verified_true_without_raising(tmp_path):
    # clause_title_source musi byc "egzemplarz" tutaj - regula miedzypolowa
    # z G-04-3c odrzuca podniesione `verified` przy prowieniencji `wlasny`.
    sub = tmp_path / "verified_true"
    _write_catalog(
        sub, overrides={"verified": True, "clause_title_source": "egzemplarz"}
    )
    catalog = mapper.load_catalog(catalog_root=sub)
    assert catalog[("TEST-STANDARD", "T 1.1")]["verified"] is True


def test_load_catalog_rejects_edition_as_int(tmp_path):
    sub = tmp_path / "edition_int"
    _write_catalog(sub, overrides={"edition": 2020})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_clause_as_float(tmp_path):
    sub = tmp_path / "clause_float"
    _write_catalog(sub, overrides={"clause": 1.1})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


@pytest.mark.parametrize(
    "field", ["standard", "clause_title", "clause_title_source", "paraphrase"]
)
def test_load_catalog_rejects_non_string_scalar_field(tmp_path, field):
    sub = tmp_path / f"non_string_{field}"
    _write_catalog(sub, overrides={field: 42})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_verification_note_wrong_type(tmp_path):
    sub = tmp_path / "verification_note_int"
    _write_catalog(sub, overrides={"verification_note": 123})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_accepts_missing_optional_verification_note(tmp_path):
    sub = tmp_path / "no_verification_note"
    _write_catalog(sub, remove_fields=["verification_note"])
    catalog = mapper.load_catalog(catalog_root=sub)
    assert "verification_note" not in catalog[("TEST-STANDARD", "T 1.1")]


def test_type_error_komunikat_niesie_pole_i_typy_bez_wartosci(tmp_path):
    sub = tmp_path / "komunikat_ksztalt"
    secret_paraphrase_value = 424242
    _write_catalog(sub, overrides={"paraphrase": secret_paraphrase_value})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "paraphrase" in message
    assert "str" in message
    assert "int" in message
    assert str(secret_paraphrase_value) not in message


def test_type_error_komunikat_niesie_wszystkie_pola_naraz(tmp_path):
    sub = tmp_path / "komunikat_wiele_pol"
    _write_catalog(sub, overrides={"edition": 2020, "verified": "prawda"})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "edition" in message
    assert "verified" in message


# --- Grupa nowa: prowieniencja tytulu punktu (STD-03, G-04-3c) -------------
#
# Zamyka luke UAT G-04-3c: katalog nie niosl w danych roznicy miedzy tytulem
# potwierdzonym wobec egzemplarza a opisem wlasnym, wiec oba renderowaly sie
# w tym samym ksztalcie.


def test_load_catalog_rejects_clause_title_source_outside_closed_set(tmp_path):
    sub = tmp_path / "clause_title_source_bad_value"
    _write_catalog(sub, overrides={"clause_title_source": "zmyslony"})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "zmyslony" in message
    assert "egzemplarz" in message
    assert "wlasny" in message


def test_load_catalog_rejects_verified_true_with_clause_title_source_wlasny(tmp_path):
    sub = tmp_path / "verified_true_wlasny"
    _write_catalog(sub, overrides={"verified": True, "clause_title_source": "wlasny"})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "verified" in message
    assert "clause_title_source" in message


def test_load_catalog_accepts_verified_true_with_clause_title_source_egzemplarz(tmp_path):
    sub = tmp_path / "verified_true_egzemplarz"
    _write_catalog(
        sub, overrides={"verified": True, "clause_title_source": "egzemplarz"}
    )

    catalog = mapper.load_catalog(catalog_root=sub)

    assert catalog[("TEST-STANDARD", "T 1.1")]["clause_title_source"] == "egzemplarz"


@pytest.mark.parametrize("clause_title_source", sorted(mapper.CLAUSE_TITLE_SOURCES))
def test_load_catalog_accepts_verified_false_with_either_clause_title_source(
    tmp_path, clause_title_source
):
    sub = tmp_path / f"verified_false_{clause_title_source}"
    _write_catalog(
        sub, overrides={"verified": False, "clause_title_source": clause_title_source}
    )

    catalog = mapper.load_catalog(catalog_root=sub)

    assert (
        catalog[("TEST-STANDARD", "T 1.1")]["clause_title_source"]
        == clause_title_source
    )


def test_resolve_passes_verified_value_without_conversion():
    zone_model = zones.build_zone_model(
        observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp"]
    )
    catalog = mapper.load_catalog()
    (standard, clause), entry = next(iter(catalog.items()))

    ref = mapper.resolve(standard, clause, zone_model=zone_model)

    assert ref.verified is entry["verified"]


# Wpis probny o zlym typie pola weryfikacji, wpisany do PRAWDZIWEGO drzewa
# pakietu - wzorzec `probe_catalog_and_check` z grupy siodmej nizej w tym
# pliku. Zaden check nie odwoluje sie do tej pary, wiec sam fakt obecnosci
# pliku w drzewie katalogu norm wystarcza, by zlamac `load_catalog()` na
# KAZDYM wywolaniu (skan jest rekurencyjny nad calym `CATALOG_ROOT`).
BAD_TYPE_PROBE_DIR_NAME = "probe_bad_type_catalog"
BAD_TYPE_PROBE_DIR = STANDARDS_ROOT / BAD_TYPE_PROBE_DIR_NAME


def _write_bad_type_probe_catalog() -> None:
    _write_catalog(BAD_TYPE_PROBE_DIR, overrides={"verified": "prawda"})


def _remove_bad_type_probe_catalog() -> None:
    if BAD_TYPE_PROBE_DIR.exists():
        shutil.rmtree(BAD_TYPE_PROBE_DIR)


@pytest.fixture
def bad_type_probe_catalog():
    assert not BAD_TYPE_PROBE_DIR.exists(), (
        f"{BAD_TYPE_PROBE_DIR} juz istnieje - poprzedni przebieg testu nie "
        "posprzatal po sobie."
    )
    _write_bad_type_probe_catalog()
    try:
        yield
    finally:
        _remove_bad_type_probe_catalog()


def test_catalog_bad_verified_type_stops_analyze_with_nonzero_exit_and_no_analysis(
    bad_type_probe_catalog, tmp_path
):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == cli_module.EXIT_UNREADABLE, result.stderr
    assert not (tmp_path / "analysis.json").exists()


def test_untouched_catalog_report_carries_provisional_status_for_every_reference(tmp_path):
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    result = analyze(fixture, out_dir=tmp_path, generated_at=GENERATED_AT)

    assert result.analysis["findings"], "Fixture bazowy nie dal ani jednego findingu."
    total_refs = sum(len(f["standard_refs"]) for f in result.analysis["findings"])
    assert total_refs > 0

    provisional_marker_count = result.report_markdown.count(
        "PROWIZORYCZNE, NIEZWERYFIKOWANE"
    )
    assert provisional_marker_count == total_refs


# --- Encoding: polskie znaki z parafrazy przechodza bez escapowania --------


def test_analysis_json_carries_polish_diacritics_without_escaping(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    raw_text = (tmp_path / "analysis.json").read_text(encoding="utf-8")
    assert "\\u" not in raw_text, "analysis.json niesie escapowana sekwencje \\uXXXX"
    assert any(ch in raw_text for ch in POLISH_DIACRITICS), (
        "analysis.json nie niesie ani jednego polskiego znaku diakrytycznego "
        "z parafrazy katalogu norm"
    )


# --- Funkcje pomocnicze wspolne dla grup 4 i 5 -------------------------------


def analyzable_fixtures() -> list[Path]:
    """Kazdy fixture z katalogu, ktory konczy analize bez wyjatku. Wzorzec
    kopiowany z `tests/test_report_forbidden_phrases.py::_analyzable_fixtures`
    - lista budowana GLOBEM, nie recznym wyliczeniem nazw, zeby nowy fixture
    wchodzil pod te bramke bez zmiany tego pliku."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def check_specs() -> list[dict]:
    """Surowe slowniki odczytane z kazdego pliku YAML pod katalogiem
    checkow, w tej samej kolejnosci posortowanej co `engine.discover_checks`.
    Potrzebne osobno od odkrywania checkow: `CheckSpec.spec` niesie surowy
    slownik, ale ta bramka porownuje takze pole edycji kazdego powolania z
    katalogiem, co jest wygodniejsze na surowym slowniku niz na rekordzie
    `CheckSpec`."""
    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(engine.CHECKS_ROOT.rglob("*.yaml"))
    ]


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} nie produkuje artefaktow (brama D-01)")


def _dedupe_pairs(standards: list[dict]) -> list[tuple[str, str]]:
    """Usuwa powtorzone pary (standard, clause), zachowujac PIERWSZE
    wystapienie - lustro `engine._dedupe_standards`, ale zwraca same pary
    do porownania z kolejnoscia powolan findingu, nie slowniki pelne."""
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []
    for entry in standards:
        key = (entry["standard"], entry["clause"])
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


# --- Grupa czwarta: kontrakt STD-03/STD-05 nad KAZDYM findingiem KAZDEGO ----
# --- analizowalnego fixture'u -----------------------------------------------


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_finding_has_nonempty_standard_refs(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        assert finding["standard_refs"], (
            f"Finding {finding['check_id']} w {fixture.name} nie niesie ani "
            "jednego powolania."
        )


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_finding_has_iec_62443_3_3_reference(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        standards = {ref["standard"] for ref in finding["standard_refs"]}
        assert "IEC-62443-3-3" in standards, (
            f"Finding {finding['check_id']} w {fixture.name} nie niesie "
            f"powolania na IEC-62443-3-3: {standards}"
        )


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_reference_has_nonempty_edition_clause_and_title(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        for ref in finding["standard_refs"]:
            assert ref["edition"], f"Powolanie findingu {finding['check_id']} bez edycji."
            assert ref["clause"], f"Powolanie findingu {finding['check_id']} bez punktu."
            assert ref["clause_title"], (
                f"Powolanie findingu {finding['check_id']} bez tytulu punktu."
            )


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_reference_order_matches_check_yaml_order_after_dedup(fixture, tmp_path):
    specs_by_id = {spec["id"]: spec for spec in check_specs()}
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        spec = specs_by_id[finding["check_id"]]
        expected = _dedupe_pairs(spec["standards"])
        actual = [(ref["standard"], ref["clause"]) for ref in finding["standard_refs"]]
        assert actual == expected


def test_reference_order_is_identical_across_two_runs(tmp_path):
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    first = analyze(fixture, out_dir=tmp_path / "first", generated_at=GENERATED_AT)
    second = analyze(fixture, out_dir=tmp_path / "second", generated_at=GENERATED_AT)

    first_orders = [
        [(ref["standard"], ref["clause"]) for ref in f["standard_refs"]]
        for f in first.analysis["findings"]
    ]
    second_orders = [
        [(ref["standard"], ref["clause"]) for ref in f["standard_refs"]]
        for f in second.analysis["findings"]
    ]
    assert first_orders == second_orders


def test_reference_count_boundary_never_zero_across_all_fixtures(tmp_path):
    """Sonda krawedziowa: zbior liczb powolan wystepujacych w findingach
    wszystkich analizowalnych fixture'ow zawiera co najmniej wartosc jeden
    i nie zawiera zera. Po planie 04-05 ten sam test zobaczy takze wartosc
    dwa i przejdzie bez zmiany, bo warunkiem jest brak zera, a nie
    konkretna liczba - nie przypinac tego testu do liczby, ktora zmieni sie
    w nastepnym planie."""
    counts: set[int] = set()
    for i, fixture in enumerate(analyzable_fixtures()):
        try:
            result = analyze(fixture, out_dir=tmp_path / f"f{i}", generated_at=GENERATED_AT)
        except (CaptureTruncatedError, CaptureFormatError):
            continue
        for finding in result.analysis["findings"]:
            counts.add(len(finding["standard_refs"]))

    assert 0 not in counts
    assert counts, "Zaden fixture nie dal ani jednego findingu."


# --- Grupa piata: kontrakt nad plikami checkow i nad katalogiem norm -------


def test_every_check_file_has_nonempty_standards_list():
    for spec in check_specs():
        assert spec.get("standards"), f"Check {spec.get('id')} bez listy powolan."


def test_every_check_reference_resolves_against_catalog():
    zone_model = zones.build_zone_model(
        observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp"]
    )
    for spec in check_specs():
        for ref in spec["standards"]:
            # Brak wyjatku jest cala tresc tego testu - `resolve` podnosi
            # `StandardsError`, gdy para (standard, clause) nie jest w katalogu.
            mapper.resolve(ref["standard"], ref["clause"], zone_model=zone_model)


def test_check_reference_edition_matches_catalog_edition():
    catalog = mapper.load_catalog()
    for spec in check_specs():
        for ref in spec["standards"]:
            catalog_entry = catalog[(ref["standard"], ref["clause"])]
            assert ref["edition"] == catalog_entry["edition"], (
                f"Check {spec['id']}: edycja {ref['edition']!r} w pliku checka "
                f"rozjezdza sie z edycja katalogu {catalog_entry['edition']!r} "
                f"dla {ref['standard']} {ref['clause']}."
            )


# --- Checki probne na katalogu tymczasowym: schemat pusty/brakujacy i -------
# --- deduplikacja/kolejnosc w findingu ---------------------------------------

CHECK_SPEC_DEFAULTS: dict = {
    "id": "probe-std-check",
    "title": "Check probny bramki STD-03",
    "applies_to": {"protocol": "modbus-tcp"},
    "severity": "high",
    "rationale": "Wlasna testowa przyczyna, nigdy cytat normy.",
    "standards": [{"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"}],
    "evaluator": "probe:evaluate",
    "remediation": "Testowe zalecenie, nieuzywane poza tym testem.",
}

# Evaluator zwracajacy dokladnie jeden finding z pierwszego zdarzenia -
# uzyty przez testy deduplikacji/kolejnosci powolan, ktorym nie zalezy na
# logice checka, tylko na tym, ze finding w ogole powstal. Wzorzec
# `tests/test_check_engine.py::EVALUATOR_ONE_FINDING_SOURCE`.
PROBE_EVALUATOR_SOURCE = textwrap.dedent(
    """
    from __future__ import annotations

    def evaluate(analysis):
        events = analysis.get("protocol_events", [])
        if not events:
            return []
        first = events[0]
        return [
            {
                "evidence": {
                    "packet_number": first["packet_number"],
                    "session_id": first["session_id"],
                }
            }
        ]
    """
).lstrip()


def _write_probe_check(
    checks_dir: Path,
    *,
    subdir: str,
    spec_overrides: dict | None = None,
    remove_fields: list[str] | None = None,
) -> Path:
    """Zapisuje jeden check probny (YAML plus siostrzany evaluator) pod
    `checks_dir/subdir`. Wzorzec `tests/test_check_engine.py::_write_check`,
    zapisany tutaj wprost zamiast importowany miedzy plikami testowymi -
    import modulu testowego z innego pliku testowego jest krucha zaleznoscia
    od kolejnosci zbierania testow przez pytest."""
    target_dir = checks_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    spec = dict(CHECK_SPEC_DEFAULTS)
    spec["applies_to"] = dict(CHECK_SPEC_DEFAULTS["applies_to"])
    if spec_overrides:
        spec.update(spec_overrides)
    if remove_fields:
        for field in remove_fields:
            spec.pop(field, None)

    yaml_path = target_dir / "check.yaml"
    yaml_path.write_text(
        yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    (target_dir / "probe.py").write_text(PROBE_EVALUATOR_SOURCE, encoding="utf-8")
    return yaml_path


def test_check_with_empty_standards_list_fails_schema(tmp_path):
    _write_probe_check(tmp_path, subdir="empty_standards", spec_overrides={"standards": []})
    with pytest.raises(engine.CheckSchemaError):
        engine.discover_checks(checks_root=tmp_path / "empty_standards")


def test_check_without_standards_key_fails_schema(tmp_path):
    _write_probe_check(tmp_path, subdir="missing_standards", remove_fields=["standards"])
    with pytest.raises(engine.CheckSchemaError):
        engine.discover_checks(checks_root=tmp_path / "missing_standards")


def test_two_identical_standard_entries_dedupe_to_one_in_finding(tmp_path):
    _write_probe_check(
        tmp_path,
        subdir="dup_standards",
        spec_overrides={
            "id": "probe-dup-standards",
            "standards": [
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
            ],
        },
    )
    checks = engine.discover_checks(checks_root=tmp_path / "dup_standards")
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert len(findings) == 1
    assert findings[0]["standards"] == [
        {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"}
    ]


def test_two_distinct_clause_entries_stay_separate_in_finding(tmp_path):
    _write_probe_check(
        tmp_path,
        subdir="ordered_standards",
        spec_overrides={
            "id": "probe-ordered-standards",
            "standards": [
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 4.1"},
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
            ],
        },
    )
    checks = engine.discover_checks(checks_root=tmp_path / "ordered_standards")
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert len(findings) == 1
    assert [entry["clause"] for entry in findings[0]["standards"]] == ["SR 4.1", "SR 1.1"]


# --- Grupa szosta: kontrakt zduplikowanej pary i przypadkow brzegowych -----
# --- wczytywania miedzy dwoma plikami katalogu ------------------------------


def _write_catalog_pair(
    root: Path, *, first: dict, second: dict
) -> tuple[Path, Path]:
    """Zapisuje DWA pliki `catalog.yaml`, kazdy w OSOBNYM podkatalogu jednego
    katalogu tymczasowego, zeby rekurencyjny skan `load_catalog` znalazl oba.
    Zwraca obie sciezki, w kolejnosci alfabetycznej podkatalogow (`a`, `b`),
    czyli w tej samej kolejnosci, w ktorej `sorted(rglob(...))` je odczyta."""
    path_a = _write_catalog(root / "a", overrides=first)
    path_b = _write_catalog(root / "b", overrides=second)
    return path_a, path_b


def test_load_catalog_rejects_duplicate_pair_between_two_files(tmp_path):
    path_a, path_b = _write_catalog_pair(
        tmp_path,
        first={"standard": "TEST-STANDARD", "clause": "T 1.1"},
        second={"standard": "TEST-STANDARD", "clause": "T 1.1"},
    )

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=tmp_path)

    message = str(excinfo.value)
    assert str(path_a) in message
    assert str(path_b) in message


def test_load_catalog_accepts_distinct_pairs_in_two_files(tmp_path):
    _write_catalog_pair(
        tmp_path,
        first={"standard": "TEST-STANDARD", "clause": "T 1.1"},
        second={"standard": "TEST-STANDARD", "clause": "T 2.2"},
    )

    catalog = mapper.load_catalog(catalog_root=tmp_path)

    assert len(catalog) == 2
    assert ("TEST-STANDARD", "T 1.1") in catalog
    assert ("TEST-STANDARD", "T 2.2") in catalog


def test_load_catalog_on_file_with_empty_entries_list_returns_empty_mapping(tmp_path):
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text(yaml.safe_dump({"entries": []}), encoding="utf-8")

    assert mapper.load_catalog(catalog_root=tmp_path) == {}


def test_load_catalog_on_completely_empty_file_returns_empty_mapping(tmp_path):
    catalog_path = tmp_path / "catalog.yaml"
    catalog_path.write_text("", encoding="utf-8")

    assert mapper.load_catalog(catalog_root=tmp_path) == {}


# Wpis z pustym polem edycji: przypadek juz pokryty przez
# `test_load_catalog_rejects_empty_string_field_same_as_missing`, ktory
# iteruje po WSZYSTKICH `REQUIRED_CATALOG_FIELDS` (edition wliczajac) - nie
# dublowany tutaj.


def test_load_catalog_scan_order_is_identical_across_two_scans(tmp_path):
    _write_catalog_pair(
        tmp_path,
        first={"standard": "TEST-STANDARD", "clause": "T 1.1"},
        second={"standard": "TEST-STANDARD", "clause": "T 2.2"},
    )

    first_scan = list(mapper.load_catalog(catalog_root=tmp_path).keys())
    second_scan = list(mapper.load_catalog(catalog_root=tmp_path).keys())

    assert first_scan == second_scan


# --- Grupa siodma: bramka zerowej zmiany kodu (kryterium 4 fazy) -----------
#
# Wzorcem jest `tests/test_check_engine.py::test_new_check_discovered_without_engine_change`,
# linia po linii: plik probny wpisany do PRAWDZIWEGO katalogu norm
# (`src/wayside/standards/`), nie do `tmp_path` - dokladnie to dowodzi
# kryterium 4 fazy (druga norma wchodzi jako plik danych, bez zmiany zadnego
# pliku `.py` pod katalogiem pakietu). Nazwa podkatalogu probnego jest STALA,
# nie losowa - nieudany wczesniejszy przebieg zostawilby slad zmieniajacy
# wynik innych testow (ten sam powod co w `test_check_engine.py`).

PACKAGE_ROOT = REPO_ROOT / "src" / "wayside"
PROBE_CATALOG_DIR_NAME = "probe_extensibility_catalog"
PROBE_CATALOG_DIR = STANDARDS_ROOT / PROBE_CATALOG_DIR_NAME
PROBE_STANDARD = "TEST-STANDARD-PROBE"
PROBE_CLAUSE = "T 9.9"
PROBE_CATALOG_ENTRY: dict = {
    "standard": PROBE_STANDARD,
    "edition": "9999",
    "clause": PROBE_CLAUSE,
    "clause_title": "Tytul probny bramki rozszerzalnosci katalogu norm",
    "clause_title_source": "wlasny",
    "paraphrase": "Testowa parafraza bramki rozszerzalnosci katalogu norm, nigdy cytat normy.",
    "verified": False,
    "verification_note": "Wpis probny, uzywany wylacznie przez test bramki rozszerzalnosci.",
}

# Check probny dopisujemy do listy powolan JEDNEGO prawdziwego checka -
# bez tego probna para nie ma jak wejsc do findingu. `modbus-unauthenticated-write`
# pasuje, bo fixture bazowy Modbusa daje dokladnie jeden finding tego checka.
PROBE_TARGET_CHECK_YAML = (
    REPO_ROOT / "src" / "wayside" / "checks" / "modbus" / "unauthenticated_write.yaml"
)
# Bajty, nie tekst: `Path.write_text` na Windows tlumaczy `\n` na `\r\n` przy
# zapisie (domyslne `newline=None`), wiec przywrocenie przez tekst zmienia
# koncowki linii pliku sledzonego przez git z LF na CRLF - pozorna, ale
# realna modyfikacja widoczna w `git status`. Restore idzie WYLACZNIE przez
# bajty, zeby byc bit-identyczny z oryginalem niezaleznie od platformy.
_PROBE_TARGET_ORIGINAL_BYTES = PROBE_TARGET_CHECK_YAML.read_bytes()
_PROBE_TARGET_ORIGINAL_TEXT = _PROBE_TARGET_ORIGINAL_BYTES.decode("utf-8")


def _package_python_files() -> list[Path]:
    """Kazdy plik o rozszerzeniu `.py` pod katalogiem pakietu, rekurencyjnie,
    z pominieciem katalogow ze skompilowanymi plikami cache."""
    return sorted(p for p in PACKAGE_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _sha256_map(paths: list[Path]) -> dict[str, str]:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def _write_probe_catalog_and_check() -> None:
    PROBE_CATALOG_DIR.mkdir(parents=True)
    (PROBE_CATALOG_DIR / "catalog.yaml").write_text(
        yaml.safe_dump({"entries": [PROBE_CATALOG_ENTRY]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    check_spec = yaml.safe_load(_PROBE_TARGET_ORIGINAL_TEXT)
    check_spec["standards"] = list(check_spec["standards"]) + [
        {"standard": PROBE_STANDARD, "edition": "9999", "clause": PROBE_CLAUSE}
    ]
    PROBE_TARGET_CHECK_YAML.write_text(
        yaml.safe_dump(check_spec, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )


def _restore_probe_catalog_and_check() -> None:
    if PROBE_CATALOG_DIR.exists():
        shutil.rmtree(PROBE_CATALOG_DIR)
    PROBE_TARGET_CHECK_YAML.write_bytes(_PROBE_TARGET_ORIGINAL_BYTES)


@pytest.fixture(autouse=True, scope="module")
def _cleanup_probe_catalog_and_check_after_module():
    """Sprzata oba slady (katalog probny, tresc pliku checka) takze wtedy,
    gdy blad wystapil przed przekazaniem sterowania do testu - wzorzec
    `tests/test_check_engine.py::_cleanup_probe_check_dir_after_module`."""
    yield
    if PROBE_CATALOG_DIR.exists():
        shutil.rmtree(PROBE_CATALOG_DIR)
    if PROBE_TARGET_CHECK_YAML.read_bytes() != _PROBE_TARGET_ORIGINAL_BYTES:
        PROBE_TARGET_CHECK_YAML.write_bytes(_PROBE_TARGET_ORIGINAL_BYTES)
    if BAD_TYPE_PROBE_DIR.exists():
        shutil.rmtree(BAD_TYPE_PROBE_DIR)


@pytest.fixture
def probe_catalog_and_check():
    assert not PROBE_CATALOG_DIR.exists(), (
        f"{PROBE_CATALOG_DIR} juz istnieje - poprzedni przebieg testu nie "
        "posprzatal po sobie."
    )
    _write_probe_catalog_and_check()
    try:
        yield
    finally:
        _restore_probe_catalog_and_check()


def test_new_catalog_file_discovered_without_package_code_change(probe_catalog_and_check, tmp_path):
    py_files_before = _package_python_files()
    checksums_before = _sha256_map(py_files_before)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    py_files_after = _package_python_files()
    checksums_after = _sha256_map(py_files_after)

    changed = sorted(
        p for p in checksums_before if checksums_before[p] != checksums_after.get(p)
    )
    added_or_removed = sorted(
        set(checksums_before.keys()) ^ set(checksums_after.keys())
    )
    assert not changed and not added_or_removed, (
        f"Zmienione pliki: {changed}; dodane/usuniete pliki: {added_or_removed}"
    )

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    probe_refs = [
        ref
        for finding in analysis["findings"]
        for ref in finding["standard_refs"]
        if ref["standard"] == PROBE_STANDARD and ref["clause"] == PROBE_CLAUSE
    ]
    assert probe_refs, "probna para powolania nie pojawila sie w analysis.json"

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert PROBE_STANDARD in report_text, "raport.md nie wymienia probnej sygnatury"


def test_probe_catalog_and_check_leave_no_trace_after_cleanup(tmp_path):
    """Bez tego testu bramka dowodzilaby, ze plik danych wchodzi, a nie ze
    wychodzi bez sladu - a to drugie jest warunkiem, zeby pozostale testy
    pakietu (w tym `test_reference_count_boundary_never_zero_across_all_fixtures`)
    nadal liczyly to, co licza. Wola po tym, jak `probe_catalog_and_check`
    (function-scoped) juz posprzatal w bloku `finally` po poprzednim tescie -
    pytest uruchamia testy tego pliku w kolejnosci zapisu."""
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"

    assert not PROBE_CATALOG_DIR.exists(), (
        "katalog probny wciaz istnieje - kolejnosc testow w tym module jest "
        "zlamana."
    )
    assert PROBE_TARGET_CHECK_YAML.read_bytes() == _PROBE_TARGET_ORIGINAL_BYTES

    baseline = analyze(fixture, out_dir=tmp_path / "baseline", generated_at=GENERATED_AT)
    baseline_counts = [
        len(f["standard_refs"]) for f in baseline.analysis["findings"]
    ]

    _write_probe_catalog_and_check()
    try:
        with_probe = analyze(fixture, out_dir=tmp_path / "with_probe", generated_at=GENERATED_AT)
        with_probe_counts = [
            len(f["standard_refs"]) for f in with_probe.analysis["findings"]
        ]
        assert with_probe_counts != baseline_counts
    finally:
        _restore_probe_catalog_and_check()

    restored = analyze(fixture, out_dir=tmp_path / "restored", generated_at=GENERATED_AT)
    restored_counts = [
        len(f["standard_refs"]) for f in restored.analysis["findings"]
    ]
    assert restored_counts == baseline_counts


def test_no_int_or_float_conversion_anywhere_in_standards_layer():
    """Krawedz precision: zaden plik `.py` pod katalogiem warstwy normatywnej
    nie wola konwersji do liczby calkowitej ani zmiennoprzecinkowej - na
    sciezce powolania nie ma ani jednej takiej konwersji, co jest tu
    SPRAWDZANE nad drzewem skladni, nie zalozone."""
    bad: list[tuple[str, str]] = []
    for py_file in STANDARDS_ROOT.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("int", "float")
            ):
                bad.append((py_file.name, node.func.id))
    assert not bad, bad
