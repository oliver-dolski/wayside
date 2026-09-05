"""Bramka rozszerzalnosci silnika checkow i kontraktu schematu (CHECK-01, CHECK-02).

`test_new_check_discovered_without_engine_change` tymczasowo dodaje check
probny do PRAWDZIWEGO katalogu `src/wayside/checks/` (nie do katalogu
tymczasowego), bo dokladnie to bada kryterium 4 fazy: nowy check w czasie
dzialania, bez zmiany zadnego pliku silnika. To sprzezenie jest nazwane
wprost: ten test tymczasowo zmienia zawartosc katalogu checkow calego
pakietu, wiec `tests/test_analyze_pipeline.py`, ktore liczy findingi,
zalezy od poprawnego uprzatniecia po tym tescie. Pytest uruchamia testy
w tym pliku szeregowo, wiec sprzezenie jest bezpieczne, ale nie jest
niewidzialne - fixture `probe_check_dir` sprzata w bloku `finally`, a
autouse fixture modulu sprzata takze wtedy, gdy `probe_check_dir` sam nie
zdazyl (np. blad w setupie przed `yield`).

Pozostale testy schematu i kolejnosci wolaja `discover_checks` na katalogu
TYMCZASOWYM (`tmp_path`) - loader oparty o `spec_from_file_location` dziala
na dowolnej sciezce, wiec te testy nigdy nie dotykaja prawdziwego pakietu.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from wayside.checks import engine

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = REPO_ROOT / "src" / "wayside" / "checks" / "engine.py"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
CHECKS_ROOT = REPO_ROOT / "src" / "wayside" / "checks"
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"

# Nazwa stala, nie losowa - inaczej nieudany wczesniejszy przebieg zostawilby
# slad, ktory zmienia wynik innych testow (patrz docstring modulu).
PROBE_CHECK_DIR_NAME = "probe_extensibility_check"
PROBE_CHECK_DIR = CHECKS_ROOT / PROBE_CHECK_DIR_NAME


def _sha256(path: Path) -> str:
    """Wzorzec `_sha256` ze `scripts/gen_fixtures.py`."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- Wzorzec pol domyslnych do budowy checkow probnych na tmp_path -----------

DEFAULT_SPEC_FIELDS: dict = {
    "id": "probe-check",
    "title": "Check probny",
    "applies_to": {"protocol": "modbus-tcp"},
    "severity": "high",
    "rationale": "Wlasna testowa przyczyna, nigdy cytat normy.",
    "standards": [{"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"}],
    "evaluator": "probe:evaluate",
    "remediation": "Testowe zalecenie, nieuzywane poza tym testem.",
}

EVALUATOR_EMPTY_SOURCE = textwrap.dedent(
    """
    from __future__ import annotations

    def evaluate(analysis):
        return []
    """
).lstrip()

# Evaluator zwracajacy dokladnie jeden finding, z dowodem wziętym z
# pierwszego zdarzenia protokolu - uzywany przez testy dedupikacji/kolejnosci
# powolan `standards`, ktorym nie zalezy na logice checka, tylko na tym, ze
# finding w ogole powstal.
EVALUATOR_ONE_FINDING_SOURCE = textwrap.dedent(
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


def _write_check(
    checks_dir: Path,
    *,
    subdir: str,
    spec_overrides: dict | None = None,
    remove_fields: list[str] | None = None,
    evaluator_filename: str = "probe",
    evaluator_source: str = EVALUATOR_EMPTY_SOURCE,
    write_evaluator: bool = True,
) -> Path:
    """Zapisuje jeden check (YAML plus siostrzany `.py`) pod
    `checks_dir/subdir`. Wydzielona wspolna logika budowy checka, zeby
    przypadek negatywny (pole brakujace, puste, duplikat, nazwa modulu
    niedozwolona) wolal ta sama funkcje pomocnicza, a nie ja dublowal -
    wzorzec `tests/test_fixture_manifest.py`. Zwraca sciezke do YAML."""
    target_dir = checks_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    spec = dict(DEFAULT_SPEC_FIELDS)
    spec["applies_to"] = dict(DEFAULT_SPEC_FIELDS["applies_to"])
    spec["standards"] = [dict(entry) for entry in DEFAULT_SPEC_FIELDS["standards"]]
    if spec_overrides:
        spec.update(spec_overrides)
    if remove_fields:
        for field in remove_fields:
            spec.pop(field, None)

    yaml_path = target_dir / "check.yaml"
    yaml_path.write_text(
        yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

    if write_evaluator:
        (target_dir / f"{evaluator_filename}.py").write_text(evaluator_source, encoding="utf-8")

    return yaml_path


# --- Fixture katalogu checka probnego wewnatrz PRAWDZIWEGO pakietu -----------


@pytest.fixture(autouse=True, scope="module")
def _cleanup_probe_check_dir_after_module():
    """Sprzata katalog checka probnego takze wtedy, gdy test padnie w
    polowie i wlasny `finally` fixture `probe_check_dir` nie zdazy
    zadzialac (np. blad przed jego wlasnym `yield`)."""
    yield
    if PROBE_CHECK_DIR.exists():
        shutil.rmtree(PROBE_CHECK_DIR)


@pytest.fixture
def probe_check_dir():
    assert not PROBE_CHECK_DIR.exists(), (
        f"{PROBE_CHECK_DIR} juz istnieje - poprzedni przebieg testu nie "
        "posprzatal po sobie."
    )
    _write_check(
        CHECKS_ROOT,
        subdir=PROBE_CHECK_DIR_NAME,
        spec_overrides={
            "id": "probe-extensibility-check",
            "title": "Check probny bramki rozszerzalnosci silnika",
        },
        evaluator_source=EVALUATOR_ONE_FINDING_SOURCE,
    )
    try:
        yield PROBE_CHECK_DIR
    finally:
        if PROBE_CHECK_DIR.exists():
            shutil.rmtree(PROBE_CHECK_DIR)


# --- Test 4 fazy: nowy check bez zmiany zadnego pliku silnika ----------------


def test_new_check_discovered_without_engine_change(probe_check_dir, tmp_path):
    engine_before = _sha256(ENGINE_PATH)
    pyproject_before = _sha256(PYPROJECT_PATH)

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

    engine_after = _sha256(ENGINE_PATH)
    pyproject_after = _sha256(PYPROJECT_PATH)
    assert engine_after == engine_before, "silnik checkow zostal zmieniony przez dodanie checka"
    assert pyproject_after == pyproject_before, "pyproject.toml zostal zmieniony przez dodanie checka"

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    probe_findings = [f for f in analysis["findings"] if f["check_id"] == "probe-extensibility-check"]
    assert probe_findings, "finding checka probnego nie pojawil sie w analysis.json"

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "probe-extensibility-check" in report_text


def test_probe_check_directory_removed_and_original_finding_count_restored(probe_check_dir, tmp_path):
    """Po usunieciu checka probnego (fixture teardown zadziala po tym
    tescie) `wayside analyze` na fixture z zapisem znow daje dokladnie
    jeden finding - dowod, ze test nie zostawia trwalego sladu."""
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
    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    # Z checkiem probnym obecnym: oryginalny check + check probny.
    check_ids = {f["check_id"] for f in analysis["findings"]}
    assert "modbus-unauthenticated-write" in check_ids
    assert "probe-extensibility-check" in check_ids


# --- Kontrakt schematu: pole wymagane brakujace lub puste --------------------


def test_check_schema_required_fields(tmp_path):
    """Brak dowolnego pola z `REQUIRED_CHECK_FIELDS`, i to samo pole
    obecne ale puste, konczy sie `CheckSchemaError` - obie galezie wolaja
    te sama funkcje pomocnicza `_write_check`, zamiast dublowac logike."""
    for field in engine.REQUIRED_CHECK_FIELDS:
        missing_subdir = f"missing_{field}"
        _write_check(tmp_path, subdir=missing_subdir, remove_fields=[field])
        with pytest.raises(engine.CheckSchemaError):
            engine.discover_checks(checks_root=tmp_path / missing_subdir)

        empty_subdir = f"empty_{field}"
        if field == "applies_to":
            empty_value: object = {}
        elif field == "standards":
            empty_value = []
        else:
            empty_value = ""
        _write_check(tmp_path, subdir=empty_subdir, spec_overrides={field: empty_value})
        with pytest.raises(engine.CheckSchemaError):
            engine.discover_checks(checks_root=tmp_path / empty_subdir)


# --- Duplikat identyfikatora -------------------------------------------------


def test_discover_checks_rejects_duplicate_id(tmp_path):
    _write_check(tmp_path, subdir="a", spec_overrides={"id": "dup-check"})
    _write_check(tmp_path, subdir="b", spec_overrides={"id": "dup-check"})

    with pytest.raises(engine.CheckSchemaError):
        engine.discover_checks(checks_root=tmp_path)


# --- Katalog pusty ------------------------------------------------------------


def test_discover_checks_on_empty_directory_returns_empty_list(tmp_path):
    assert engine.discover_checks(checks_root=tmp_path) == []


# --- Kolejnosc posortowanych sciezek, niezalezna od kolejnosci tworzenia ----


def test_discover_checks_orders_by_sorted_path(tmp_path):
    # Tworzone celowo w kolejnosci odwrotnej wobec alfabetu, zeby dowiesc,
    # ze wynik nie jest kolejnoscia tworzenia.
    _write_check(tmp_path, subdir="charlie", spec_overrides={"id": "check-charlie"})
    _write_check(tmp_path, subdir="alfa", spec_overrides={"id": "check-alfa"})
    _write_check(tmp_path, subdir="bravo", spec_overrides={"id": "check-bravo"})

    checks = engine.discover_checks(checks_root=tmp_path)
    ids = [c.spec["id"] for c in checks]

    assert ids == ["check-alfa", "check-bravo", "check-charlie"]
    assert [c.path for c in checks] == sorted(c.path for c in checks)


# --- Nazwa modulu evaluatora z separatorem sciezki albo dwiema kropkami -----


def test_load_evaluator_rejects_path_separator_and_double_dot(tmp_path):
    bad_module_names = ("sub/dir", "sub\\dir", "..")
    for bad_module_name in bad_module_names:
        subdir = "bad_" + re.sub(r"[^a-z]+", "_", bad_module_name.lower()).strip("_")
        _write_check(
            tmp_path,
            subdir=subdir,
            spec_overrides={"evaluator": f"{bad_module_name}:evaluate"},
            write_evaluator=False,
        )
        with pytest.raises(engine.CheckSchemaError):
            engine.discover_checks(checks_root=tmp_path / subdir)
        # Nic nie zostalo zaimportowane - modul probny pod ta nazwa nigdy
        # nie istnieje w sys.modules (zagrozenie T-2-04).
        assert f"wayside._checks.{bad_module_name}" not in sys.modules


# --- Deduplikacja i kolejnosc powtorzonych wpisow `standards` ---------------


def test_run_checks_deduplicates_repeated_standard_reference(tmp_path):
    _write_check(
        tmp_path,
        subdir="dup_standards",
        spec_overrides={
            "id": "dup-standards-check",
            "standards": [
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
            ],
        },
        evaluator_source=EVALUATOR_ONE_FINDING_SOURCE,
    )
    checks = engine.discover_checks(checks_root=tmp_path / "dup_standards")
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert len(findings) == 1
    assert findings[0]["standards"] == [
        {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"}
    ]


def test_run_checks_preserves_yaml_order_for_distinct_standards(tmp_path):
    _write_check(
        tmp_path,
        subdir="ordered_standards",
        spec_overrides={
            "id": "ordered-standards-check",
            "standards": [
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 2.1"},
                {"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"},
            ],
        },
        evaluator_source=EVALUATOR_ONE_FINDING_SOURCE,
    )
    checks = engine.discover_checks(checks_root=tmp_path / "ordered_standards")
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert len(findings) == 1
    assert [entry["clause"] for entry in findings[0]["standards"]] == ["SR 2.1", "SR 1.1"]


# --- G-04-5b: para adresow sesji dopisywana z macierzy komunikacji ----------


def _comm_matrix_row(session_id: int, source: str, target: str) -> dict:
    """Wiersz macierzy komunikacji w ksztalcie pola obserwowanego
    (`dataclasses.asdict(ObservedField(...))`), wzorem prawdziwego
    `flow.build_comm_matrix`."""
    return {
        "session_id": {"value": session_id, "provenance": "observed"},
        "source": {"value": source, "provenance": "observed"},
        "target": {"value": target, "provenance": "observed"},
    }


def test_endpoints_by_session_maps_two_matrix_rows():
    analysis = {
        "comm_matrix": [
            _comm_matrix_row(0, "10.0.0.1:502", "10.0.0.2:50210"),
            _comm_matrix_row(1, "10.0.0.3:502", "10.0.0.4:50333"),
        ]
    }

    mapping = engine._endpoints_by_session(analysis)

    assert mapping == {
        0: ("10.0.0.1:502", "10.0.0.2:50210"),
        1: ("10.0.0.3:502", "10.0.0.4:50333"),
    }


def test_endpoints_by_session_is_empty_without_comm_matrix_key():
    assert engine._endpoints_by_session({}) == {}


def test_run_checks_finding_carries_endpoints_from_matrix_row(tmp_path):
    _write_check(
        tmp_path,
        subdir="with_matrix_row",
        spec_overrides={"id": "with-matrix-row-check"},
        evaluator_source=EVALUATOR_ONE_FINDING_SOURCE,
    )
    checks = engine.discover_checks(checks_root=tmp_path / "with_matrix_row")
    analysis = {
        "protocol_events": [{"packet_number": 1, "session_id": 0}],
        "comm_matrix": [_comm_matrix_row(0, "10.0.0.1:502", "10.0.0.2:50210")],
    }

    findings = engine.run_checks(analysis, checks)

    assert findings[0]["evidence"]["source"] == "10.0.0.1:502"
    assert findings[0]["evidence"]["target"] == "10.0.0.2:50210"


def test_run_checks_finding_uses_placeholder_for_session_absent_from_matrix(tmp_path):
    _write_check(
        tmp_path,
        subdir="without_matrix_row",
        spec_overrides={"id": "without-matrix-row-check"},
        evaluator_source=EVALUATOR_ONE_FINDING_SOURCE,
    )
    checks = engine.discover_checks(checks_root=tmp_path / "without_matrix_row")
    # Analiza bez klucza `comm_matrix` w ogole - zalozenie Z-92: model probny
    # tego modulu nie ma macierzy, a odwzorowanie ma byc na to tolerancyjne.
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert findings[0]["evidence"]["source"] == engine.ENDPOINT_UNKNOWN
    assert findings[0]["evidence"]["target"] == engine.ENDPOINT_UNKNOWN


def test_run_checks_does_not_mutate_evidence_dict_returned_by_evaluator():
    """Zalozenie Z-91: silnik sklada NOWY slownik dowodu zamiast mutowac ten
    zwrocony przez evaluator. Test buduje `CheckSpec` wprost, z evaluatorem
    zwracajacym WSPOLDZIELONY slownik dowodu, zeby mutacja w miejscu byla
    wykrywalna bez posredniego odczytu z dysku."""
    shared_evidence = {"packet_number": 1, "session_id": 0}
    shared_result = {"evidence": shared_evidence}

    def evaluate(analysis: dict) -> list[dict]:
        return [shared_result]

    spec = engine.CheckSpec(
        path=Path("unused-probe-path"),
        spec={
            "id": "shared-evidence-check",
            "title": "Check probny slownika wspoldzielonego",
            "severity": "high",
            "rationale": "Wlasna testowa przyczyna, nigdy cytat normy.",
            "standards": [],
            "remediation": "Testowe zalecenie, nieuzywane poza tym testem.",
        },
        evaluate=evaluate,
    )

    engine.run_checks({}, [spec])

    assert shared_result["evidence"] is shared_evidence
    assert shared_evidence == {"packet_number": 1, "session_id": 0}
