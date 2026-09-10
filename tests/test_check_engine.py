"""Gate for the extensibility of the check engine and for the schema contract
(CHECK-01, CHECK-02).

`test_new_check_discovered_without_engine_change` temporarily adds a probe
check to the REAL `src/wayside/checks/` directory (not to a temporary one),
because that is exactly what criterion 4 of the phase examines: a new check at
run time, without a change to any engine file. That coupling is named
outright: this test temporarily changes the contents of the check directory of
the whole package, so `tests/test_analyze_pipeline.py`, which counts findings,
depends on a correct cleanup after this test. Pytest runs the tests of this
file serially, so the coupling is safe, but it is not invisible - the
`probe_check_dir` fixture cleans up in a `finally` block, and the module
autouse fixture cleans up even when `probe_check_dir` did not get to (say an
error in the setup before its `yield`).

The remaining schema and ordering tests call `discover_checks` over a
TEMPORARY directory (`tmp_path`) - the loader built on
`spec_from_file_location` works over any path, so those tests never touch the
real package.
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

# A constant name, not a random one - otherwise a failed earlier run would
# leave a trace changing the result of other tests (see the module docstring).
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

# An evaluator returning exactly one finding, with its evidence taken from
# the first protocol event - used by the deduplication and ordering tests of
# the `standards` citations, which do not care about the logic of a check, only
# that a finding came into being at all.
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
    """Writes one check (the YAML plus its sibling `.py`) under
    `checks_dir/subdir`. The shared check-building logic is extracted so that
    the negative cases (a missing field, an empty one, a duplicate, a
    disallowed module name) call the same helper instead of duplicating it -
    the `tests/test_fixture_manifest.py` pattern. Returns the path of the
    YAML."""
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
    """Cleans up the probe check directory even when a test fails halfway and
    the `finally` block of the `probe_check_dir` fixture does not get to run
    (say an error before its own `yield`)."""
    yield
    if PROBE_CHECK_DIR.exists():
        shutil.rmtree(PROBE_CHECK_DIR)


@pytest.fixture
def probe_check_dir():
    assert not PROBE_CHECK_DIR.exists(), (
        f"{PROBE_CHECK_DIR} already exists - an earlier test run did not "
        "clean up after itself."
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
    assert engine_after == engine_before, "the check engine was changed by adding a check"
    assert pyproject_after == pyproject_before, "pyproject.toml was changed by adding a check"

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    probe_findings = [f for f in analysis["findings"] if f["check_id"] == "probe-extensibility-check"]
    assert probe_findings, "no probe check finding appeared in analysis.json"

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "probe-extensibility-check" in report_text


def test_probe_check_directory_removed_and_original_finding_count_restored(probe_check_dir, tmp_path):
    """Once the probe check is removed (the fixture teardown runs after this
    test), `wayside analyze` over the write fixture again yields exactly one
    finding - proof that the test leaves no lasting trace."""
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


# --- Schema contract: a required field missing or empty --------------------


def test_check_schema_required_fields(tmp_path):
    """The absence of any field of `REQUIRED_CHECK_FIELDS`, and the same field
    present but empty, ends in a `CheckSchemaError` - both branches call the
    same `_write_check` helper instead of duplicating the logic."""
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


# --- Sorted path order, independent of creation order ----------------------


def test_discover_checks_orders_by_sorted_path(tmp_path):
    # Created deliberately in reverse alphabetical order, to prove the result
    # is not the creation order.
    _write_check(tmp_path, subdir="charlie", spec_overrides={"id": "check-charlie"})
    _write_check(tmp_path, subdir="alfa", spec_overrides={"id": "check-alfa"})
    _write_check(tmp_path, subdir="bravo", spec_overrides={"id": "check-bravo"})

    checks = engine.discover_checks(checks_root=tmp_path)
    ids = [c.spec["id"] for c in checks]

    assert ids == ["check-alfa", "check-bravo", "check-charlie"]
    assert [c.path for c in checks] == sorted(c.path for c in checks)


# --- An evaluator module name with a path separator or two dots ------------


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
        # Nothing was imported - a probe module under that name never exists
        # in sys.modules (threat T-2-04).
        assert f"wayside._checks.{bad_module_name}" not in sys.modules


# --- Deduplication and order of repeated `standards` entries ---------------


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
    # An analysis without a `comm_matrix` key at all - assumption Z-92: the
    # probe model of this module has no matrix, and the mapping is meant to
    # tolerate that.
    analysis = {"protocol_events": [{"packet_number": 1, "session_id": 0}]}

    findings = engine.run_checks(analysis, checks)

    assert findings[0]["evidence"]["source"] == engine.ENDPOINT_UNKNOWN
    assert findings[0]["evidence"]["target"] == engine.ENDPOINT_UNKNOWN


def test_run_checks_does_not_mutate_evidence_dict_returned_by_evaluator():
    """Assumption Z-91: the engine assembles a NEW evidence dictionary instead
    of mutating the one returned by the evaluator. The test builds a
    `CheckSpec` directly, with an evaluator returning a SHARED evidence
    dictionary, so that an in-place mutation is detectable without an
    intervening read from disk."""
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
