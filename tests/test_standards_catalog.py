"""Gate for the standards catalogue: the paraphrase, the absence of verbatim
text, the provisional entry (STD-01, STD-02).

No test in this file contains a fragment of the text of a standard - the tests
examine shape and fields, never content. The violating line needed to prove
that `scan_text_structural` has teeth at all is ASSEMBLED at run time from
separate variables (the clause number, a modal term taken from
`guard.NORMATIVE_MODAL_TERMS`, padding for the length) - no single line of
this file's SOURCE carries both a dotted number and a normative modal term at
once, so the confidentiality gate does not trip on THE TEST FILE ITSELF and
there is no need to add it to `.confidentiality-allow` (that file warns that a
whole-path entry lifts the structural layer from the WHOLE file, including
content added later).
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

DEFAULT_ENTRY: dict = {
    "standard": "TEST-STANDARD",
    "edition": "2020",
    "clause": "T 1.1",
    "clause_title": "Test clause title",
    "clause_title_source": "own",
    "paraphrase": "A test paraphrase, never a quote of a standard.",
    "verified": False,
    "verification_note": "A test note, a provisional entry.",
}


def _write_catalog(
    catalog_root: Path,
    *,
    overrides: dict | None = None,
    remove_fields: list[str] | None = None,
) -> Path:
    """Writes one `catalog.yaml` with one entry under `catalog_root`. The
    shared logic is extracted so that the missing-field and empty-field cases
    call the same helper, the `tests/test_fixture_manifest.py` pattern."""
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


# --- The structural layer of the confidentiality gate, called over the ----
# --- content of the catalogue ---------------------------------------------


def test_scan_text_structural_returns_empty_list_for_catalog_content():
    text = CATALOG_PATH.read_text(encoding="utf-8")
    assert guard.scan_text_structural(text, str(CATALOG_PATH)) == []


def test_scan_text_structural_flags_composed_clause_and_modal_line():
    # Assembled from separate variables - see the module docstring. Not one of
    # these assignments carries a number and a modal term on the same line.
    clause_prefix = "12"
    clause_suffix = "3.4"
    clause_number = f"{clause_prefix}.{clause_suffix}"
    modal_term = guard.NORMATIVE_MODAL_TERMS[0]
    padding = "x" * guard.MIN_STRUCTURAL_FRAGMENT_LENGTH
    composed_line = clause_number + " " + modal_term + " " + padding

    violations = guard.scan_text_structural(composed_line, "composed-test-line")

    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_STRUCTURAL_CLAUSE_MODAL


# --- The shape of an entry in the real catalogue ---------------------------


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


# --- The schema contract over a temporary catalogue: a missing field and ---
# --- an empty one ---------------------------------------------------------


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
            # verified=False is legitimate, the only valid value of a
            # provisional entry - it must not be treated as a missing field.
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


# --- The new group: the gate on catalogue field types (STD-03, STD-05, -----
# --- G-04-2) --------------------------------------------------------------
#
# It closes the UAT gap G-04-2: an entry whose `verified` field was written as
# a string or a number loaded without an error, and `resolve` turned every
# non-empty string into `True` through `bool(...)`. The tests below prove the
# gate sits in the LOADING layer, not only in this test suite.


def test_load_catalog_rejects_verified_as_string(tmp_path):
    sub = tmp_path / "verified_string"
    _write_catalog(sub, overrides={"verified": "true"})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_verified_as_int(tmp_path):
    sub = tmp_path / "verified_int"
    _write_catalog(sub, overrides={"verified": 1})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_accepts_verified_true_without_raising(tmp_path):
    # clause_title_source has to be "copy" here - the cross-field rule of
    # G-04-3c rejects a raised `verified` with the `own` provenance.
    sub = tmp_path / "verified_true"
    _write_catalog(
        sub, overrides={"verified": True, "clause_title_source": "copy"}
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


# --- The new group: the provenance of a clause title (STD-03, G-04-3c) ----
#
# It closes the UAT gap G-04-3c: the catalogue carried no difference in its
# data between a title confirmed against a copy of the standard and a
# description of our own, so both rendered in the same shape.


def test_load_catalog_rejects_clause_title_source_outside_closed_set(tmp_path):
    sub = tmp_path / "clause_title_source_bad_value"
    _write_catalog(sub, overrides={"clause_title_source": "made-up"})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "made-up" in message
    assert "copy" in message
    assert "own" in message


def test_load_catalog_rejects_verified_true_with_clause_title_source_own(tmp_path):
    sub = tmp_path / "verified_true_own"
    _write_catalog(sub, overrides={"verified": True, "clause_title_source": "own"})

    with pytest.raises(mapper.StandardsError) as excinfo:
        mapper.load_catalog(catalog_root=sub)

    message = str(excinfo.value)
    assert "verified" in message
    assert "clause_title_source" in message


def test_load_catalog_accepts_verified_true_with_clause_title_source_copy(tmp_path):
    sub = tmp_path / "verified_true_copy"
    _write_catalog(
        sub, overrides={"verified": True, "clause_title_source": "copy"}
    )

    catalog = mapper.load_catalog(catalog_root=sub)

    assert catalog[("TEST-STANDARD", "T 1.1")]["clause_title_source"] == "copy"


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


# A probe entry with the wrong type in its verification field, written into
# the REAL package tree - the `probe_catalog_and_check` pattern of group seven
# below in this file. No check references that pair, so the mere presence of
# the file in the standards catalogue tree is enough to break `load_catalog()`
# on EVERY call (the scan is recursive over the whole `CATALOG_ROOT`).
BAD_TYPE_PROBE_DIR_NAME = "probe_bad_type_catalog"
BAD_TYPE_PROBE_DIR = STANDARDS_ROOT / BAD_TYPE_PROBE_DIR_NAME


def _write_bad_type_probe_catalog() -> None:
    _write_catalog(BAD_TYPE_PROBE_DIR, overrides={"verified": "true"})


def _remove_bad_type_probe_catalog() -> None:
    if BAD_TYPE_PROBE_DIR.exists():
        shutil.rmtree(BAD_TYPE_PROBE_DIR)


@pytest.fixture
def bad_type_probe_catalog():
    assert not BAD_TYPE_PROBE_DIR.exists(), (
        f"{BAD_TYPE_PROBE_DIR} already exists - an earlier test run did not "
        "clean up after itself."
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

    assert result.analysis["findings"], "The base fixture yielded not a single finding."
    total_refs = sum(len(f["standard_refs"]) for f in result.analysis["findings"])
    assert total_refs > 0

    provisional_marker_count = result.report_markdown.count(
        "PROVISIONAL, UNVERIFIED"
    )
    assert provisional_marker_count == total_refs


# --- Encoding: the artifact carries no escape sequence and does carry a ---
# --- paraphrase from the catalogue ----------------------------------------


def test_analysis_json_carries_no_escape_and_a_catalogue_paraphrase(tmp_path):
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
    assert "\\u" not in raw_text, "analysis.json carries an escaped \\uXXXX sequence"

    catalog = mapper.load_catalog()
    paraphrases = [entry["paraphrase"] for entry in catalog.values()]
    assert any(paraphrase in raw_text for paraphrase in paraphrases), (
        "analysis.json carries no paraphrase from the standards catalogue - "
        "the citation resolution path does not reach the artifact"
    )


# --- Helpers shared by groups 4 and 5 --------------------------------------


def analyzable_fixtures() -> list[Path]:
    """Every fixture of the directory whose analysis finishes without an
    exception. The pattern is copied from
    `tests/test_report_forbidden_phrases.py::_analyzable_fixtures` - the list is
    built by GLOB rather than by naming the files by hand, so that a new
    fixture falls under this gate without a change to this file."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def check_specs() -> list[dict]:
    """The raw dictionaries read from every YAML file under the checks
    directory, in the same sorted order as `engine.discover_checks`. Needed
    separately from check discovery: `CheckSpec.spec` carries the raw
    dictionary, but this gate also compares the edition field of every citation
    against the catalogue, which is more convenient over a raw dictionary than
    over a `CheckSpec` record."""
    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(engine.CHECKS_ROOT.rglob("*.yaml"))
    ]


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (the D-01 gate)")


def _dedupe_pairs(standards: list[dict]) -> list[tuple[str, str]]:
    """Removes repeated (standard, clause) pairs, keeping the FIRST occurrence
    - a mirror of `engine._dedupe_standards`, but returning the pairs alone for
    comparison with the citation order of a finding, not the full
    dictionaries."""
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []
    for entry in standards:
        key = (entry["standard"], entry["clause"])
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


# --- Group four: the STD-03/STD-05 contract over EVERY finding of EVERY ---
# --- analyzable fixture ---------------------------------------------------


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_finding_has_nonempty_standard_refs(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        assert finding["standard_refs"], (
            f"Finding {finding['check_id']} in {fixture.name} carries not a "
            "single citation."
        )


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_finding_has_iec_62443_3_3_reference(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        standards = {ref["standard"] for ref in finding["standard_refs"]}
        assert "IEC-62443-3-3" in standards, (
            f"Finding {finding['check_id']} in {fixture.name} carries no "
            f"IEC-62443-3-3 citation: {standards}"
        )


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_every_reference_has_nonempty_edition_clause_and_title(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    for finding in result.analysis["findings"]:
        for ref in finding["standard_refs"]:
            assert ref["edition"], f"A citation of finding {finding['check_id']} has no edition."
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
    """An edge probe: the set of citation counts occurring in the findings of
    every analyzable fixture contains at least the value one and does not
    contain zero. Since plan 04-05 that same test also sees the value two and
    passes unchanged, because the condition is the absence of zero rather than
    a particular number - do not pin this test to a number that changes in the
    next plan."""
    counts: set[int] = set()
    for i, fixture in enumerate(analyzable_fixtures()):
        try:
            result = analyze(fixture, out_dir=tmp_path / f"f{i}", generated_at=GENERATED_AT)
        except (CaptureTruncatedError, CaptureFormatError):
            continue
        for finding in result.analysis["findings"]:
            counts.add(len(finding["standard_refs"]))

    assert 0 not in counts
    assert counts, "No fixture yielded a single finding."


# --- Group five: the contract over the check files and over the ------------
# --- standards catalogue --------------------------------------------------


def test_every_check_file_has_nonempty_standards_list():
    for spec in check_specs():
        assert spec.get("standards"), f"Check {spec.get('id')} has no citation list."


def test_every_check_reference_resolves_against_catalog():
    zone_model = zones.build_zone_model(
        observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp"]
    )
    for spec in check_specs():
        for ref in spec["standards"]:
            # The absence of an exception is the whole content of this test -
            # `resolve` raises `StandardsError` when the (standard, clause) pair
            # is not in the catalogue.
            mapper.resolve(ref["standard"], ref["clause"], zone_model=zone_model)


def test_check_reference_edition_matches_catalog_edition():
    catalog = mapper.load_catalog()
    for spec in check_specs():
        for ref in spec["standards"]:
            catalog_entry = catalog[(ref["standard"], ref["clause"])]
            assert ref["edition"] == catalog_entry["edition"], (
                f"Check {spec['id']}: the edition {ref['edition']!r} in the check "
                f"file drifts from the catalogue edition "
                f"{catalog_entry['edition']!r} for {ref['standard']} {ref['clause']}."
            )


# --- Probe checks over a temporary catalogue: an empty or missing schema ---
# --- and the deduplication and order of citations in a finding ------------

CHECK_SPEC_DEFAULTS: dict = {
    "id": "probe-std-check",
    "title": "Probe check of the STD-03 gate",
    "applies_to": {"protocol": "modbus-tcp"},
    "severity": "high",
    "rationale": "Our own test rationale, never a quote of a standard.",
    "standards": [{"standard": "IEC-62443-3-3", "edition": "2013", "clause": "SR 1.1"}],
    "evaluator": "probe:evaluate",
    "remediation": "A test remediation, used nowhere but in this test.",
}

# An evaluator returning exactly one finding from the first event - used by
# the citation deduplication and ordering tests, which do not care about
# the logic of a check, only that a finding came into being at all. The
# `tests/test_check_engine.py::EVALUATOR_ONE_FINDING_SOURCE` pattern.
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
    """Writes one probe check (the YAML plus its sibling evaluator) under
    `checks_dir/subdir`. The `tests/test_check_engine.py::_write_check`
    pattern, written out here rather than imported between test files - an
    import of one test module from another is a fragile dependency on the order
    in which pytest collects tests."""
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


# --- Group six: the duplicate pair contract and the loading edge cases ----
# --- across two catalogue files -------------------------------------------


def _write_catalog_pair(
    root: Path, *, first: dict, second: dict
) -> tuple[Path, Path]:
    """Writes TWO `catalog.yaml` files, each in a SEPARATE subdirectory of one
    temporary directory, so that the recursive scan of `load_catalog` finds
    both. Returns both paths, in the alphabetical order of the subdirectories
    (`a`, `b`), that is in the same order `sorted(rglob(...))` reads them."""
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


# An entry with an empty edition field: a case already covered by
# `test_load_catalog_rejects_empty_string_field_same_as_missing`, which
# iterates over ALL of `REQUIRED_CATALOG_FIELDS` (edition included) - not
# duplicated here.


def test_load_catalog_scan_order_is_identical_across_two_scans(tmp_path):
    _write_catalog_pair(
        tmp_path,
        first={"standard": "TEST-STANDARD", "clause": "T 1.1"},
        second={"standard": "TEST-STANDARD", "clause": "T 2.2"},
    )

    first_scan = list(mapper.load_catalog(catalog_root=tmp_path).keys())
    second_scan = list(mapper.load_catalog(catalog_root=tmp_path).keys())

    assert first_scan == second_scan


# --- Group seven: the zero-code-change gate (criterion 4 of the phase) ----
#
# The model is `tests/test_check_engine.py::test_new_check_discovered_without_engine_change`,
# line for line: a probe file written into the REAL standards catalogue
# (`src/wayside/standards/`), not into `tmp_path` - that is exactly what proves
# criterion 4 of the phase (a second standard enters as a data file, without a
# change to any `.py` file under the package directory). The name of the probe
# subdirectory is CONSTANT, not random - a failed earlier run would leave a
# trace changing the result of other tests (the same reason as in
# `test_check_engine.py`).

PACKAGE_ROOT = REPO_ROOT / "src" / "wayside"
PROBE_CATALOG_DIR_NAME = "probe_extensibility_catalog"
PROBE_CATALOG_DIR = STANDARDS_ROOT / PROBE_CATALOG_DIR_NAME
PROBE_STANDARD = "TEST-STANDARD-PROBE"
PROBE_CLAUSE = "T 9.9"
PROBE_CATALOG_ENTRY: dict = {
    "standard": PROBE_STANDARD,
    "edition": "9999",
    "clause": PROBE_CLAUSE,
    "clause_title": "Probe clause title of the standards catalogue extensibility gate",
    "clause_title_source": "own",
    "paraphrase": "A test paraphrase of the standards catalogue extensibility gate, never a quote of a standard.",
    "verified": False,
    "verification_note": "A probe entry, used only by the extensibility gate test.",
}

# The probe check is appended to the citation list of ONE real check -
# without that the probe pair has no way into a finding.
# `modbus-unauthenticated-write` fits, because the base Modbus fixture yields
# exactly one finding of that check.
PROBE_TARGET_CHECK_YAML = (
    REPO_ROOT / "src" / "wayside" / "checks" / "modbus" / "unauthenticated_write.yaml"
)
# Bytes, not text: on Windows `Path.write_text` translates `\n` into `\r\n` on
# write (the default `newline=None`), so restoring through text changes the
# line endings of a git-tracked file from LF to CRLF - an apparent but real
# modification visible in `git status`. The restore goes through BYTES ONLY, so
# as to be bit identical to the original regardless of the platform.
_PROBE_TARGET_ORIGINAL_BYTES = PROBE_TARGET_CHECK_YAML.read_bytes()
_PROBE_TARGET_ORIGINAL_TEXT = _PROBE_TARGET_ORIGINAL_BYTES.decode("utf-8")


def _package_python_files() -> list[Path]:
    """Every file with the `.py` extension under the package directory,
    recursively, skipping the directories of compiled cache files."""
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
    """Cleans up both traces (the probe catalogue, the content of the check
    file) even when an error occurred before control was handed to the test -
    the `tests/test_check_engine.py::_cleanup_probe_check_dir_after_module`
    pattern."""
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
        f"{PROBE_CATALOG_DIR} already exists - an earlier test run did not "
        "clean up after itself."
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
        f"Changed files: {changed}; added or removed files: {added_or_removed}"
    )

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    probe_refs = [
        ref
        for finding in analysis["findings"]
        for ref in finding["standard_refs"]
        if ref["standard"] == PROBE_STANDARD and ref["clause"] == PROBE_CLAUSE
    ]
    assert probe_refs, "the probe citation pair did not appear in analysis.json"

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert PROBE_STANDARD in report_text, "report.md does not mention the probe designation"


def test_probe_catalog_and_check_leave_no_trace_after_cleanup(tmp_path):
    """Without this test the gate would prove that a data file enters, not that
    it leaves without a trace - and the latter is the condition for the rest of
    the suite (`test_reference_count_boundary_never_zero_across_all_fixtures`
    included) to keep counting what it counts. It runs after the
    function-scoped `probe_catalog_and_check` has already cleaned up in its
    `finally` block following the previous test - pytest runs the tests of this
    file in the order they are written."""
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"

    assert not PROBE_CATALOG_DIR.exists(), (
        "the probe catalogue still exists - the order of the tests in this "
        "module is broken."
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
    """The precision edge case: no `.py` file under the directory of the
    normative layer calls a conversion to an integer or to a floating point
    number - there is not one such conversion on the citation path, which is
    CHECKED here over the syntax tree rather than assumed."""
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
