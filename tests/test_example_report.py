"""Machine gate REPORT-05: the example report generated from a slice of the
public 4SICS capture set (decision record `0005`).

The division this whole file rests on: EVERY test OTHER than the
reproducibility group runs without network access and without the downloaded
capture set - they check the artifacts already sitting in the repository
(`examples/4sics/*`) and the shape of the manifest entry. One test, the one
about reproducibility (group eight), needs the slice file on the machine and
is skipped with an explicit reason when it is absent. Without that division
this whole file would be skipped on a clean clone and the REPORT-05 gate would
not exist in practice.
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

# The constants of the fetch script and of the generator script are imported
# rather than duplicated - two copies of the same name or value would drift
# apart at the first correction (exactly as tests/test_standards_catalog.py
# imports the confidentiality gate from scripts/).
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import fetch_4sics_sample as fetch_sample  # noqa: E402
import gen_example_report as gen_report  # noqa: E402

# The functions extracting the text layer of a PDF and the regular expression
# extracting check identifiers are already module-level functions in
# tests/test_report_pdf.py - imported from there rather than extracted a second
# time (plan Task 3, 04-06-PLAN.md).
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


# --- Group one: existence and shape of the three artifacts -----------------


def test_three_artifacts_exist_and_have_nonzero_length():
    for path in (ANALYSIS_PATH, REPORT_MD_PATH, REPORT_PDF_PATH):
        assert path.is_file(), f"Artifact does not exist: {path}"
        assert path.stat().st_size > 0, f"Artifact has zero length: {path}"


def test_report_pdf_has_valid_format_signature():
    assert REPORT_PDF_PATH.read_bytes()[:5] == pdf_test_helpers.PDF_SIGNATURE


def test_analysis_json_has_at_least_one_finding():
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    assert len(analysis["findings"]) >= 1


# --- Group two: parity of the three artifacts ------------------------------


def test_check_id_set_is_identical_across_three_artifacts():
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    ids_from_model = {finding["check_id"] for finding in analysis["findings"]}

    report_text = REPORT_MD_PATH.read_text(encoding="utf-8")
    ids_from_markdown = set(pdf_test_helpers._check_ids_in_text(report_text))

    pdf_text = pdf_test_helpers._extract_text(REPORT_PDF_PATH.read_bytes())
    ids_from_pdf = set(pdf_test_helpers._check_ids_in_text(pdf_text))

    assert ids_from_model == ids_from_markdown == ids_from_pdf


# --- Group three: the normative layer of the example (the STD-03/STD-05 ----
# --- gate repeated over an artifact sitting in the repository rather than ---
# --- one generated during the test) -----------------------------------------


def _example_findings() -> list[dict]:
    import json

    analysis = json.loads(ANALYSIS_PATH.read_text(encoding="utf-8"))
    return analysis["findings"]


def test_every_finding_has_nonempty_standard_refs():
    for finding in _example_findings():
        assert finding["standard_refs"], (
            f"Finding {finding['check_id']} carries not a single citation."
        )


def test_every_finding_has_iec_62443_3_3_reference():
    for finding in _example_findings():
        standards = {ref["standard"] for ref in finding["standard_refs"]}
        assert "IEC-62443-3-3" in standards, (
            f"Finding {finding['check_id']} carries no IEC-62443-3-3 citation: {standards}"
        )


def test_every_reference_has_nonempty_edition():
    for finding in _example_findings():
        for ref in finding["standard_refs"]:
            assert ref["edition"], f"A citation of finding {finding['check_id']} has no edition."


# --- G-04-5: the analytical fact visible in the report itself, not only ----
# --- in the README ----------------------------------------------------------


def _endpoint_host(endpoint: str) -> str:
    """The address without the port, out of an endpoint of the form `address:port`."""
    return endpoint.rsplit(":", 1)[0]


def test_unauthenticated_industrial_protocol_findings_share_one_source_host_and_have_distinct_targets():
    """The machine record of the single analytical fact of this run (Task 3,
    04-09-PLAN.md): one host polling five different Modbus/TCP servers. The
    test reads a file from the repository, so it needs no slice file and has no
    skip condition - do not add one to it by analogy with the reproducibility
    test (group eight below).

    The comparison goes by the ADDRESS of the source host, not by the full
    `address:port` endpoint (a deviation found empirically in this task): the
    client opens a separate TCP connection to every server, so the ephemeral
    port differs between sessions despite the same IP address - that is normal
    TCP behaviour, not a defect. The analytical fact ("one host") concerns the
    host address, not the (address, port) tuple; the target pairs are compared
    as full endpoints, because it is PRECISELY the destination port (502) that
    tells them apart from the gateway port `44818` visible elsewhere in the
    communication matrix of the same run."""
    findings = [
        f for f in _example_findings() if f["check_id"] == "unauthenticated-industrial-protocol"
    ]
    assert len(findings) == 5

    source_hosts = {_endpoint_host(f["evidence"]["source"]) for f in findings}
    targets = {f["evidence"]["target"] for f in findings}
    assert len(source_hosts) == 1
    assert len(targets) == 5


def test_remediations_section_row_count_equals_distinct_remediation_count():
    """The number of rows of the aggregated remediation section equals the
    number of distinct remediations among the findings of this example - the
    number comes from the analysis file rather than from a constant typed here
    (which would drift at the first change to the set of checks)."""
    findings = _example_findings()
    expected_row_count = len({f["remediation"] for f in findings})

    report_text = REPORT_MD_PATH.read_text(encoding="utf-8")
    section = report_text.split("## Recommendations", 1)[1]
    rows = [line for line in section.splitlines() if line.startswith("- ")]

    assert len(rows) == expected_row_count
    assert len(rows) == len(set(rows)), rows


# --- Group four: the shape of the external capture set entry ---------------


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


# --- Group five: licence attribution (a gate on a licensing condition, ----
# --- not an editorial check) ------------------------------------------------


def test_attribution_string_present_in_both_readmes():
    entry = _external_dataset_entry()
    attribution = entry["attribution"].strip()
    example_readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    main_readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    # The manifest carries the text as a folded block (`>-`), the README
    # repeats it with arbitrary whitespace wrapping - the comparison happens
    # after collapsing every whitespace run into a single space, with one
    # source of truth (the manifest field) rather than a literal duplicated in
    # this test.
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
    # The description field of the manifest entry names the domain boundary
    # outright: the traffic does NOT come from a railway installation. The
    # presence of that string in the README of the example directory is
    # enough, read from the description field - not a literal duplicated in
    # this test. The comparison collapses whitespace (spaces and line
    # endings) to a single space - markdown wraps long sentences over several
    # lines, and that is a matter of typography, not of content.
    entry = _external_dataset_entry()
    description = entry["description"]
    marker = "NOT from a railway installation"
    assert marker in description, (
        "The manifest description field does not carry the domain boundary "
        "sentence"
    )
    example_readme = (EXAMPLE_DIR / "README.md").read_text(encoding="utf-8")
    assert marker in " ".join(example_readme.split())


# --- Group six: no capture in the tracked tree, the download directory -----
# --- ignored ----------------------------------------------------------------


def test_no_pcap_dump_file_tracked_outside_fixture_directory():
    tracked = _git_tracked_files()
    hits = [
        path
        for path in tracked
        if (path.endswith(".pcap") or path.endswith(".pcapng"))
        and not path.startswith("tests/fixtures/pcap/")
    ]
    assert hits == [], f"A capture file tracked outside the fixture directory: {hits}"


def test_dataset_download_directory_is_gitignored():
    # The trailing slash is required: without it `git check-ignore` over a
    # path that does not exist on disk yet (a clean clone, before the first run
    # of the fetch script) does not know whether the path is a directory and
    # returns a non-zero code regardless of the rule in .gitignore - measured
    # 2026-09-06; this test is meant to work on a clean clone too, not only
    # after the capture set has been downloaded.
    result = subprocess.run(
        ["git", "check-ignore", "-q", "datasets/"],
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, "The 'datasets' directory is not ignored by git"


# --- Group seven: the git attribute rules for the three artifacts ---------


def _git_check_attr(attribute: str, path: str) -> str:
    result = subprocess.run(
        ["git", "check-attr", attribute, "--", path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    # The output format: "path: attribute: value"
    return result.stdout.strip().rsplit(":", 1)[-1].strip()


def test_report_md_and_analysis_json_have_text_normalization_disabled():
    for rel_path in ("examples/4sics/report.md", "examples/4sics/analysis.json"):
        value = _git_check_attr("text", rel_path)
        assert value == "unset", f"{rel_path}: atrybut text = {value!r}, oczekiwano 'unset'"


def test_report_pdf_has_binary_attribute_set():
    value = _git_check_attr("binary", "examples/4sics/report.pdf")
    assert value == "set", f"report.pdf: atrybut binary = {value!r}, oczekiwano 'set'"


# --- Group eight: byte reproducibility, skipped conditionally --------------


def test_example_artifacts_are_byte_reproducible_from_slice(tmp_path):
    slice_path = fetch_sample.DATASET_DIR / fetch_sample.SLICE_FILENAME
    if not slice_path.is_file():
        pytest.skip(
            f"The slice file {slice_path} is not on this machine - build it "
            "with: uv run python scripts/fetch_4sics_sample.py"
        )

    analysis_path, report_path, pdf_path = gen_report.generate(slice_path, tmp_path)

    assert analysis_path.read_bytes() == ANALYSIS_PATH.read_bytes()
    assert report_path.read_bytes() == REPORT_MD_PATH.read_bytes()
    # The PDF contract: the byte determinism measurement of 04-03-SUMMARY.md
    # came out POSITIVE (two fixtures, four PYTHONHASHSEED values) - criterion
    # 5 of the phase demands no narrowing for the PDF, so the comparison goes
    # byte for byte just as it does for the two text artifacts.
    assert pdf_path.read_bytes() == REPORT_PDF_PATH.read_bytes()


# --- AST: no network dependency in this test file --------------------------


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
