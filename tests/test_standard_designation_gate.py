"""Machine gate for decision record `0004` (the CLC/TS 50701 designation) and
record `0006` (verification of citations against a copy of the standard).

Decision record `0004`, in its enforcement section, states outright: a machine
gate for that decision DOES NOT EXIST at the moment it is written and comes
into being together with the plan of this phase. This file is that gate.

The value of `FORBIDDEN_DESIGNATION` is TAKEN from the rejected alternatives
section of record `0004` rather than typed from memory - the record is the
source of truth for what the gate is to forbid.

**The gate also covers the binary files tracked by git within the scan scope**
(plan `04-07`, closing WR-03 of `04-VERIFICATION.md`). The text scan
`_scan_tree_for_designation` skips every file unreadable as UTF-8 - exactly
the route through which `examples/4sics/report.pdf` fell out of the gate's
reach despite being tracked by git. `BINARY_SCAN_TARGETS` declares by name the
search strategy for every such file, and the completeness test turns red on
every undeclared binary file. Plan `04-03` (the PDF export) landed 2026-09-05,
so `wayside.report_pdf` and `pypdf` are dependencies of this tree today -
both imports are unconditional, there is no longer any silent-skip path in
this module.
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

# The expected value of the `resolved_option` field from the frontmatter of
# the decision record above. The first test reads the frontmatter and compares
# it against this constant - without that the gate is not tied to the record
# and would stop making sense on the day the record is revised, without
# noticing.
EXPECTED_RESOLVED_OPTION = "clc-ts-50701-2023"

# Taken from the rejected alternatives section of record 0004: "`EN 50701`
# without a year (rejected, because it cites a document that does not
# exist...)" - the form without a year, exactly as it stands there.
FORBIDDEN_DESIGNATION = "EN 50701"

# The documents directory, the planning directory and the tests directory are
# OUT of scope, each for its own reason:
# - docs/decisions/ has to be free to name the rejected designation (record
#   0004 quotes it itself in its rejected alternatives section);
# - .planning/ carries planning notes, among them STATE.md and the phase
#   research, which also quote the rejected designation as a record of the
#   state of knowledge before the correction (the same reason as in
#   tests/test_no_external_dissector.py);
# - tests/ carries this very file, which has to be free to carry the
#   FORBIDDEN_DESIGNATION constant as a PYTHON VALUE rather than as prose -
#   were this directory in scope, this file would break its own gate.
SCAN_SCOPE: tuple[str, ...] = ("src", "scripts", "examples", "README.md")

# The CENELEC technical specification part of the designation - every
# standards catalogue entry starting with it is meant to carry the edition
# year, because the two editions of that document differ in content (record
# 0004, the enforcement section).
RAILWAY_STANDARD_PREFIX = "CLC/TS"
EXPECTED_RAILWAY_EDITION = "2023"

_RESOLVED_OPTION_RE = re.compile(r"^resolved_option:\s*(\S+)\s*$", re.MULTILINE)


# --- Test one: the resolution field of the record 0004 frontmatter --------


def test_decision_record_resolved_option_matches_expected():
    text = DECISION_RECORD_PATH.read_text(encoding="utf-8")
    match = _RESOLVED_OPTION_RE.search(text)
    assert match is not None, (
        f"The decision record {DECISION_RECORD_PATH} carries no "
        "'resolved_option' field in its frontmatter."
    )
    assert match.group(1) == EXPECTED_RESOLVED_OPTION, (
        f"The 'resolved_option' field of record {DECISION_RECORD_PATH} carries "
        f"{match.group(1)!r}, expected {EXPECTED_RESOLVED_OPTION!r}."
    )


# --- Helpers shared by the tests below -------------------------------------
#
# The tree scan pattern is copied from
# tests/test_no_external_dissector.py::scan_tree - case-insensitive substring
# matching, files undecodable as text skipped.


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
    # The message carries the path and the line number, never the content of
    # the line - the same discipline as in tests/test_standards_catalog.py and
    # scripts/confidentiality_guard.py.
    return "\n".join(f"  {path}:{line}" for path, line in hits)


def analyzable_fixtures() -> list[Path]:
    """Every fixture of the directory whose analysis finishes without an
    exception. The `tests/test_standards_catalog.py::analyzable_fixtures`
    pattern."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (the D-01 gate)")


# --- Test two: no rejected designation in the code, the scripts, ----------
# --- the examples and the README --------------------------------------------


def test_scan_scope_carries_no_forbidden_designation():
    hits = _scan_scope_for_designation(FORBIDDEN_DESIGNATION)
    assert hits == [], (
        f"The designation rejected in decision record {DECISION_RECORD_PATH} "
        f"found in:\n{_format_hits(hits)}"
    )


# --- Test three: no rejected designation in the rendered markdown report --
# --- of every analyzable fixture --------------------------------------------


@pytest.mark.parametrize("fixture", analyzable_fixtures(), ids=lambda p: p.name)
def test_rendered_report_carries_no_forbidden_designation(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    assert FORBIDDEN_DESIGNATION not in result.report_markdown, (
        f"{fixture.name}: the markdown report carries the designation rejected "
        f"in decision record {DECISION_RECORD_PATH}."
    )


# --- Test four: no rejected designation in the PDF text layer -------------


def test_pdf_text_layer_carries_no_forbidden_designation(tmp_path):
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    result = _analyze_or_skip(fixture, tmp_path)

    pdf_bytes = report_pdf.render_pdf(
        result.analysis, generated_at=GENERATED_AT, warnings=result.warnings
    )
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert FORBIDDEN_DESIGNATION not in text, (
        "The text layer of the PDF file carries the designation rejected in "
        f"decision record {DECISION_RECORD_PATH}."
    )


# --- Test five: every standards catalogue entry with a technical ----------
# --- specification designation carries the expected edition -----------------


def test_every_railway_catalog_entry_has_expected_edition():
    catalog = mapper.load_catalog()
    railway_entries = {
        key: entry
        for key, entry in catalog.items()
        if key[0].startswith(RAILWAY_STANDARD_PREFIX)
    }
    assert railway_entries, (
        f"No standards catalogue entry starts with {RAILWAY_STANDARD_PREFIX!r} "
        "- the gate has nothing to guard."
    )
    for key, entry in railway_entries.items():
        assert entry["edition"] == EXPECTED_RAILWAY_EDITION, (
            f"Entry {key} carries the edition {entry['edition']!r}, expected "
            f"{EXPECTED_RAILWAY_EDITION!r}."
        )


# --- Test six: the decision record directory with no numeric prefix clash -


def test_decision_records_have_no_colliding_numeric_prefix():
    names = [p.name for p in (REPO_ROOT / "docs" / "decisions").glob("*.md")]
    prefixes = [re.match(r"^(\d+)", name).group(1) for name in names]
    assert len(set(prefixes)) == len(prefixes), (
        f"A numeric prefix clash in the decision record directory: {sorted(names)}"
    )


# --- The README group (Task 3): the section on the verification status of --
# --- citations of standards -------------------------------------------------
#
# That section is NOT PUB-03 (Intended Use, Phase 5) - it is a small section of
# this phase's own. It is extracted by its header, following
# tests/test_report_forbidden_phrases.py::_section_body, so that the test
# checks the presence of the strings IN ITS BODY rather than across the whole
# README - a test over the whole file would pass even if those strings stood in
# another section.

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
    raise AssertionError(f"The README has no '{header}' section")


def test_readme_has_standard_verification_section_header():
    text = README_PATH.read_text(encoding="utf-8")
    assert README_SECTION_HEADER in text


def test_readme_verification_section_carries_verification_marker():
    body = _readme_section_body(README_SECTION_HEADER)
    assert VERIFICATION_MARKER_STRING in body, (
        "The README verification status section does not carry the "
        f"verification marker string {VERIFICATION_MARKER_STRING!r} in the "
        "exact form it takes in the catalogue file."
    )


def test_readme_verification_section_links_both_decision_records():
    body = _readme_section_body(README_SECTION_HEADER)
    assert "0004-clc-ts-50701-designation.md" in body
    assert "0006-verification-of-citations-against-a-copy-of-the-standard.md" in body


# --- The new group (plan 04-07): the gate covers the binary files tracked --
# --- by git within the scan scope, WR-03 of 04-VERIFICATION.md --------------
#
# A tracked binary file within the scan scope is searchable either through its
# text layer or through its raw bytes - there is no third possibility and no
# exclusion list (assumption Z-79). An exclusion list is exactly the mechanism
# through which `examples/4sics/report.pdf` fell out of this gate's reach.
BINARY_SCAN_TARGETS: dict[str, str] = {
    "examples/4sics/report.pdf": "pdf-text",
    "src/wayside/assets/fonts/DejaVuSans.ttf": "raw-bytes",
    "src/wayside/assets/fonts/DejaVuSans-Bold.ttf": "raw-bytes",
}


def _tracked_files_in_scope() -> list[Path]:
    """The files TRACKED by git within `SCAN_SCOPE`, not the files sitting on
    disk (assumption Z-78): the working tree carries directories of compiled
    intermediate code which are not in the repository, and the question of
    decision record `0004` concerns the contents of the repository. A non-zero
    git exit code ends this test as a failure carrying the error output, never
    as a skip - the `tests/test_example_report.py::_git_tracked_files`
    pattern."""
    result = subprocess.run(
        ["git", "ls-files", "--", *SCAN_SCOPE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"git ls-files exited with code {result.returncode}: {result.stderr}"
    )
    return [REPO_ROOT / line for line in result.stdout.splitlines() if line]


def _undecodable_tracked_files() -> list[Path]:
    """Out of the files tracked within the scan scope, exactly those whose
    attempted read as UTF-8 text ends in a decoding error - that is, exactly
    the set `_scan_tree_for_designation` silently skips today."""
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
        "Undeclared binary files tracked by git: "
        f"{undeclared}; declared paths with no corresponding file: "
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
    assert target.is_file(), f"The declared file does not exist: {relative_path}"

    if strategy == "pdf-text":
        reader = pypdf.PdfReader(str(target))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        assert not _FORBIDDEN_PATTERN.search(text), (
            f"{relative_path}: the text layer carries the rejected designation "
            f"(strategy {strategy!r})."
        )
    elif strategy == "raw-bytes":
        # Two encodings: ASCII and UTF-16BE - the name table of a font file
        # (the `name` table of the TrueType/OpenType format) holds its strings
        # in UTF-16BE on the Microsoft platform.
        data = target.read_bytes()
        ascii_needle = FORBIDDEN_DESIGNATION.encode("ascii")
        utf16be_needle = FORBIDDEN_DESIGNATION.encode("utf-16-be")
        assert ascii_needle not in data, (
            f"{relative_path}: the ASCII bytes carry the rejected designation "
            f"(strategy {strategy!r})."
        )
        assert utf16be_needle not in data, (
            f"{relative_path}: the UTF-16BE bytes carry the rejected designation "
            f"(strategy {strategy!r})."
        )
    else:  # pragma: no cover - a guard against a third strategy
        raise AssertionError(f"Unknown search strategy: {strategy!r}")
