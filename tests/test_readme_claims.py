"""Gate for the README claim catalogue (PUB-03, PUB-04).

Which decision each group of assertions carries out:

- D-14: `compliance/readme-claims.yaml` is an artifact checked mechanically,
  not a one-off review written in markdown.
- D-15: the shape of a catalogue entry (`id`, `claim`, `readme_anchor`,
  `evidence`, `reason`, `status`).
- D-16: the gate carries THREE assertions - (a) every entry has a non-empty
  `evidence`, (b) every `evidence` that is not manual evidence is present in
  the pytest collection gathered by `--collect-only`, (c) every `##` header of
  the README has either an entry or an explicit exclusion in that same file.
  Task 1 introduced assertions (a) and (b) together with the shape gate of the
  `## Intended Use` section (D-10, D-11, D-12). **Task 2 adds assertion (c)**,
  its converse against dead entries, the handling of the `retired` status, and
  the gate on the ASCII-only orthography of the README (D-13).
- D-17: manual evidence (`evidence == MANUAL_EVIDENCE`) is admissible only
  with a non-empty `reason` field.

The second-level header expression (`_HEADER_LINE_RE`) is copied verbatim from
`tests/test_standard_designation_gate.py` - one statement of that rule in the
repository, not two.

The module writes and changes no file in the repository tree - the negative
cases of the catalogue and of the section are built in memory, never by
writing to a file in this tree (see
`test_module_source_contains_no_file_write_calls` at the end of the file).
"""

from __future__ import annotations

import inspect
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

# The sibling gate inserts `tests/` into sys.path explicitly, as a belt and
# braces measure (the `tests/test_example_report.py` pattern), rather than
# relying solely on the insertion pytest performs for this module's OWN
# directory.
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

# One source of truth for the predicate over characters outside ASCII, shared
# with the INVERSE rule for the report (tests/test_report_orthography.py):
# a direct import rather than a copy of the value -
# `test_readme_claims.non_ascii_chars is
# test_report_orthography.non_ascii_chars` has to hold.
from test_report_orthography import non_ascii_chars  # noqa: E402

CATALOG_PATH = REPO_ROOT / "compliance" / "readme-claims.yaml"
README_PATH = REPO_ROOT / "README.md"

MANUAL_EVIDENCE = "manual"
ALLOWED_STATUS: frozenset[str] = frozenset({"active", "retired"})

INTENDED_USE_HEADER = "## Intended Use"
REQUIRED_INTENDED_USE_SUBSECTIONS: tuple[str, ...] = (
    "### What it is for",
    "### What it is not for",
    "### Condition of use",
)
PASSIVITY_EVIDENCE_NODE_ID = (
    "tests/test_oui.py::test_no_network_module_imports_under_src_wayside"
)

# Boundary sentences from D-11 and D-12, copied verbatim into the README
# text - one statement of both rules, used at once as document content and as
# the criterion of the shape gate.
PASSIVITY_BOUNDARY_MARKER = (
    "the gate guards imports in the source code, not the actual absence of "
    "traffic at runtime"
)
NETWORK_OWNER_CONSENT_MARKER = (
    "may be analysed only with the consent of the owner of that network"
)
NETWORK_OWNER_NO_CHECK_MARKER = (
    "the tool does not check that consent and cannot check it"
)

# Copied verbatim from tests/test_standard_designation_gate.py.
_HEADER_LINE_RE = re.compile(r"^## .+$", re.MULTILINE)


# --- Shared helpers (the <interfaces> block of plan 05-01) -----------------


def _load_catalog() -> dict:
    """Loads the claim catalogue with the safe YAML parser. A missing
    `entries` key, or an empty list, ends in an assertion failure whose message
    names the file and the missing key - not in a silent return of an empty
    list, after which every loop passes trivially (row E-08 of the edge probe:
    an empty catalogue is not a green run)."""
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
    entries = raw.get("entries")
    assert entries, (
        f"{CATALOG_PATH} carries no 'entries' key, or the list is empty."
    )
    return raw


def _entries(*, active_only: bool = True) -> list[dict]:
    entries = _load_catalog()["entries"]
    if active_only:
        return [e for e in entries if e.get("status") == "active"]
    return list(entries)


def _readme_text() -> str:
    return README_PATH.read_text(encoding="utf-8")


def _section_body(text: str, header: str) -> str:
    """The body of the `header` section in `text`, from the end of the header
    line to the start of the next second-level header (or the end of the text).
    It works over ANY text, not only over the README - the negative cases built
    in memory pass a probe text in here, never a file on disk."""
    headers = list(_HEADER_LINE_RE.finditer(text))
    for index, match in enumerate(headers):
        if match.group(0).strip() != header:
            continue
        start = match.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        return text[start:end]
    raise AssertionError(f"The text has no '{header}' section")


def _readme_section_body(header: str) -> str:
    return _section_body(_readme_text(), header)


def _readme_anchors() -> list[str]:
    """The list of second-level README headers, in order of appearance,
    without the hash characters and without the leading space (matching the
    shape of the `readme_anchor` field of D-15)."""
    return [
        match.group(0)[3:].strip()
        for match in _HEADER_LINE_RE.finditer(_readme_text())
    ]


def _excluded_anchors() -> dict[str, str]:
    """A mapping of an excluded header onto its reason, read from the
    catalogue on disk."""
    raw = _load_catalog()
    return {
        item.get("anchor"): item.get("reason", "")
        for item in (raw.get("excluded_anchors") or [])
    }


_collected_test_ids_cache: frozenset[str] | None = None


def _collected_test_ids() -> frozenset[str]:
    """Collects the test identifiers from `pytest --collect-only` in a
    subprocess of the current interpreter, from the repository root.

    Two explicit overrides, each with its reason:

    - `-o addopts=` zeroes the default options from `pyproject.toml`. Plan
      `05-04` introduces a default marker filter (`-m "not slow"`) which
      shrinks the collection - without this override an evidence pointing at a
      test carrying the `slow` marker would turn red with no change to the
      content of the claim at all (assumption Z-83).
    - `-p no:cacheprovider` disables writing to `.pytest_cache` from this
      subprocess. This gate is meant to write nothing into the repository tree
      (row E-06 of the edge probe); two parallel runs of the suite would write
      differently into the same cache directory.

    The result is memoized in a module variable after the first call. The
    function is NOT called at module import time, because the collection
    subprocess imports this same module - a call at import time would call
    itself recursively.
    """
    global _collected_test_ids_cache
    if _collected_test_ids_cache is not None:
        return _collected_test_ids_cache

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    ids: set[str] = set()
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "::" not in stripped:
            continue
        # The pytest identifiers use a forward slash, but we do not assume
        # that - we normalize the path separator, so that the result stays
        # stable on a machine that happens to print a backslash.
        ids.add(stripped.replace("\\", "/"))

    _collected_test_ids_cache = frozenset(ids)
    return _collected_test_ids_cache


def _evidence_is_collected(evidence: str, collected: frozenset[str]) -> bool:
    """True when `evidence` is in the collection verbatim, or when the
    collection carries an identifier starting with `evidence` and the opening
    square bracket of a parameter (assumption Z-84: tests parametrized over the
    pcap fixtures are the rule in this repository, and the number of cases grows
    with every new fixture, so recording an evidence by a single case would age
    by itself)."""
    if evidence in collected:
        return True
    prefix = f"{evidence}["
    return any(cid.startswith(prefix) for cid in collected)


# --- Assertions D-16 (a) and (b), plus D-17 --------------------------------


def _entry_errors(catalog: dict, collected: frozenset[str]) -> list[str]:
    """The list of failures of assertion (a) [non-empty `evidence`], (b)
    [evidence present in the collection] and D-17 [manual evidence requires a
    non-empty `reason`], in the order the entries appear in the `entries` list
    (row E-09 of the edge probe). It works over ANY dictionary in memory - the
    negative catalogue cases do NOT modify the file in the tree."""
    entries = catalog.get("entries")
    assert entries, "The catalogue carries no entries (no 'entries' key, or an empty list)."

    errors: list[str] = []
    seen_ids: set[str] = set()
    for entry in entries:
        entry_id = entry.get("id", "<no id>")
        if entry_id in seen_ids:
            errors.append(f"{entry_id}: duplicate entry identifier.")
        seen_ids.add(entry_id)

        status = entry.get("status")
        if status not in ALLOWED_STATUS:
            errors.append(
                f"{entry_id}: status {status!r} outside the allowed set "
                f"{sorted(ALLOWED_STATUS)}."
            )

        evidence = entry.get("evidence")
        if not evidence:
            errors.append(f"{entry_id}: empty 'evidence' field.")
            continue

        if evidence == MANUAL_EVIDENCE:
            if not (entry.get("reason") or "").strip():
                errors.append(f"{entry_id}: manual evidence without a non-empty 'reason' field.")
            continue

        if status == "retired":
            # A retired entry is not checked against the collection (task 2).
            continue

        if not _evidence_is_collected(evidence, collected):
            errors.append(f"{entry_id}: evidence {evidence!r} absent from the pytest collection.")

    return errors


# --- Assertion D-16 (c): completeness of header coverage, plus its converse ---


def _completeness_errors(catalog: dict, readme_headers: list[str]) -> list[str]:
    """Assertion (c) of D-16 [every header has an active entry or an explicit
    exclusion] together with its converse against dead entries [every entry and
    every exclusion points at a header that really exists in the README] and
    with the third sub-point of D-16 about a non-empty exclusion reason. It
    works over ANY catalogue dictionary and ANY list of headers in memory - the
    negative catalogue cases do NOT modify the file in the tree.

    The failures about missing coverage are listed in the order the header
    appears in `readme_headers` (row E-09 of the edge probe)."""
    entries = catalog.get("entries") or []
    excluded = catalog.get("excluded_anchors")
    if excluded is None:
        excluded = []

    errors: list[str] = []

    excluded_map: dict[str, str] = {}
    for item in excluded:
        anchor = item.get("anchor")
        reason = (item.get("reason") or "").strip()
        if not reason:
            errors.append(f"The exclusion of header {anchor!r} has an empty 'reason' field.")
        if anchor not in readme_headers:
            errors.append(
                f"An exclusion points at header {anchor!r}, which is not in the README."
            )
        excluded_map[anchor] = reason

    seen_entry_anchors: set[str] = set()
    active_anchors: set[str] = set()
    for entry in entries:
        anchor = entry.get("readme_anchor")
        if anchor not in seen_entry_anchors:
            seen_entry_anchors.add(anchor)
            if anchor not in readme_headers:
                errors.append(
                    f"An entry points at header {anchor!r}, which is not in the README."
                )
        if entry.get("status") == "active":
            active_anchors.add(anchor)

    for header in readme_headers:
        if header in active_anchors or header in excluded_map:
            continue
        errors.append(
            f"The header '## {header}' has neither an active entry nor an explicit "
            "exclusion in compliance/readme-claims.yaml."
        )

    return errors


# --- Shape gate for the `## Intended Use` section (D-10, D-11, D-12) ------


def _normalize_ws(text: str) -> str:
    """Collapses every whitespace run (markdown line wrapping included) into a
    single space. The README wraps paragraphs at around 80 characters, so a
    boundary sentence may cross a line ending - matching over the raw text
    would lose it through the layout alone rather than through absent
    content."""
    return re.sub(r"\s+", " ", text)


def _intended_use_shape_errors(text: str) -> list[str]:
    """The list of shape failures of the `## Intended Use` section in the given
    text. An empty list means the shape is valid. It works over ANY text in
    memory, not only over the README - the negative cases do NOT modify the
    file in the tree (a hard requirement of task 1)."""
    try:
        body = _section_body(text, INTENDED_USE_HEADER)
    except AssertionError:
        return [f"The text has no '{INTENDED_USE_HEADER}' section."]

    if not body.strip():
        return [f"The '{INTENDED_USE_HEADER}' section has a body of whitespace only."]

    errors: list[str] = []

    subsection_positions = [
        (name, body.find(name)) for name in REQUIRED_INTENDED_USE_SUBSECTIONS
    ]
    for name, pos in subsection_positions:
        if pos == -1:
            errors.append(f"Brakuje podsekcji '{name}'.")

    present_positions = [pos for _, pos in subsection_positions if pos != -1]
    first_subsection_pos = min(present_positions) if present_positions else len(body)
    intro = body[:first_subsection_pos]

    normalized_intro = _normalize_ws(intro)
    if PASSIVITY_EVIDENCE_NODE_ID not in normalized_intro:
        errors.append(
            "The passivity paragraph does not carry the literal test "
            f"identifier {PASSIVITY_EVIDENCE_NODE_ID!r}."
        )
    # The boundary match is case-insensitive: the sentence may open the
    # paragraph (capital letter at the start) or sit inside another sentence.
    if PASSIVITY_BOUNDARY_MARKER not in normalized_intro.lower():
        errors.append(
            "The passivity paragraph does not name the boundary of the proof "
            "in the same paragraph."
        )

    condition_pos = body.find("### Condition of use")
    if condition_pos != -1:
        condition_body = _normalize_ws(body[condition_pos:]).lower()
        if NETWORK_OWNER_CONSENT_MARKER not in condition_body:
            errors.append(
                "The condition of use subsection does not carry the sentence "
                "about the network owner's consent."
            )
        if NETWORK_OWNER_NO_CHECK_MARKER not in condition_body:
            errors.append(
                "The condition of use subsection does not carry the sentence "
                "about the tool not checking that consent."
            )

    return errors


# --- Testy: obecnosc i ksztalt sekcji `## Intended Use` --------------------


def _sample_intended_use_text(
    *,
    subsections: tuple[str, ...] = REQUIRED_INTENDED_USE_SUBSECTIONS,
    intro: str = (
        f"A passivity sentence with the evidence {PASSIVITY_EVIDENCE_NODE_ID}. "
        f"{PASSIVITY_BOUNDARY_MARKER}."
    ),
    condition_body: str = (
        f"A sentence: {NETWORK_OWNER_CONSENT_MARKER}. "
        f"{NETWORK_OWNER_NO_CHECK_MARKER}."
    ),
) -> str:
    """Builds a probe document in memory with an Intended Use section of the
    given shape. Used only by the negative tests below - the README on disk is
    not modified."""
    lines = [INTENDED_USE_HEADER, "", intro, ""]
    for name in subsections:
        lines.append(name)
        lines.append(
            condition_body if name == "### Condition of use" else "Subsection body."
        )
        lines.append("")
    return "\n".join(lines)


def test_readme_has_intended_use_header():
    assert INTENDED_USE_HEADER in _readme_text()


def test_readme_intended_use_section_shape_is_valid():
    assert _intended_use_shape_errors(_readme_text()) == []


def test_missing_subsection_fails_shape_gate():
    text = _sample_intended_use_text(
        subsections=("### What it is for", "### Condition of use")
    )
    errors = _intended_use_shape_errors(text)
    assert any("What it is not for" in e for e in errors)


def test_extra_subsection_does_not_fail_shape_gate():
    text = _sample_intended_use_text(
        subsections=REQUIRED_INTENDED_USE_SUBSECTIONS + ("### Extra",)
    )
    assert _intended_use_shape_errors(text) == []


def test_header_present_with_blank_body_fails_shape_gate():
    text = f"{INTENDED_USE_HEADER}\n\n   \n\n## Kolejny naglowek\ntresc\n"
    assert _intended_use_shape_errors(text) != []


def test_header_absent_fails_shape_gate():
    text = "## Inna sekcja\n\ntresc\n"
    assert _intended_use_shape_errors(text) != []


def test_passivity_paragraph_carries_evidence_node_id_in_readme():
    body = _readme_section_body(INTENDED_USE_HEADER)
    first_pos = body.find(REQUIRED_INTENDED_USE_SUBSECTIONS[0])
    intro = body[:first_pos]
    assert PASSIVITY_EVIDENCE_NODE_ID in intro


def test_missing_evidence_id_in_intro_fails_shape_gate():
    text = _sample_intended_use_text(
        intro="A sentence with neither evidence nor a boundary."
    )
    errors = _intended_use_shape_errors(text)
    assert any("literal test identifier" in e for e in errors)


def test_missing_boundary_marker_fails_shape_gate():
    text = _sample_intended_use_text(
        intro=(
            f"A sentence with the evidence {PASSIVITY_EVIDENCE_NODE_ID}, with no "
            "sentence about the boundary."
        )
    )
    errors = _intended_use_shape_errors(text)
    assert any("boundary of the proof" in e for e in errors)


def test_condition_missing_consent_sentence_fails_shape_gate():
    text = _sample_intended_use_text(
        condition_body="A sentence with neither consent nor checking."
    )
    errors = _intended_use_shape_errors(text)
    assert any("consent" in e for e in errors) and any(
        "not checking that consent" in e for e in errors
    )


# --- Testy: katalog obietnic, asercje (a) i (b) D-16, D-17 -----------------


def test_catalog_loads_with_entries_and_excluded_anchors_keys():
    catalog = _load_catalog()
    assert isinstance(catalog["entries"], list) and len(catalog["entries"]) >= 1
    assert "excluded_anchors" in catalog


def test_catalog_with_missing_entries_key_fails():
    with pytest.raises(AssertionError):
        _entry_errors({}, frozenset())


def test_catalog_with_empty_entries_list_fails():
    with pytest.raises(AssertionError):
        _entry_errors({"entries": []}, frozenset())


def test_active_catalog_entries_are_covered_by_real_collection():
    errors = _entry_errors(_load_catalog(), _collected_test_ids())
    assert errors == []


def test_passivity_evidence_is_present_in_real_collection():
    assert PASSIVITY_EVIDENCE_NODE_ID in _collected_test_ids()


def test_real_collection_has_a_meaningful_number_of_tests():
    assert len(_collected_test_ids()) > 300


def test_entry_with_empty_evidence_fails():
    catalog = {
        "entries": [
            {"id": "x", "claim": "c", "readme_anchor": "A", "evidence": "", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert any("x" in e and "evidence" in e for e in errors)


def test_entry_with_manual_evidence_and_empty_reason_fails():
    catalog = {
        "entries": [
            {
                "id": "y",
                "claim": "c",
                "readme_anchor": "A",
                "evidence": MANUAL_EVIDENCE,
                "reason": "   ",
                "status": "active",
            }
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert any("y" in e for e in errors)


def test_entry_with_manual_evidence_and_reason_passes():
    catalog = {
        "entries": [
            {
                "id": "z",
                "claim": "c",
                "readme_anchor": "A",
                "evidence": MANUAL_EVIDENCE,
                "reason": "a claim about the environment, not about the code",
                "status": "active",
            }
        ]
    }
    assert _entry_errors(catalog, frozenset()) == []


def test_entry_with_status_outside_allowed_set_fails():
    catalog = {
        "entries": [
            {"id": "w", "claim": "c", "readme_anchor": "A", "evidence": "tests/x.py::y", "status": "draft"}
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::y"}))
    assert any("w" in e for e in errors)


def test_duplicate_entry_ids_fail():
    catalog = {
        "entries": [
            {"id": "dup", "claim": "c1", "readme_anchor": "A", "evidence": "tests/x.py::a", "status": "active"},
            {"id": "dup", "claim": "c2", "readme_anchor": "B", "evidence": "tests/x.py::b", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a", "tests/x.py::b"}))
    assert any("dup" in e and "duplicate" in e for e in errors)


def test_two_entries_same_readme_anchor_is_not_a_collision():
    catalog = {
        "entries": [
            {"id": "one", "claim": "c1", "readme_anchor": "A", "evidence": "tests/x.py::a", "status": "active"},
            {"id": "two", "claim": "c2", "readme_anchor": "A", "evidence": "tests/x.py::b", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a", "tests/x.py::b"}))
    assert errors == []


def test_evidence_pointing_to_nonexistent_test_fails():
    catalog = {
        "entries": [
            {"id": "ghost", "claim": "c", "readme_anchor": "A", "evidence": "tests/x.py::nope", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a"}))
    assert any("ghost" in e and "nope" in e for e in errors)


def test_entry_errors_reports_in_file_order():
    catalog = {
        "entries": [
            {"id": "first", "claim": "c", "readme_anchor": "A", "evidence": "", "status": "active"},
            {"id": "second", "claim": "c", "readme_anchor": "B", "evidence": "", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    first_pos = next(i for i, e in enumerate(errors) if "first" in e)
    second_pos = next(i for i, e in enumerate(errors) if "second" in e)
    assert first_pos < second_pos


def test_failure_message_never_carries_claim_text():
    claim_text = "SECRET-CLAIM-DO-NOT-REPEAT"
    catalog = {
        "entries": [
            {"id": "secretive", "claim": claim_text, "readme_anchor": "A", "evidence": "", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert errors, "the test needs at least one failure to check"
    assert all(claim_text not in e for e in errors)


# --- Testy: `_readme_anchors`, `_excluded_anchors` --------------------------


def test_readme_anchors_lists_headers_in_order():
    anchors = _readme_anchors()
    assert anchors[0] == "What a finding looks like"
    assert anchors[1] == "Intended Use"
    assert "Tests" in anchors


def test_excluded_anchors_maps_real_catalog_exclusions_to_reasons():
    excluded = _excluded_anchors()
    assert "Tests" in excluded
    assert excluded["Tests"].strip() != ""


# --- Testy: asercja (c) D-16 - kompletnosc pokrycia i pozycje martwe -------


def test_real_catalog_covers_every_readme_header():
    errors = _completeness_errors(_load_catalog(), _readme_anchors())
    assert errors == []


def test_header_without_entry_or_exclusion_fails_completeness():
    headers = ["Header A", "Header B"]
    catalog = {
        "entries": [
            {"id": "x", "readme_anchor": "Header A", "evidence": "e", "status": "active"}
        ],
        "excluded_anchors": [],
    }
    errors = _completeness_errors(catalog, headers)
    assert any("Header B" in e for e in errors)


def test_entry_pointing_to_nonexistent_header_fails_completeness():
    headers = ["Header A"]
    catalog = {
        "entries": [
            {"id": "x", "readme_anchor": "Widmo", "evidence": "e", "status": "active"}
        ],
        "excluded_anchors": [],
    }
    errors = _completeness_errors(catalog, headers)
    assert any("Widmo" in e for e in errors)


def test_exclusion_pointing_to_nonexistent_header_fails_completeness():
    headers = ["Header A"]
    catalog = {"entries": [], "excluded_anchors": [{"anchor": "Widmo", "reason": "powod"}]}
    errors = _completeness_errors(catalog, headers)
    assert any("Widmo" in e for e in errors)


def test_exclusion_with_empty_reason_fails_completeness():
    headers = ["Header A"]
    catalog = {"entries": [], "excluded_anchors": [{"anchor": "Header A", "reason": "   "}]}
    errors = _completeness_errors(catalog, headers)
    assert any("Header A" in e and "reason" in e for e in errors)


def test_header_covered_only_by_retired_entry_fails_completeness():
    headers = ["Header A"]
    catalog = {
        "entries": [
            {"id": "x", "readme_anchor": "Header A", "evidence": "e", "status": "retired"}
        ],
        "excluded_anchors": [],
    }
    errors = _completeness_errors(catalog, headers)
    assert any("Header A" in e for e in errors)


def test_two_active_entries_same_header_is_not_a_completeness_collision():
    headers = ["Header A"]
    catalog = {
        "entries": [
            {"id": "one", "readme_anchor": "Header A", "evidence": "e1", "status": "active"},
            {"id": "two", "readme_anchor": "Header A", "evidence": "e2", "status": "active"},
        ],
        "excluded_anchors": [],
    }
    assert _completeness_errors(catalog, headers) == []


def test_new_header_added_to_readme_without_coverage_fails_completeness():
    """The third sub-point of D-16: the gate is robust against CONTENT ADDED to
    the README, not only against content changed. It simulates a new header
    added with neither an entry nor an exclusion - the list of headers lives in
    memory, the README on disk is untouched."""
    headers = _readme_anchors() + ["Probe New Header"]
    errors = _completeness_errors(_load_catalog(), headers)
    assert any("Probe New Header" in e for e in errors)


def test_completeness_errors_report_missing_headers_in_readme_order():
    headers = ["First", "Second", "Third"]
    catalog = {"entries": [], "excluded_anchors": []}
    errors = _completeness_errors(catalog, headers)
    positions = [next(i for i, e in enumerate(errors) if name in e) for name in headers]
    assert positions == sorted(positions)


def test_completeness_verdict_is_independent_of_entry_order():
    headers = ["A", "B"]
    catalog_forward = {
        "entries": [
            {"id": "one", "readme_anchor": "A", "evidence": "e1", "status": "active"},
            {"id": "two", "readme_anchor": "B", "evidence": "e2", "status": "active"},
        ],
        "excluded_anchors": [],
    }
    catalog_reversed = {
        "entries": list(reversed(catalog_forward["entries"])),
        "excluded_anchors": [],
    }
    assert _completeness_errors(catalog_forward, headers) == []
    assert _completeness_errors(catalog_reversed, headers) == []


# --- Tests: the README ASCII orthography gate (D-13) -----------------------


def test_readme_orthography_gate_shares_predicate_with_report_gate():
    """One statement of the rule in the repository - the README rule and the
    report rule stand on the same object, not on two copies of the same
    value."""
    import test_report_orthography as _orthography_module

    assert non_ascii_chars is _orthography_module.non_ascii_chars


def test_readme_is_ascii():
    text = _readme_text()
    hits = [(i, ch) for i, ch in enumerate(text) if non_ascii_chars(ch)]
    assert hits == [], f"Characters outside ASCII in README (position, char): {hits[:5]}"


# --- Testy: `_evidence_is_collected` ----------------------------------------


def test_evidence_is_collected_literal_match():
    collected = frozenset({"tests/t.py::test_a"})
    assert _evidence_is_collected("tests/t.py::test_a", collected)


def test_evidence_is_collected_parametrized_prefix_match():
    collected = frozenset({"tests/t.py::test_a[fixture-1]"})
    assert _evidence_is_collected("tests/t.py::test_a", collected)


def test_evidence_is_collected_returns_false_for_missing():
    collected = frozenset({"tests/t.py::test_a[fixture-1]"})
    assert not _evidence_is_collected("tests/t.py::test_b", collected)


# --- Test: the gate writes nothing into the tree ---------------------------


def test_module_source_contains_no_file_write_calls():
    """A check OVER THE SOURCE of the module rather than over the state of the
    tree before and after - the alternative (comparing the state of the tree)
    also fires on the work of another parallel session in the same tree and
    cannot tell it apart from a write by this module. The patterns are joined
    from two parts so that this check does not catch its OWN source (the list
    below) as a false hit."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"The module carries a file write pattern: {hits}"
