"""Regression tests for the three blockers of the phase 1 code review
(`01-REVIEW.md`).

Each of them was confirmed by calling the code directly before the fix was
written, and each hits a promise this phase rests on: FOUND-04 (nothing from
under `standards/.local` reaches the repository), FOUND-03 (normative text is
recognized) and PUB-01 (a verdict carries a human name).

The tests sit in a separate file rather than being appended to the suites of
plans 01-02 and 01-04, on purpose: this is the trace of one particular review
and is meant to read as such, should anybody come back to the question of
where that list of modal terms came from.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_pub_gate  # noqa: E402
import confidentiality_guard  # noqa: E402


# CR-01. Layer 0 is the only one that cannot be lifted by an entry in
# `.confidentiality-allow`, so a case-sensitive comparison here is a way
# around the whole layer. Windows/NTFS is case-insensitive, while git records
# the literal form of a path in the index - `git add -f
# Standards/.local/x.txt` adds the same file from disk under a different name.
@pytest.mark.parametrize(
    "path",
    [
        "standards/.local/standard.txt",
        "Standards/.local/standard.txt",
        "STANDARDS/.LOCAL/standard.txt",
        "standards/.Local/standard.txt",
        "Standards\\.local\\standard.txt",
    ],
)
def test_layer0_catches_local_corpus_regardless_of_case(path):
    assert confidentiality_guard.scan_paths([path]), (
        f"layer 0 let a path into the local corpus through: {path!r}"
    )


def test_layer0_does_not_overreach_to_similar_paths():
    """Case insensitivity must not turn into matching on a fragment of a name -
    `standards/public` and `my-standards` stay clean.
    """
    clean = [
        "standards/public/readme.md",
        "docs/standards.md",
        "my-standards/.local/x.txt",
        "standards/.locally-sourced/x.txt",
    ]
    assert not confidentiality_guard.scan_paths(clean)


# CR-02. The structural layer is the only one that works in CI (the corpus by
# its nature does not exist on the runner), so a gap in it is a gap in the
# backstop. The Polish equivalents ("musi", "powinien") had been on the list
# from the start, the English "must" and "should" had not - an asymmetry, not
# a decision. The last case below stays Polish on purpose: the author's corpus
# of standards is Polish, so the modal term list stays bilingual.
@pytest.mark.parametrize(
    "fragment",
    [
        "3.4.2 The system shall enforce authentication for all write operations.",
        "3.4.2 The system must enforce authentication for all write operations.",
        "3.4.2 The system should enforce authentication for all write operations.",
        "3.4.2 The system must not permit anonymous write operations at any time.",
        "3.4.2 The system should not permit anonymous writes under any circumstances.",
        "3.4.2 System musi wymuszac uwierzytelnienie dla wszystkich operacji zapisu.",
    ],
)
def test_structural_layer_catches_normative_modals(fragment):
    assert confidentiality_guard.scan_text_structural(fragment, "probe.md"), (
        f"the structural layer let a fragment of clause shape through: {fragment!r}"
    )


def test_structural_layer_ignores_prose_without_clause_number():
    """A modal term alone, without a dotted clause number, is ordinary prose."""
    assert not confidentiality_guard.scan_text_structural(
        "The tool must be run from the repository root before the first commit.",
        "README.md",
    )


@pytest.mark.parametrize(
    "fragment",
    [
        # Real sentences from `.planning/research/PITFALLS.md` that tripped the
        # layer only after "must" was added to the modal term list - a software
        # version number was posing as a clause number.
        "CVSS v4.0 added a Safety supplemental metric, so it must be shown as a "
        "separate field and never folded into the base score silently.",
        "CVSS v4.0 OT/ICS/IoT coverage confirms the base score is not altered by "
        "the Safety supplemental value, must be reported separately.",
    ],
)
def test_structural_layer_ignores_software_version_numbers(fragment):
    """A version number is not a clause number.

    No standard numbers its clauses as `v4.0`, so excluding the `v` prefix
    does not weaken detection while it lifts a whole class of false alarms over
    the project's own documentation.
    """
    assert not confidentiality_guard.scan_text_structural(fragment, "PITFALLS.md")


def test_version_exclusion_does_not_swallow_real_clause_numbers():
    """The `v` exclusion must not lift a clause number that follows a letter.

    The control opposite to the test above: were the narrowing too wide, the
    CR-02 gap would come back, only through a different door.
    """
    assert confidentiality_guard.scan_text_structural(
        "3.4.2 The system must support TLS 1.2 for all remote management sessions "
        "initiated by field operators in this zone.",
        "probe.md",
    )


# The `reviewer` field is a weak control by nature, but rejecting a bare
# "bot" while accepting "some-bot" is not a weakness of the heuristic, it is a
# tokenization bug: splitting on whitespace alone breaks neither a hyphen nor
# an underscore.
@pytest.mark.parametrize(
    "reviewer",
    [
        "some-bot",
        "Automated-Reviewer",
        "helper_agent",
        "AI Assistant",
        "bot",
        "",
        "<first and last name>",
        "TBD",
    ],
)
def test_reviewer_field_rejects_non_human_values(reviewer):
    assert check_pub_gate._reviewer_is_invalid(reviewer), (
        f"the reviewer field accepted a value that is not a human name: {reviewer!r}"
    )


@pytest.mark.parametrize(
    "reviewer",
    [
        "Oliver Dolski",
        "Anna Nowak-Kowalska",
        "Jean-Luc Picard",
    ],
)
def test_reviewer_field_accepts_human_names(reviewer):
    assert not check_pub_gate._reviewer_is_invalid(reviewer), (
        f"the reviewer field rejected a human name: {reviewer!r}"
    )


# WR-03. The layer 2 exception list rested on `fnmatch.fnmatch`, which folds
# case through `os.path.normcase` - that is, only on Windows. The same list
# would behave differently on a Linux runner than on the author's machine,
# while layer 0 (CR-01 above) is case-insensitive on both. The fix does not
# change the result on Windows, it merely stops making it depend on the
# platform.
@pytest.mark.parametrize(
    "path",
    [
        "tests/test_confidentiality_guard.py",
        "Tests/Test_Confidentiality_Guard.py",
        "tests\\test_confidentiality_guard.py",
    ],
)
def test_allow_list_is_case_insensitive_on_every_platform(path):
    assert confidentiality_guard._matches_allow_list(
        path, ["tests/test_confidentiality_guard.py"]
    )


def test_allow_list_does_not_overreach_to_other_files():
    assert not confidentiality_guard._matches_allow_list(
        "src/wayside/cli.py", ["tests/test_confidentiality_guard.py"]
    )
