"""Gate for the content of the `LICENSE` file (PUB-04, D-02, D-03,
assumptions Z-88, Z-89).

This gate checks the CONTENT of the licence file, not its legal effect.
Judging the legal effect of the chosen licence is not a technical threat and
is the subject of no test in this module - the decision record
`docs/decisions/0007-apache-2-0-license.md` names the residual risk outright,
and neither that file nor that record gives legal advice.

**The comparison happens after normalizing line endings to a single character
(assumption Z-89), not byte for byte.** The reason was measured at planning
time: `.gitattributes` carries `* text=auto` and the local git configuration
has checkout conversion enabled, so a text file in the working tree on this
machine carries two-character line endings. A byte comparison would give a
result dependent on the platform and on the local git configuration - a gate
that turns red for somebody else without any change to the content.

**The difference from the canonical text is EXACTLY one line (assumption
Z-88):** the copyright line in the closing block, with both bracketed values
substituted. The digest test builds the content with the template line put
back and compares the sha256 digest against the value measured at planning
time (downloaded 2026-09-09 from
`https://www.apache.org/licenses/LICENSE-2.0.txt`, line endings as a single
newline character). The structural marker test checks the presence of each of
the nine numbered sections and of the end-of-terms line SEPARATELY, so that
the failure message names the missing section rather than quoting a fragment
of the licence text.

The unchanged-project-name test (D-03) checks the package name field and the
command line entry point in `pyproject.toml` against the `PACKAGE_NAME` and
`CLI_ENTRY_POINT` constants - the decision about the name was confirmed rather
than skipped, so it leaves a machine trace that turns red on a silent change.

The module writes and changes no file in the repository tree - the negative
cases are built over text in memory, never by writing to `LICENSE` (see
`test_module_source_contains_no_file_write_calls` at the end of the file, the
`tests/test_readme_claims.py` pattern).
"""

from __future__ import annotations

import hashlib
import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

LICENSE_PATH = REPO_ROOT / "LICENSE"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# The sha256 digest of the canonical text (downloaded 2026-09-09, line
# endings as a single newline character) - measured at planning time, recorded
# in 05-02-PLAN.md, the table of facts measured at planning time.
CANONICAL_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

# The number of lines of the canonical text after line ending normalization -
# measured at planning time from the same download as the digest above.
CANONICAL_LINE_COUNT = 202

# The template line from the closing block of the canonical text, exactly as
# it appears in the downloaded text - the only line this file substitutes.
CANONICAL_PLACEHOLDER_LINE = "Copyright [yyyy] [name of copyright owner]"

# The line after substitution, D-02: the year 2026 and the author's name.
COPYRIGHT_LINE = "Copyright 2026 Oliver Dolski"

# The nine numbered sections of the canonical text plus the end-of-terms
# line - checked SEPARATELY, so that the failure message names the missing
# section rather than copying a fragment of the licence text into the message.
REQUIRED_SECTION_MARKERS: tuple[str, ...] = (
    "1. Definitions.",
    "2. Grant of Copyright License.",
    "3. Grant of Patent License.",
    "4. Redistribution.",
    "5. Submission of Contributions.",
    "6. Trademarks.",
    "7. Disclaimer of Warranty.",
    "8. Limitation of Liability.",
    "9. Accepting Warranty or Additional Liability.",
    "END OF TERMS AND CONDITIONS",
)

# D-03: the package name and the command line entry point, confirmed unchanged.
PACKAGE_NAME = 'name = "wayside"'
CLI_ENTRY_POINT = 'wayside = "wayside.cli:app"'


def _license_text_lf() -> str:
    """The content of `LICENSE` after normalizing line endings to a single
    character (assumption Z-89) - the input of every test in this module
    below."""
    raw = LICENSE_PATH.read_text(encoding="utf-8")
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def _license_with_placeholder_restored() -> str:
    """The (normalized) content of `LICENSE` with the `COPYRIGHT_LINE` put
    back as the `CANONICAL_PLACEHOLDER_LINE` template line - the input of the
    sha256 digest test against the canonical text."""
    return _license_text_lf().replace(COPYRIGHT_LINE, CANONICAL_PLACEHOLDER_LINE)


# --- The file exists and has as many lines as the canonical text ----------


def test_license_file_exists():
    assert LICENSE_PATH.is_file(), f"{LICENSE_PATH} does not exist."


def test_license_line_count_matches_canonical():
    actual_count = len(_license_text_lf().splitlines())
    matches = actual_count == CANONICAL_LINE_COUNT
    assert matches, (
        f"LICENSE carries {actual_count} lines after line ending "
        f"normalization, expected {CANONICAL_LINE_COUNT} (as many as the "
        "canonical text). This message carries line counts only, never "
        "content."
    )


# --- Structural markers: nine numbered sections plus END ------------------


def test_required_section_markers_constant_has_at_least_ten_entries():
    assert len(REQUIRED_SECTION_MARKERS) >= 10


def test_license_carries_every_required_section_marker():
    text = _license_text_lf()
    missing = [marker for marker in REQUIRED_SECTION_MARKERS if marker not in text]
    assert missing == [], f"LICENSE does not carry the markers: {missing}"


def test_missing_single_marker_in_sample_text_is_detected_by_name():
    """The opposite test: the gate names the MISSING marker rather than merely
    reporting a failure - the message of the test above has to be
    distinguishable by which marker vanished."""
    sample = _license_text_lf().replace("6. Trademarks.", "6. Something Else.")
    missing = [marker for marker in REQUIRED_SECTION_MARKERS if marker not in sample]
    assert missing == ["6. Trademarks."]


# --- The copyright line: the substituted one present, the template absent -


def test_license_carries_substituted_copyright_line():
    assert COPYRIGHT_LINE in _license_text_lf()


def test_license_does_not_carry_canonical_placeholder_line():
    assert CANONICAL_PLACEHOLDER_LINE not in _license_text_lf()


# --- The sha256 digest after putting the template line back ---------------


def test_license_with_placeholder_restored_matches_canonical_sha256():
    restored = _license_with_placeholder_restored()
    digest = hashlib.sha256(restored.encode("utf-8")).hexdigest()
    assert digest == CANONICAL_SHA256, (
        f"The digest of the LICENSE content with the template line put back is "
        f"{digest}, expected {CANONICAL_SHA256} (the digest of the canonical "
        "text). This message carries digests and line counts only, never a "
        "fragment of the content."
    )


def test_restoring_placeholder_does_not_change_line_count():
    restored_count = len(_license_with_placeholder_restored().splitlines())
    matches = restored_count == CANONICAL_LINE_COUNT
    assert matches, (
        f"LICENSE with the template line put back has {restored_count} lines, "
        f"expected {CANONICAL_LINE_COUNT}. This message carries line counts only."
    )


# --- D-03: package name, CLI command and source directory unchanged -------


def test_package_name_unchanged():
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert PACKAGE_NAME in text, (
        f"{PYPROJECT_PATH} does not carry {PACKAGE_NAME!r} - D-03 requires the "
        "package name to stay unchanged by this plan."
    )


def test_cli_entry_point_unchanged():
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert CLI_ENTRY_POINT in text, (
        f"{PYPROJECT_PATH} does not carry {CLI_ENTRY_POINT!r} - D-03 requires "
        "the command line entry point to stay unchanged by this plan."
    )


def test_source_directory_unchanged():
    assert (REPO_ROOT / "src" / "wayside").is_dir(), (
        "The source directory src/wayside does not exist - D-03 requires the "
        "name of the source directory to stay unchanged."
    )


# --- Test: the gate writes nothing into the tree --------------------------


def test_module_source_contains_no_file_write_calls():
    """A check OVER THE SOURCE of the module, the same pattern as
    `tests/test_readme_claims.py::test_module_source_contains_no_file_write_calls`
    - the alternative (comparing the state of the tree before and after) also
    fires on the work of a parallel session in the same tree."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"The module carries a file write pattern: {hits}"
