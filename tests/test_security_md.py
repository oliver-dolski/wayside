"""Gate for the content and shape of `SECURITY.md` (PUB-02, D-04 through D-09).

Which decision each group of assertions carries out:

- D-04: two second-level headers in order - a vulnerability in the tool, then
  a vulnerability in someone else's network. `REQUIRED_SECTION_HEADERS`.
- D-05: the channel of the first section is private vulnerability reporting in
  the security tab of the repository, never an email address.
  `CHANNEL_MARKERS`, `_EMAIL_SHAPE_RE`.
- D-06: the two windows of the first section (acknowledgement of receipt,
  initial assessment), no fix window, no reward programme.
  `ACKNOWLEDGEMENT_WINDOW`, `ASSESSMENT_WINDOW`, `FORBIDDEN_REMEDIATION_PROMISES`.
- D-07: no mediation in someone else's networks, three routes of the reader's
  own. `COORDINATION_ROUTES`.
- D-08: no `security.txt` file per RFC 9116 comes into being.
  `RFC9116_FORBIDDEN_PATHS`.
- D-09: one narrow safe harbour sentence, bounded to the scope of the first
  section. `SAFE_HARBOR_MARKERS`.

**This gate checks the PRESENCE of phrases and the SHAPE of the document, not
whether a sentence says exactly what the decision names.** Whether the content
reads honestly (say whether the sentence about the absence of mediation is
direct enough) is judged by a human - a manual check recorded in
`05-VALIDATION.md` under `## Manual-Only Verifications`, not by this file.

**The closed set of forbidden promises (`FORBIDDEN_REMEDIATION_PROMISES`)
lives ONLY in this module as its single source of truth** - `SECURITY.md`
does not repeat it (the gate scans `SECURITY.md`, not this module), and were
it to repeat it, that would be a duplicate drifting apart at the first fix in
one of the two places. The SUMMARY of this plan quotes the full contents of
the set together with the justification of every entry (the `<output>`
requirement of plan 05-02) - which is safe, because the gate scans
`SECURITY.md` only, not `.planning/`.

Every pattern below is narrowed against the particular negating sentence
`SECURITY.md` has to be able to say without firing its own gate - the same
problem phase 3 paid for once in
`tests/test_report_forbidden_phrases.py` (see the docstring of that module).

The module writes and changes no file in the repository tree - the negative
cases are built over text in memory, never by writing to `SECURITY.md` (see
`test_module_source_contains_no_file_write_calls`).
"""

from __future__ import annotations

import inspect
import os
import re
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

# One source of truth for the predicate over characters outside ASCII,
# shared with the report orthography gate.
from test_report_orthography import non_ascii_chars  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_PATH = REPO_ROOT / "SECURITY.md"

# Copied verbatim from tests/test_readme_claims.py and
# tests/test_standard_designation_gate.py - one statement of that rule.
_HEADER_LINE_RE = re.compile(r"^## .+$", re.MULTILINE)

# D-04: two second-level headers, in their order of appearance in the file.
REQUIRED_SECTION_HEADERS: tuple[str, str] = (
    "## A vulnerability in the Wayside tool",
    "## A vulnerability found with Wayside in someone else's network",
)

# D-06: both windows, written exactly as they stand in SECURITY.md.
ACKNOWLEDGEMENT_WINDOW = "five business days"
ASSESSMENT_WINDOW = "thirty days"

# D-06: a closed set of forbidden promises. Every entry is phrased as a
# POSITIVE promise (a declaration of a window or a reward), never as a
# fragment of a negating sentence - SECURITY.md has to be able to say "no fix
# release window stands here" without firing its own gate.
FORBIDDEN_REMEDIATION_PROMISES: tuple[str, ...] = (
    # A declaration of a numeric fix window - the form with "is" is a
    # POSITIVE statement of a window, distinct from the boundary sentence
    # "no fix release window stands here" (which carries no "is").
    "the fix release window is",
    # The second natural variant of the same promise - the future tense
    # ("will be released"), which this file's boundary sentence does not use.
    "a fix will be released within",
    # The third variant - a fix as a commitment by a specific calendar date,
    # lexically independent of the two above.
    "we commit to fixing within",
    # A promise of a reward for a report - the noun "reward" with the
    # complement "for reporting a vulnerability", distinct from the boundary
    # sentence "no reward programme for reports stands here" (which uses
    # "programme" and does not carry the word "vulnerability").
    "reward for reporting a vulnerability",
    # The proper name of a vulnerability reward programme, widely recognised
    # in the industry - it appears in no correct boundary sentence.
    "bug bounty",
)

# D-05: the fragments naming the platform channel as the only channel of
# section 1. The comparison in the tests happens after whitespace
# normalization, so markdown line wrapping does not lose the match.
CHANNEL_MARKERS: tuple[str, ...] = (
    "private vulnerability reporting in the security tab of this repository",
)

# D-09: a fragment of the narrow safe harbour sentence.
SAFE_HARBOR_MARKERS: tuple[str, ...] = (
    "faces no claims from the author on that account",
)

# D-07: the three names of public coordination points, written verbatim.
COORDINATION_ROUTES: tuple[str, ...] = (
    "CISA ICS-CERT",
    "CSIRT NASK",
    "CSIRT GOV",
)

# D-08: the paths this plan deliberately does NOT create. Absolute, so that
# they work regardless of the working directory the test is called from.
RFC9116_FORBIDDEN_PATHS: tuple[str, ...] = (
    str(REPO_ROOT / "security.txt"),
    str(REPO_ROOT / ".well-known" / "security.txt"),
)

# The shape of an email address: a local part, an at sign, a domain with a
# dot. Narrow ON PURPOSE - the words "email address" in prose do NOT fire this
# pattern, because the document is entitled to explain why there is no
# address.
_EMAIL_SHAPE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _security_text() -> str:
    return SECURITY_PATH.read_text(encoding="utf-8")


def _section_body(text_or_header, header: str | None = None) -> str:
    """The body of the `header` section, from the end of the header line to the
    start of the next second-level header (or the end of the text).

    Callable in two ways, so that the negative cases can work over any text in
    memory (the `tests/test_readme_claims.py::_section_body` pattern):
    `_section_body(header)` operates over `_security_text()`, while
    `_section_body(text, header)` operates over the text given.
    """
    if header is None:
        text, header = _security_text(), text_or_header
    else:
        text = text_or_header
    headers = list(_HEADER_LINE_RE.finditer(text))
    for index, match in enumerate(headers):
        if match.group(0).strip() != header:
            continue
        start = match.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        return text[start:end]
    raise AssertionError(f"The text has no {header!r} section.")


# --- The file exists and has exactly two headers, in order ----------------


def test_security_file_exists():
    assert SECURITY_PATH.is_file(), f"{SECURITY_PATH} does not exist."


def test_security_has_exactly_two_second_level_headers_in_order():
    headers = [m.group(0).strip() for m in _HEADER_LINE_RE.finditer(_security_text())]
    assert headers == list(REQUIRED_SECTION_HEADERS), headers


def test_required_section_headers_constant_has_two_entries():
    assert len(REQUIRED_SECTION_HEADERS) == 2


# --- Kazda sekcja ma niepuste cialo -----------------------------------------


def test_each_section_body_is_nonempty_after_stripping_whitespace():
    for header in REQUIRED_SECTION_HEADERS:
        body = _section_body(header)
        assert body.strip(), f"Sekcja {header!r} ma cialo puste po zdjeciu bialych znakow."


def test_section_body_missing_from_text_raises():
    with pytest_raises_assertion():
        _section_body("tekst bez zadnego naglowka", "## Nieistniejacy naglowek")


def pytest_raises_assertion():
    import pytest

    return pytest.raises(AssertionError)


# --- D-06: the two windows of the first section ----------------------------


def test_section_one_body_carries_acknowledgement_window():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    found = ACKNOWLEDGEMENT_WINDOW in body
    assert found, "Section 1 does not carry the ACKNOWLEDGEMENT_WINDOW fragment."


def test_section_one_body_carries_assessment_window():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    found = ASSESSMENT_WINDOW in body
    assert found, "Section 1 does not carry the ASSESSMENT_WINDOW fragment."


def test_assessment_and_acknowledgement_windows_do_not_leak_into_section_two():
    body = _section_body(REQUIRED_SECTION_HEADERS[1])
    acknowledgement_leaked = ACKNOWLEDGEMENT_WINDOW in body
    assessment_leaked = ASSESSMENT_WINDOW in body
    assert not acknowledgement_leaked, "ACKNOWLEDGEMENT_WINDOW leaks into section 2."
    assert not assessment_leaked, "ASSESSMENT_WINDOW leaks into section 2."


# --- D-06: the closed set of forbidden promises ----------------------------


def test_forbidden_remediation_promises_constant_has_at_least_four_entries():
    assert len(FORBIDDEN_REMEDIATION_PROMISES) >= 4


def test_security_text_carries_no_forbidden_remediation_promise():
    text = _security_text().lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in text]
    assert hits == [], f"SECURITY.md carries forbidden promises: {hits}"


def test_forbidden_promise_pattern_does_not_catch_the_own_boundary_sentences():
    """The opposite test: the set of forbidden promises must not fire on the
    boundary sentences of that same document, which use the same word stems in
    a negated form. The probes below are the sentences SECURITY.md actually
    carries."""
    boundary_text = (
        "No fix release window stands here. "
        "No reward programme for reports stands here, for the same reason."
    ).lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in boundary_text]
    assert hits == [], hits


def test_a_genuine_promise_sentence_is_caught_by_the_set():
    """The opposite direction: without this the gate could be empty and pass
    always, regardless of content."""
    promise_text = "the fix release window is fourteen days.".lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in promise_text]
    assert hits


# --- D-05: the platform channel, no email address -------------------------


def test_channel_markers_constant_is_nonempty():
    assert len(CHANNEL_MARKERS) >= 1


def test_section_one_body_names_platform_channel():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    normalized = re.sub(r"\s+", " ", body)
    for marker in CHANNEL_MARKERS:
        found = re.sub(r"\s+", " ", marker) in normalized
        assert found, "Section 1 does not carry one of CHANNEL_MARKERS."


def test_security_text_carries_no_email_shaped_string():
    has_email_shape = _EMAIL_SHAPE_RE.search(_security_text()) is not None
    assert not has_email_shape, "SECURITY.md carries a string shaped like an email address."


def test_email_shape_pattern_does_not_fire_on_prose_about_email_addresses():
    """The opposite test: the words 'email address' alone in prose are not
    meant to fire the address shape pattern."""
    prose = "Why there is no email address here: the platform channel..."
    has_email_shape = _EMAIL_SHAPE_RE.search(prose) is not None
    assert not has_email_shape


def test_email_shape_pattern_catches_a_real_looking_address():
    matched = _EMAIL_SHAPE_RE.search("contact: example.author@example-domain.example") is not None
    assert matched


# --- D-09: the safe harbour sentence, narrow and bounded to section 1 -----


def test_safe_harbor_markers_constant_is_nonempty():
    assert len(SAFE_HARBOR_MARKERS) >= 1


def test_section_one_body_carries_safe_harbor_sentence():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    normalized = re.sub(r"\s+", " ", body)
    for marker in SAFE_HARBOR_MARKERS:
        found = re.sub(r"\s+", " ", marker) in normalized
        assert found, "Section 1 does not carry one of SAFE_HARBOR_MARKERS."


# --- D-07: no mediation, three routes for the reader -----------------------


def test_coordination_routes_constant_has_at_least_three_entries():
    assert len(COORDINATION_ROUTES) >= 3


def test_section_two_body_carries_every_coordination_route():
    body = _section_body(REQUIRED_SECTION_HEADERS[1])
    missing = [route for route in COORDINATION_ROUTES if route not in body]
    assert missing == [], f"Section 2 does not carry the coordination routes: {missing}"


def test_section_two_body_states_no_mediation():
    body = _section_body(REQUIRED_SECTION_HEADERS[1]).lower()
    no_mediation_present = "does not mediate" in body
    no_acceptance_present = "does not accept" in body
    assert no_mediation_present, "Section 2 does not carry 'does not mediate'."
    assert no_acceptance_present, "Section 2 does not carry 'does not accept'."


def test_section_two_body_carries_no_day_count_as_incident_deadline():
    """Task 1 behavior list: the second section carries no day count as an
    incident reporting deadline - neither numeric nor the spelled-out windows
    of section 1."""
    body = _section_body(REQUIRED_SECTION_HEADERS[1]).lower()
    has_numeric_day_count = re.search(r"\b\d+\s+days?\b", body) is not None
    has_acknowledgement_window_words = "five business days" in body
    has_assessment_window_words = "thirty days" in body
    assert not has_numeric_day_count, "Section 2 carries a numeric day count as a deadline."
    assert not has_acknowledgement_window_words, (
        "Section 2 carries the spelled-out window of section 1 (five days)."
    )
    assert not has_assessment_window_words, (
        "Section 2 carries the spelled-out window of section 1 (thirty days)."
    )


# --- D-08: brak pliku RFC 9116 ----------------------------------------------


def test_rfc9116_forbidden_paths_constant_has_at_least_two_entries():
    assert len(RFC9116_FORBIDDEN_PATHS) >= 2


def test_no_rfc9116_security_txt_file_exists():
    present = [p for p in RFC9116_FORBIDDEN_PATHS if os.path.exists(p)]
    assert present == [], f"Pliki RFC 9116 istnieja mimo rozstrzygniecia D-08: {present}"


# --- Ortografia: brak polskich znakow diakrytycznych ------------------------


def test_security_md_is_ascii():
    text = _security_text()
    hits = [(i, ch) for i, ch in enumerate(text) if non_ascii_chars(ch)]
    assert hits == [], (
        f"Characters outside ASCII in SECURITY.md (position, char): {hits[:5]}"
    )


# --- Test: the gate writes nothing into the tree ---------------------------


def test_module_source_contains_no_file_write_calls():
    """A check OVER THE SOURCE of the module, the same pattern as
    `tests/test_readme_claims.py::test_module_source_contains_no_file_write_calls`."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"The module carries a file write pattern: {hits}"
