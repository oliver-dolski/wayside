"""Text gate for STD-07, RISK-01 and RISK-02 over the RESULT of rendering.

Three things this file is meant to say outright.

**The gate works over the result, not over the logic.** It scans `report.md`
and the content of `analysis.json` of a REAL analysis of every fixture, not a
hand-built model. `tests/test_report_render.py` has its own test over a
hand-built model and this file does NOT replace it: that one guards the shape
of the rendering, this one guards what actually comes out of the pipeline.

**The gate was written AFTER the final content of the sections was settled,
not before.** Phase 2 paid once already for the opposite order: a pattern too
wide caught the report's own correct text as a violation, because a sentence
explaining what the tool does NOT do inherently contains the word the
prohibition is about. That is why this file comes in the last wave of phase 3,
once the scope, methodology, inventory, communication matrix and limitations
sections are in their final form.

**The pattern list is bilingual on purpose.** The report is English today, so
the English patterns are the ones that can actually fire; the Polish ones stay
as a regression guard, the same reasoning that keeps `NORMATIVE_MODAL_TERMS`
bilingual in the confidentiality gate. Widening the detection never costs
correctness here - a false alarm would, and that is what the narrowings below
prevent.

**Narrowings against the list from `03-RESEARCH.md`, each with its reason.**

1. The compliance-claim pattern is ANCHORED on word boundaries and enumerates
   the adjectival and nominal endings instead of catching the stem alone
   (assumption Z-36). The reason: an unanchored stem catches the Polish adverb
   used in ordinary prose to mean "according to". The fragment that forced it:
   that adverb occurs in descriptive sentences across the project and is not a
   claim of conformity with a standard. The negative case has its own test.

2. The pattern does NOT cover the verb "meet", nor its Polish counterpart
   (assumption Z-37). The reason: that is the verb of the methodology
   sentence which EXPLAINS that the tool issues no compliance judgement. The
   fragment that forced it: "never a judgement on whether an installation does
   or does not meet the requirements of a standard" in
   `src/wayside/report.py`. A prohibition wider than the forbidden content
   would strip from the report exactly the part that contradicts that content
   most strongly.

3. The security level pattern requires a DIGIT in the range 1-4 next to the
   acronym. The reason: the bare acronym without a number occurs in citations
   of a clause of a standard (`SR 1.1`) and in prose about levels as a
   concept, while what is forbidden is assigning a level, not mentioning that
   levels exist.

No other pattern from the research list was narrowed.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wayside import risk
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def normalize_for_match(text: str) -> str:
    """Lower case with diacritics stripped (assumption Z-35).

    The way they are stripped is the same as in
    `scripts/confidentiality_guard.py` (`_strip_diacritics`): two different
    normalizations in one repository drift apart at the first fix to one of
    them. The author's corpus of standards carries real diacritics while the
    source code writes without them - a pattern over the raw text would let one
    of those two spellings through.
    """
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


# Patterns over text that is ALREADY normalized, so without diacritics and
# without upper case. The `\b` anchoring is the whole difference between a
# working gate and a generator of false alarms - see narrowing 1 in the
# docstring.
COMPLIANCE_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        "compliance-adjective-pl",
        re.compile(r"\b(?:nie)?\s*zgodn(?:y|a|e|ego|ej|ym|ymi|ych|osc|osci|oscia)\b"),
    ),
    ("compliant-en", re.compile(r"\b(?:non-?)?compliant\b")),
    ("compliance-en", re.compile(r"\bcompliance\b")),
    ("certification-pl", re.compile(r"\bcertyfik\w*\b")),
    ("certification-en", re.compile(r"\bcertif\w*\b")),
)

# Three spellings of a numeric security level. The digit is required - see
# narrowing 3 in the docstring.
SECURITY_LEVEL_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("security-level-acronym", re.compile(r"\bsl[\s-]?[1-4]\b")),
    ("security-level-en", re.compile(r"\bsecurity\s+level\s*[1-4]\b")),
    ("security-level-phrase-pl", re.compile(r"\bpoziom\w*\s+bezpieczenstwa\s*[1-4]\b")),
)

# An aggregate numeric indicator in the form of a fraction of a hundred. The
# pattern is carried over from `tests/test_report_render.py` (a constant of the
# same name) - one concept, the same expression in both gates.
NUMERIC_SCORE_PATTERN = re.compile(r"\b\d{1,3}\s*/\s*100\b")

_CONTEXT_RADIUS = 30


def scan_forbidden(
    text: str, patterns: tuple[tuple[str, re.Pattern], ...]
) -> list[tuple[str, str]]:
    """Returns pairs of `(pattern name, a short context around the hit)`.

    The context is needed for the fix: without it the test message says that
    something is wrong but not where. At the same time it is SHORT, so that the
    message does not become a channel for leaking content - the same tension
    `scripts/confidentiality_guard.py` settled in favour of having no text
    field at all in `Violation`. The distinction is this: there the input is
    the text of a standard covered by confidentiality, here it is the project's
    own report. Do not carry this solution back into that gate.
    """
    normalized = normalize_for_match(text)
    hits: list[tuple[str, str]] = []
    for name, pattern in patterns:
        for match in pattern.finditer(normalized):
            start = max(0, match.start() - _CONTEXT_RADIUS)
            end = min(len(normalized), match.end() + _CONTEXT_RADIUS)
            hits.append((name, normalized[start:end]))
    return hits


ALL_PATTERNS = COMPLIANCE_CLAIM_PATTERNS + SECURITY_LEVEL_PATTERNS + (
    ("numeric-indicator", NUMERIC_SCORE_PATTERN),
)


def _analyzable_fixtures() -> list[Path]:
    """Every fixture of the directory whose analysis finishes without an exception.

    The list is built by GLOB over the directory rather than by naming the
    files by hand: a hand-written list would not cover a fixture added in
    Phase 4, and the gate would then silently stop covering the new content.

    Fixtures whose analysis ends in an exception (a truncated or corrupted
    capture, an unsupported format) are skipped by an EXPLICIT filter on two
    named exception types rather than by a block catching anything - otherwise
    a regression in the pipeline would hide as "a fixture with no artifacts".
    """
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (the D-01 gate)")


# --- normalize_for_match ----------------------------------------------------


def test_normalize_lowercases_and_strips_diacritics():
    assert normalize_for_match("ZGODNOSC") == normalize_for_match("zgodnosc")
    assert normalize_for_match("zgodność") == "zgodnosc"
    assert normalize_for_match("NIEZGODNOŚĆ") == "niezgodnosc"


# --- scan_forbidden ---------------------------------------------------------


def test_scan_forbidden_on_empty_text_returns_empty_list():
    assert scan_forbidden("", ALL_PATTERNS) == []


def test_scan_forbidden_on_clean_text_returns_empty_list():
    text = "Analysis of capture raised one indicator of observed behaviour."

    assert scan_forbidden(text, ALL_PATTERNS) == []


def test_scan_forbidden_rejects_a_compliance_claim():
    """The OPPOSITE test: without it a pattern broken so that it catches
    nothing passes the whole suite green."""
    text = "Instalacja jest zgodna z wymaganiem normy w tym zakresie."

    hits = scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS)

    assert hits
    assert hits[0][0] == "compliance-adjective-pl"
    assert len(hits[0][1]) < len(text) + 1


def test_scan_forbidden_rejects_a_numeric_security_level():
    """The second opposite test, for the second family of patterns."""
    text = "The controller was assessed at SL-2 in this segment."

    hits = scan_forbidden(text, SECURITY_LEVEL_PATTERNS)

    assert hits
    assert hits[0][0] == "security-level-acronym"


def test_compliance_pattern_catches_diacritic_and_ascii_spelling():
    with_diacritics = "Wynik potwierdza zgodność instalacji."
    without = "Wynik potwierdza zgodnosc instalacji."

    assert scan_forbidden(with_diacritics, COMPLIANCE_CLAIM_PATTERNS)
    assert scan_forbidden(without, COMPLIANCE_CLAIM_PATTERNS)


def test_compliance_pattern_catches_negated_and_noun_forms():
    for text in (
        "Instalacja jest niezgodna z wymaganiem.",
        "Raport stwierdza niezgodnosc z norma.",
        "The system is non-compliant.",
        "This is a compliance report.",
    ):
        assert scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS), text


def test_compliance_pattern_does_not_catch_the_adverb_meaning_according_to():
    """The negative case forced by narrowing 1 of the docstring."""
    text = "Waga findingu wynika zgodnie z kryteriami zapisanej rubryki."

    assert scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS) == []


def test_compliance_pattern_does_not_catch_the_methodology_verb():
    """The negative case forced by narrowing 2 of the docstring - the
    methodology sentence the report has carried since Phase 2, in the English
    form it takes today and in the Polish form it took before."""
    for text in (
        "never a judgement on whether an installation does or does not meet "
        "the requirements of a standard",
        "nigdy ocene, czy instalacja spelnia albo nie spelnia wymagan normy",
    ):
        assert scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS) == [], text


def test_security_level_pattern_catches_three_spellings():
    for text in (
        "poziom SL 3 dla tej strefy",
        "assessed Security Level 2",
        "przypisany poziom bezpieczenstwa 4",
    ):
        assert scan_forbidden(text, SECURITY_LEVEL_PATTERNS), text


def test_security_level_pattern_does_not_catch_bare_acronym_or_clause_number():
    for text in (
        "poziom bezpieczenstwa jest celem z analizy ryzyka, nie pomiarem",
        "Standard citation: IEC-62443-3-3 SR 1.1",
    ):
        assert scan_forbidden(text, SECURITY_LEVEL_PATTERNS) == [], text


# --- The gate over the result of a real analysis ---------------------------


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_rendered_report_carries_no_forbidden_phrase(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    hits = scan_forbidden(result.report_markdown, ALL_PATTERNS)

    assert hits == [], f"{fixture.name}: {hits}"


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_analysis_json_carries_no_forbidden_phrase(fixture, tmp_path):
    """Assumption Z-38: the machine artifact is published output just as much
    as the report, so a prohibition holding in only one of the two would be a
    prohibition in appearance only."""
    result = _analyze_or_skip(fixture, tmp_path)
    serialized = json.dumps(result.analysis, ensure_ascii=False)

    hits = scan_forbidden(serialized, ALL_PATTERNS)

    assert hits == [], f"{fixture.name}: {hits}"


# --- RISK-01: the severity method in the methodology section of a real ----
# --- report ---------------------------------------------------------------
#
# The value of this test against `tests/test_report_render.py`: that one proves
# the renderer CAN print the criteria, this one proves they really are in a
# REAL report from a real analysis. It breaks when somebody adds a fifth
# severity level to the rubric and forgets the report - the criteria are read
# from the production module, never from a copy in this file.

HEADER_PATTERN = re.compile(r"^## (.+)$", flags=re.MULTILINE)


def _section_body(text: str, name: str) -> str:
    """The body of one section, from its header to the next one.

    Cutting by header is not excessive caution: a criterion sentence present
    anywhere in the report would satisfy a test looking for a substring across
    the whole text, and RISK-01 speaks outright about the methodology section.
    A test over the whole file would pass even if the methodology section
    vanished and the criteria landed in the recommendations.
    """
    matches = list(HEADER_PATTERN.finditer(text))
    for index, match in enumerate(matches):
        if match.group(1).strip() != name:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        return text[start:end]
    raise AssertionError(f"The report has no '{name}' section")


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_methodology_section_carries_every_rubric_criterion(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    body = _section_body(result.report_markdown, "Methodology")

    for severity, criterion in risk.RUBRIC_CRITERIA.items():
        assert criterion in body, f"{fixture.name}: no criterion for severity {severity}"


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_methodology_section_carries_rubric_version(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    body = _section_body(result.report_markdown, "Methodology")

    assert risk.RUBRIC_VERSION in body, fixture.name


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_methodology_section_names_every_allowed_severity(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    body = _section_body(result.report_markdown, "Methodology")

    for severity in risk.ALLOWED_SEVERITIES:
        assert severity in body, f"{fixture.name}: the severity name {severity} is absent"
