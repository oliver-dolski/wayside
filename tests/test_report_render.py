"""Machine gate REPORT-01: the six-section markdown report (plan 02-04).

The input model is built by hand in this file, through the `_render` and
`_finding` helpers - `render_markdown` is a function over a dictionary, and the
proof through the whole pipeline (pcap file -> CLI -> report.md) already exists
in `tests/test_analyze_pipeline.py`. `test_six_sections_present` and
`test_report_makes_no_compliance_claim` are part of the requirement-to-test
contract of `02-VALIDATION.md`, their names do not change.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from wayside import risk
from wayside.flow import (
    COMPLETENESS_CLAIM_TERMS,
    VANTAGE_POINT_LIMITATIONS,
    vantage_point_limitations,
)
from wayside.model import collect_not_derivable_fields
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.report import (
    CITATION_SCOPE_LABEL,
    SECTIONS,
    aggregated_remediations,
    citation_line,
    citation_scope_line,
    finding_genitive_phrase,
    render_markdown,
    session_parties_line,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"

GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Verdict words as test data - not literals scattered across the assertions.
# The list stays bilingual: the Polish stems catch inflected forms
# ("zgodnosci", "niezgodne") and stay in place as a regression guard now that
# the report itself is English, the same reasoning that keeps
# `NORMATIVE_MODAL_TERMS` bilingual.
VERDICT_WORDS: tuple[str, ...] = (
    "zgodny",
    "niezgodny",
    "zgodnosc",
    "niezgodnosc",
    "compliant",
    "non-compliant",
)

# Pattern of an aggregate numeric indicator of the form "number / 100".
NUMERIC_SCORE_PATTERN = re.compile(r"\b\d{1,3}\s*/\s*100\b")

HEADER_PATTERN = re.compile(r"^## (.+)$", flags=re.MULTILINE)


def _finding(**overrides) -> dict:
    """Builds one finding in dictionary shape, exactly as
    `dataclasses.asdict(model.Finding(...))` does in `pipeline.py`."""
    base = {
        "check_id": "modbus-unauthenticated-write",
        "title": "Write operation to a controller over Modbus/TCP with no authentication at all",
        "severity": "high",
        "risk": "serious",
        "rationale": "Our own analysis of the observed traffic, not a quote of a standard.",
        "standard_refs": [
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "clause_title_source": "copy",
                "paraphrase": "Paraphrase of the clause, not a quote of the original.",
                "verified": False,
                "verification_note": "Provisional numbering, awaiting comparison against a lawfully obtained copy of the standard.",
            }
        ],
        "evidence": {
            "packet_number": 1,
            "session_id": 0,
            "source": "10.0.0.1:502",
            "target": "10.0.0.2:50210",
        },
        "remediation": "Ograniczyc mozliwosc wysylania kodow zapisu do znanych hostow inzynierskich.",
    }
    base.update(overrides)
    return base


def _render(*, findings: list[dict] | None = None, warnings: tuple[str, ...] = ()) -> str:
    analysis = {
        "capture": {"filename": "test.pcap", "packet_count": 2},
        "findings": findings if findings is not None else [],
    }
    return render_markdown(analysis, generated_at=GENERATED_AT, warnings=warnings)


def _headers(text: str) -> list[str]:
    return HEADER_PATTERN.findall(text)


def _section_bodies(text: str) -> list[str]:
    """Returns the body of every section (between one header and the next, and
    for the last section up to the end of the text), whitespace stripped."""
    matches = list(HEADER_PATTERN.finditer(text))
    bodies: list[str] = []
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        bodies.append(text[start:end].strip())
    return bodies


# --- REPORT-01: dokladnie szesc naglowkow, w kolejnosci SECTIONS -----------


def test_six_sections_present():
    text = _render(findings=[_finding()])

    headers = _headers(text)

    assert tuple(headers) == SECTIONS


def test_no_duplicate_section_headers():
    text = _render(findings=[_finding()])

    headers = _headers(text)

    assert len(headers) == len(set(headers))


# --- REPORT-01, edge: adjacency - no section is left empty -----------------


def test_no_section_is_left_without_content():
    text = _render(findings=[_finding()])

    bodies = _section_bodies(text)

    assert len(bodies) == len(SECTIONS)
    for section_name, body in zip(SECTIONS, bodies):
        assert body, f"Section '{section_name}' is empty"


def test_no_section_is_left_without_content_when_no_findings():
    text = _render(findings=[])

    bodies = _section_bodies(text)

    assert len(bodies) == len(SECTIONS)
    for section_name, body in zip(SECTIONS, bodies):
        assert body, f"Section '{section_name}' is empty"


# --- REPORT-01, edge: empty - a report with no findings says so outright --


def test_empty_findings_list_still_has_all_six_sections_and_explicit_statement():
    text = _render(findings=[])

    headers = _headers(text)
    assert tuple(headers) == SECTIONS

    findings_body = _section_bodies(text)[SECTIONS.index("Findings")]
    assert "no findings" in findings_body.lower()


# --- Model z jednym findingiem: pola dowodu i znacznik nieweryfikacji ------


def test_one_finding_section_carries_evidence_clause_and_unverified_marker():
    text = _render(findings=[_finding()])

    findings_body = _section_bodies(text)[SECTIONS.index("Findings")]

    assert "packet no. 1" in findings_body
    assert "session no. 0" in findings_body
    assert "SR 1.1" in findings_body
    assert "Human user identification and authentication" in findings_body
    assert "Paraphrase of the clause" in findings_body
    assert "PROVISIONAL" in findings_body
    assert "UNVERIFIED" in findings_body


# --- G-04-5b: linia uczestnikow sesji, przed linia dowodu ------------------


def test_session_parties_line_builds_source_arrow_target():
    evidence = {"packet_number": 1, "session_id": 0, "source": "A:1", "target": "B:2"}

    line = session_parties_line(evidence)

    assert line == "Session parties: A:1 -> B:2"


def test_finding_block_carries_session_parties_line_before_evidence_line():
    text = _render(findings=[_finding()])

    findings_body = _section_bodies(text)[SECTIONS.index("Findings")]

    assert "Session parties: 10.0.0.1:502 -> 10.0.0.2:50210" in findings_body
    parties_pos = findings_body.index("Session parties:")
    evidence_pos = findings_body.index("Evidence:")
    assert parties_pos < evidence_pos


def test_five_findings_of_same_check_have_five_distinct_session_parties_lines():
    """Five findings of the same check in one run carry five different session
    parties lines when the sessions differ (the <behavior> block of task 1 of
    plan 04-09)."""
    findings = [
        _finding(
            evidence={
                "packet_number": i,
                "session_id": i,
                "source": "10.0.0.1:502",
                "target": f"10.0.0.{i + 2}:502",
            }
        )
        for i in range(5)
    ]

    text = _render(findings=findings)

    findings_body = _section_bodies(text)[SECTIONS.index("Findings")]
    parties_lines = [
        line for line in findings_body.splitlines() if line.startswith("- Session parties:")
    ]
    assert len(parties_lines) == 5
    assert len(set(parties_lines)) == 5


# --- citation_line i citation_scope_line: prowieniencja tytulu (G-04-3c) --


def _ref(**overrides) -> dict:
    base = {
        "standard": "IEC-62443-3-3",
        "clause": "SR 1.1",
        "clause_title": "Clause title",
        "clause_title_source": "copy",
    }
    base.update(overrides)
    return base


def test_citation_line_carries_title_for_copy_provenance():
    line = citation_line(_ref(clause_title_source="copy"))

    assert "IEC-62443-3-3" in line
    assert "SR 1.1" in line
    assert "Clause title" in line


def test_citation_line_omits_title_for_own_provenance():
    line = citation_line(_ref(clause_title_source="own"))

    assert "IEC-62443-3-3" in line
    assert "SR 1.1" in line
    assert "Clause title" not in line


def test_citation_scope_line_is_none_for_copy_provenance():
    assert citation_scope_line(_ref(clause_title_source="copy")) is None


def test_citation_scope_line_carries_label_and_title_for_own_provenance():
    line = citation_scope_line(_ref(clause_title_source="own"))

    assert line is not None
    assert CITATION_SCOPE_LABEL in line
    assert "Clause title" in line


def test_own_provenance_finding_has_no_line_with_both_clause_and_title():
    """A collective proof over the hand-built model: an entry of own provenance
    has not a single line carrying both a clause number and a title
    (G-04-3c)."""
    finding = _finding(
        standard_refs=[
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Title of our own description",
                "clause_title_source": "own",
                "paraphrase": "Paraphrase of the clause, not a quote of the original.",
                "verified": False,
                "verification_note": "Provisional numbering.",
            }
        ]
    )
    text = _render(findings=[finding])
    findings_body = _section_bodies(text)[SECTIONS.index("Findings")]

    for line in findings_body.splitlines():
        if "SR 1.1" in line:
            assert "Title of our own description" not in line
    assert CITATION_SCOPE_LABEL in findings_body
    assert "Title of our own description" in findings_body


# --- The methodology section carries the text of every rubric criterion ---


def test_methodology_section_carries_every_rubric_criterion():
    text = _render(findings=[])

    methodology_body = _section_bodies(text)[SECTIONS.index("Methodology")]

    for criterion_text in risk.RUBRIC_CRITERIA.values():
        assert criterion_text in methodology_body


# --- Prohibicje REPORT-01: brak werdyktu, brak wskaznika liczbowego --------


def test_report_makes_no_compliance_claim():
    text_with_finding = _render(findings=[_finding()])
    text_without_finding = _render(findings=[])

    for text in (text_with_finding, text_without_finding):
        lowered = text.lower()
        for word in VERDICT_WORDS:
            assert word not in lowered, f"Slowo werdyktu '{word}' w raporcie"
        assert NUMERIC_SCORE_PATTERN.search(text) is None, (
            "Wzorzec zbiorczego wskaznika liczbowego w raporcie"
        )


# --- Determinizm renderowania: czysta funkcja, zero stanu ------------------


def test_render_markdown_is_deterministic_for_same_model_and_timestamp():
    findings = [_finding()]

    first = render_markdown(
        {"capture": {"filename": "test.pcap", "packet_count": 2}, "findings": findings},
        generated_at=GENERATED_AT,
    )
    second = render_markdown(
        {"capture": {"filename": "test.pcap", "packet_count": 2}, "findings": findings},
        generated_at=GENERATED_AT,
    )

    assert first == second


# --- FLOW-03/REPORT-02: sekcja ograniczen (plan 03-07, Task 3) --------------


def _host(*, ip: str, mac_known: bool = True) -> dict:
    return {
        "ip": {"value": ip, "provenance": "observed"},
        "mac": (
            {"value": "02:00:00:00:00:01", "provenance": "observed"}
            if mac_known
            else {"value": None, "provenance": "not-derivable-passively"}
        ),
    }


def _matrix_row() -> dict:
    return {
        "session_id": {"value": 0, "provenance": "observed"},
        "source": {"value": "192.0.2.10:1024", "provenance": "observed"},
        "target": {"value": "192.0.2.20:502", "provenance": "observed"},
        "direction": {
            "value": "192.0.2.10:1024 -> 192.0.2.20:502",
            "provenance": "observed",
        },
        "initiator": {"value": None, "provenance": "not-derivable-passively"},
        "protocol": {"value": "tcp", "provenance": "observed"},
        "volume_bytes": {"value": 100, "provenance": "observed"},
        "packet_count": {"value": 2, "provenance": "observed"},
    }


def _limitations_body(analysis: dict, warnings: tuple[str, ...] = ()) -> str:
    text = render_markdown(analysis, generated_at=GENERATED_AT, warnings=warnings)
    bodies = _section_bodies(text)
    return bodies[SECTIONS.index("Limitations")]


def test_collect_not_derivable_fields_on_model_without_sections_is_empty():
    assert collect_not_derivable_fields({}) == []
    assert collect_not_derivable_fields({"assets": [], "comm_matrix": []}) == []


def test_collect_not_derivable_fields_on_fully_determined_model_is_empty():
    analysis = {"assets": [_host(ip="192.0.2.10")], "comm_matrix": []}

    assert collect_not_derivable_fields(analysis) == []


def test_collect_not_derivable_fields_counts_entries_and_total():
    analysis = {
        "assets": [_host(ip="192.0.2.10", mac_known=False), _host(ip="192.0.2.20")]
    }

    rows = collect_not_derivable_fields(analysis, sections=("assets",))

    assert rows == [{"section": "assets", "field": "mac", "count": 1, "total": 2}]


def test_collect_not_derivable_fields_is_sorted_by_section_then_field():
    analysis = {
        "assets": [_host(ip="192.0.2.10", mac_known=False)],
        "comm_matrix": [_matrix_row()],
    }

    rows = collect_not_derivable_fields(analysis)

    assert [(row["section"], row["field"]) for row in rows] == sorted(
        (row["section"], row["field"]) for row in rows
    )


def test_same_field_name_in_two_sections_gives_two_separate_rows():
    analysis = {
        "assets": [
            {"role": {"value": None, "provenance": "not-derivable-passively"}}
        ],
        "comm_matrix": [
            {"role": {"value": None, "provenance": "not-derivable-passively"}}
        ],
    }

    rows = collect_not_derivable_fields(analysis)

    assert len(rows) == 2
    assert {row["section"] for row in rows} == {"assets", "comm_matrix"}


def test_vantage_point_limitations_carries_every_constant_sentence():
    lines = vantage_point_limitations(
        host_count=2, session_count=1, payloadless_session_count=0, window_duration_s=1.5
    )

    for sentence in VANTAGE_POINT_LIMITATIONS:
        assert sentence in lines


def test_vantage_point_limitations_carries_numbers_of_this_run():
    lines = vantage_point_limitations(
        host_count=7, session_count=3, payloadless_session_count=0, window_duration_s=2.5
    )
    joined = " ".join(lines)

    assert "7" in joined
    assert "3" in joined
    assert "2.5" in joined


def test_vantage_point_limitations_without_window_says_so_instead_of_empty_value():
    lines = vantage_point_limitations(
        host_count=0, session_count=0, payloadless_session_count=0, window_duration_s=None
    )
    joined = " ".join(lines)

    assert "was not established" in joined
    assert "None" not in joined


def test_limitations_section_names_blind_spots():
    analysis = {
        "capture": {"filename": "x.pcap", "packet_count": 2},
        "findings": [],
        "assets": [_host(ip="192.0.2.10", mac_known=False)],
        "comm_matrix": [_matrix_row()],
    }
    warnings = tuple(
        vantage_point_limitations(
            host_count=1,
            session_count=1,
            payloadless_session_count=0,
            window_duration_s=1.0,
        )
    )

    body = _limitations_body(analysis, warnings=warnings)

    for sentence in VANTAGE_POINT_LIMITATIONS:
        assert sentence in body
    assert "section `assets`, field `mac`: 1 of 1 entries" in body
    assert "section `comm_matrix`, field `initiator`: 1 of 1 entries" in body


def test_limitations_section_states_explicitly_when_nothing_is_undetermined():
    analysis = {
        "capture": {"filename": "x.pcap", "packet_count": 2},
        "findings": [],
        "assets": [_host(ip="192.0.2.10")],
        "comm_matrix": [],
    }

    body = _limitations_body(analysis)

    assert (
        "every field of the inventory and communication matrix sections was "
        "established" in body
    )


def test_report_makes_no_completeness_claim():
    """Machine gate FLOW-03. The list is read from the production module rather
    than retyped here: a copy would drift at the first entry added."""
    analysis = {
        "capture": {"filename": "x.pcap", "packet_count": 2},
        "findings": [],
        "assets": [_host(ip="192.0.2.10", mac_known=False)],
        "comm_matrix": [_matrix_row()],
    }
    warnings = tuple(
        vantage_point_limitations(
            host_count=1,
            session_count=1,
            payloadless_session_count=1,
            window_duration_s=1.0,
        )
    )

    text = render_markdown(analysis, generated_at=GENERATED_AT, warnings=warnings).lower()

    for term in COMPLETENESS_CLAIM_TERMS:
        assert term.lower() not in text


# --- G-04-5a: the aggregated remediation section without repetitions -------


def test_aggregated_remediations_collapses_identical_remediations_with_count():
    findings = [{"remediation": "X"}, {"remediation": "X"}, {"remediation": "X"}]

    assert aggregated_remediations(findings) == [("X", 3)]


def test_aggregated_remediations_keeps_first_occurrence_order():
    findings = [
        {"remediation": "A"},
        {"remediation": "B"},
        {"remediation": "A"},
    ]

    assert aggregated_remediations(findings) == [("A", 2), ("B", 1)]


def test_aggregated_remediations_treats_shared_prefix_as_two_distinct_entries():
    """Assumption Z-94: two remediations differing only in their ending are two
    distinct entries - deduplication goes by the whole string, never by a
    prefix."""
    findings = [
        {"remediation": "Segment the network"},
        {"remediation": "Segment the network and the conduit"},
    ]

    assert aggregated_remediations(findings) == [
        ("Segment the network", 1),
        ("Segment the network and the conduit", 1),
    ]


def test_aggregated_remediations_on_empty_list_is_empty_list():
    assert aggregated_remediations([]) == []


def test_finding_genitive_phrase_singular_for_one():
    assert finding_genitive_phrase(1) == "1 finding"


def test_finding_genitive_phrase_plural_for_every_other_count():
    """English plural has no exception for 12-14 - the Polish original of
    this function did, and this test is what proved the rule collapsed
    correctly when the report moved to English."""
    for count in (2, 5, 12, 13, 14, 22, 100):
        assert finding_genitive_phrase(count) == f"{count} findings", count


def _analyzable_fixtures() -> list[Path]:
    """The `tests/test_report_forbidden_phrases.py::_analyzable_fixtures`
    pattern - the list is built by GLOB, not by naming the files by hand."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (the D-01 gate)")


def _remediation_section_rows(report_markdown: str) -> list[str]:
    section = report_markdown.split(f"## {SECTIONS[7]}", 1)[1]
    return [line for line in section.splitlines() if line.startswith("- ")]


@pytest.mark.parametrize("fixture", _analyzable_fixtures(), ids=lambda path: path.name)
def test_remediations_section_has_no_duplicate_rows(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    rows = _remediation_section_rows(result.report_markdown)

    assert len(rows) == len(set(rows)), f"{fixture.name}: {rows}"
