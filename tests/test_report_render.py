"""Bramka maszynowa REPORT-01: raport markdown szesciosekcyjny (plan 02-04).

Model wejsciowy jest budowany recznie w tym pliku, przez funkcje pomocnicze
`_render` i `_finding` - `render_markdown` jest funkcja nad slownikiem, a
dowod przez caly potok (plik pcap -> CLI -> report.md) juz istnieje w
`tests/test_analyze_pipeline.py`. `test_six_sections_present` i
`test_report_makes_no_compliance_claim` sa czescia kontraktu wymaganie
na test z `02-VALIDATION.md`, nazwy nie sa zmieniane.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from wayside import risk
from wayside.flow import (
    COMPLETENESS_CLAIM_TERMS,
    VANTAGE_POINT_LIMITATIONS,
    vantage_point_limitations,
)
from wayside.model import collect_not_derivable_fields
from wayside.report import SECTIONS, render_markdown

GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Slowa werdyktu, jako dane testowe - nie literaly rozsiane po asercjach.
# Zawiera tez rdzenie polskie, ktore lapia odmiane ("zgodnosci", "niezgodne").
VERDICT_WORDS: tuple[str, ...] = (
    "zgodny",
    "niezgodny",
    "zgodnosc",
    "niezgodnosc",
    "compliant",
    "non-compliant",
)

# Wzorzec zbiorczego wskaznika liczbowego w postaci "liczba / 100".
NUMERIC_SCORE_PATTERN = re.compile(r"\b\d{1,3}\s*/\s*100\b")

HEADER_PATTERN = re.compile(r"^## (.+)$", flags=re.MULTILINE)


def _finding(**overrides) -> dict:
    """Buduje jeden finding w ksztalcie slownika, dokladnie jak
    `dataclasses.asdict(model.Finding(...))` w `pipeline.py`."""
    base = {
        "check_id": "modbus-unauthenticated-write",
        "title": "Operacja zapisu do sterownika przez Modbus/TCP bez uwierzytelnienia",
        "severity": "high",
        "risk": "wysokie",
        "rationale": "Wlasna analiza zaobserwowanego ruchu, nie cytat z normy.",
        "standard_refs": [
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "paraphrase": "Parafraza punktu normy, nie cytat oryginalu.",
                "verified": False,
                "verification_note": "Numeracja prowizoryczna, czeka na zestawienie z legalnym egzemplarzem normy.",
            }
        ],
        "evidence": {"packet_number": 1, "session_id": 0},
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
    """Zwraca tresc kazdej sekcji (miedzy jednym naglowkiem a nastepnym,
    a dla ostatniej sekcji do konca tekstu), po odcieciu bialych znakow."""
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


# --- REPORT-01, edge: adjacency - zadna sekcja nie zostaje pusta -----------


def test_no_section_is_left_without_content():
    text = _render(findings=[_finding()])

    bodies = _section_bodies(text)

    assert len(bodies) == len(SECTIONS)
    for section_name, body in zip(SECTIONS, bodies):
        assert body, f"Sekcja '{section_name}' jest pusta"


def test_no_section_is_left_without_content_when_no_findings():
    text = _render(findings=[])

    bodies = _section_bodies(text)

    assert len(bodies) == len(SECTIONS)
    for section_name, body in zip(SECTIONS, bodies):
        assert body, f"Sekcja '{section_name}' jest pusta"


# --- REPORT-01, edge: empty - raport bez findingow ma jawne zdanie --------


def test_empty_findings_list_still_has_all_six_sections_and_explicit_statement():
    text = _render(findings=[])

    headers = _headers(text)
    assert tuple(headers) == SECTIONS

    findings_body = _section_bodies(text)[SECTIONS.index("Findingi")]
    assert "brak" in findings_body.lower()


# --- Model z jednym findingiem: pola dowodu i znacznik nieweryfikacji ------


def test_one_finding_section_carries_evidence_clause_and_unverified_marker():
    text = _render(findings=[_finding()])

    findings_body = _section_bodies(text)[SECTIONS.index("Findingi")]

    assert "pakiet nr 1" in findings_body
    assert "sesja nr 0" in findings_body
    assert "SR 1.1" in findings_body
    assert "Human user identification and authentication" in findings_body
    assert "Parafraza punktu normy" in findings_body
    assert "PROWIZORYCZNE" in findings_body
    assert "NIEZWERYFIKOWANE" in findings_body


# --- Sekcja metodyki niesie tresc kazdego kryterium rubryki ----------------


def test_methodology_section_carries_every_rubric_criterion():
    text = _render(findings=[])

    methodology_body = _section_bodies(text)[SECTIONS.index("Metodyka")]

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
    return bodies[SECTIONS.index("Ograniczenia")]


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

    assert "nie zostalo ustalone" in joined
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
    assert "sekcja `assets`, pole `mac`: 1 z 1 wpisow" in body
    assert "sekcja `comm_matrix`, pole `initiator`: 1 z 1 wpisow" in body


def test_limitations_section_states_explicitly_when_nothing_is_undetermined():
    analysis = {
        "capture": {"filename": "x.pcap", "packet_count": 2},
        "findings": [],
        "assets": [_host(ip="192.0.2.10")],
        "comm_matrix": [],
    }

    body = _limitations_body(analysis)

    assert "kazde pole sekcji inwentarza i macierzy komunikacji zostalo ustalone" in body


def test_report_makes_no_completeness_claim():
    """Bramka maszynowa FLOW-03. Lista czytana z modulu produkcyjnego, nie
    przepisana tutaj: kopia rozjedzie sie przy pierwszym dopisanym wpisie."""
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
