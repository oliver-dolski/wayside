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
        "capture": {"path": "test.pcap", "packet_count": 2},
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
        {"capture": {"path": "test.pcap", "packet_count": 2}, "findings": findings},
        generated_at=GENERATED_AT,
    )
    second = render_markdown(
        {"capture": {"path": "test.pcap", "packet_count": 2}, "findings": findings},
        generated_at=GENERATED_AT,
    )

    assert first == second
