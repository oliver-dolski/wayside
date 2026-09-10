"""Bramka tekstowa STD-07, RISK-01 i RISK-02 nad WYNIKIEM renderowania.

Trzy rzeczy, ktore ten plik ma powiedziec wprost.

**Bramka dziala nad wynikiem, nie nad logika.** Skanuje `report.md` i tresc
`analysis.json` z PRAWDZIWEJ analizy kazdego fixture'a, nie model budowany
recznie. `tests/test_report_render.py` ma wlasny test nad modelem recznym
i ten plik go NIE zastepuje: tamten pilnuje ksztaltu renderowania, ten pilnuje
tego, co faktycznie wychodzi z potoku.

**Bramka powstala PO ustaleniu ostatecznej tresci sekcji, nie przed.** Faza 2
zaplacila juz raz za odwrotna kolejnosc: zbyt szeroki wzorzec zlapal wlasny,
poprawny tekst raportu jako naruszenie, bo zdanie wyjasniajace, czego narzedzie
NIE robi, z natury zawiera slowo, ktorego zakaz dotyczy. Dlatego ten plik
powstaje w ostatniej fali fazy 3, gdy sekcje zakresu, metodyki, inwentarza,
macierzy komunikacji i ograniczen sa juz w postaci ostatecznej.

**Zwezenia wzorca wobec listy z `03-RESEARCH.md`, kazde z powodem.**

1. Wzorzec twierdzenia o zgodnosci jest ZAKOTWICZONY na granicy slowa
   i wylicza koncowki przymiotnikowe oraz rzeczownikowe, zamiast lapac sam
   rdzen (zalozenie Z-36). Powod: rdzen bez zakotwiczenia lapie przyslowek
   uzywany w zwyklej prozie w znaczeniu "wedlug". Fragment, ktory to wymusil:
   zwrot `zgodnie z` wystepuje w zdaniach opisowych calego projektu i nie jest
   twierdzeniem o zgodnosci z norma. Przypadek negatywny ma wlasny test.

2. Wzorzec NIE obejmuje czasownika `spelnia` ani `nie spelnia` (zalozenie
   Z-37). Powod: to jest czasownik zdania z sekcji metodyki, ktore WYJASNIA,
   ze narzedzie oceny zgodnosci nie wydaje. Fragment, ktory to wymusil:
   `nigdy ocene, czy instalacja spelnia albo nie spelnia wymagan normy`
   w `src/wayside/report.py`. Zakaz szerszy niz zakazana tresc usunalby
   z raportu wlasnie te czesc, ktora tresci zakazanej najmocniej przeczy.

3. Wzorzec poziomu bezpieczenstwa wymaga CYFRY z zakresu 1-4 obok skrotu.
   Powod: sam skrot bez liczby wystepuje w powolaniach na punkt normy
   (`SR 1.1`) i w prozie o poziomach jako pojeciu, a zakazem jest przypisanie
   poziomu, nie wzmianka o jego istnieniu.

Zaden inny wzorzec z listy badania nie zostal zwezony.
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
    """Male litery i zdjete polskie znaki diakrytyczne (zalozenie Z-35).

    Sposob zdejmowania jest ten sam co w `scripts/confidentiality_guard.py`
    (`_strip_diacritics`): dwie rozne normalizacje w jednym repozytorium
    rozjezdzaja sie po pierwszej poprawce w jednej z nich. Katalog norm
    z Fazy 2 niesie prawdziwe znaki diakrytyczne, a kod zrodlowy pisze bez
    nich - wzorzec nad surowym tekstem przepuscilby jeden z tych dwoch zapisow.
    """
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


# Wzorce nad tekstem JUZ znormalizowanym, wiec bez znakow diakrytycznych
# i bez wielkich liter. Zakotwiczenie `\b` jest cala roznica miedzy dzialajaca
# bramka a generatorem falszywych alarmow - patrz zwezenie 1 w docstringu.
COMPLIANCE_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        "zgodnosc-przymiotnik-pl",
        re.compile(r"\b(?:nie)?\s*zgodn(?:y|a|e|ego|ej|ym|ymi|ych|osc|osci|oscia)\b"),
    ),
    ("compliant-en", re.compile(r"\b(?:non-?)?compliant\b")),
    ("compliance-en", re.compile(r"\bcompliance\b")),
    ("certyfikacja-pl", re.compile(r"\bcertyfik\w*\b")),
    ("certification-en", re.compile(r"\bcertif\w*\b")),
)

# Trzy zapisy liczbowego poziomu bezpieczenstwa. Cyfra jest wymagana - patrz
# zwezenie 3 w docstringu.
SECURITY_LEVEL_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("security-level-skrot", re.compile(r"\bsl[\s-]?[1-4]\b")),
    ("security-level-en", re.compile(r"\bsecurity\s+level\s*[1-4]\b")),
    ("poziom-bezpieczenstwa-pl", re.compile(r"\bpoziom\w*\s+bezpieczenstwa\s*[1-4]\b")),
)

# Zbiorczy wskaznik liczbowy w postaci ulamka ze stu. Wzorzec przeniesiony
# z `tests/test_report_render.py` (stala o tej samej nazwie) - jedno pojecie,
# ten sam zapis w obu bramkach.
NUMERIC_SCORE_PATTERN = re.compile(r"\b\d{1,3}\s*/\s*100\b")

_CONTEXT_RADIUS = 30


def scan_forbidden(
    text: str, patterns: tuple[tuple[str, re.Pattern], ...]
) -> list[tuple[str, str]]:
    """Zwraca pary `(nazwa wzorca, krotki kontekst wokol trafienia)`.

    Kontekst jest potrzebny do naprawy: bez niego komunikat testu mowi, ze cos
    jest zle, ale nie gdzie. Jednoczesnie jest KROTKI, zeby komunikat nie stal
    sie kanalem wycieku tresci - to samo napiecie, ktore
    `scripts/confidentiality_guard.py` rozstrzygnal na korzysc calkowitego
    braku pola tekstowego w `Violation`. Rozroznienie jest takie: tam wejsciem
    jest tresc normy objeta poufnoscia, tutaj wlasny raport projektu. Nie
    przenos tego rozwiazania z powrotem do tamtej bramki.
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
    ("wskaznik-liczbowy", NUMERIC_SCORE_PATTERN),
)


def _analyzable_fixtures() -> list[Path]:
    """Kazdy fixture z katalogu, ktory konczy analize bez wyjatku.

    Lista budowana GLOBEM po katalogu, nie recznym wyliczeniem nazw: lista
    reczna nie obejmie fixture'a dodanego w Fazie 4, a wtedy bramka cicho
    przestanie pokrywac nowa tresc.

    Fixture'y konczace analize wyjatkiem (zrzut obciety, uszkodzony, format
    nieobslugiwany) sa pomijane JAWNYM filtrem na dwa nazwane typy wyjatku,
    nie blokiem przechwytujacym cokolwiek - inaczej regresja w potoku ukrylaby
    sie jako "fixture bez artefaktow".
    """
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} nie produkuje artefaktow (brama D-01)")


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
    """Test PRZECIWNY: bez niego wzorzec zepsuty tak, ze nie lapie niczego,
    przechodzi caly pakiet na zielono."""
    text = "Instalacja jest zgodna z wymaganiem normy w tym zakresie."

    hits = scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS)

    assert hits
    assert hits[0][0] == "zgodnosc-przymiotnik-pl"
    assert len(hits[0][1]) < len(text) + 1


def test_scan_forbidden_rejects_a_numeric_security_level():
    """Drugi test przeciwny, dla drugiej rodziny wzorcow."""
    text = "Sterownik zostal oceniony na SL-2 w tym segmencie."

    hits = scan_forbidden(text, SECURITY_LEVEL_PATTERNS)

    assert hits
    assert hits[0][0] == "security-level-skrot"


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
    """Przypadek negatywny wymuszony przez zwezenie 1 z docstringu."""
    text = "Waga findingu wynika zgodnie z kryteriami zapisanej rubryki."

    assert scan_forbidden(text, COMPLIANCE_CLAIM_PATTERNS) == []


def test_compliance_pattern_does_not_catch_the_methodology_verb():
    """Przypadek negatywny wymuszony przez zwezenie 2 z docstringu - zdanie
    sekcji metodyki obecne w raporcie od Fazy 2, w obu wariantach."""
    for text in (
        "nigdy ocene, czy instalacja spelnia wymagania normy",
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


# --- Bramka nad wynikiem prawdziwej analizy ---------------------------------


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
    """Zalozenie Z-38: artefakt maszynowy jest publikowanym wyjsciem tak samo
    jak raport, wiec zakaz obowiazujacy tylko w jednym z dwoch bylby zakazem
    pozornym."""
    result = _analyze_or_skip(fixture, tmp_path)
    serialized = json.dumps(result.analysis, ensure_ascii=False)

    hits = scan_forbidden(serialized, ALL_PATTERNS)

    assert hits == [], f"{fixture.name}: {hits}"


# --- RISK-01: metoda oceny wagi w sekcji metodyki prawdziwego raportu -------
#
# Wartosc tego testu wobec `tests/test_report_render.py`: tamten dowodzi, ze
# renderer UMIE wypisac kryteria, ten dowodzi, ze w PRAWDZIWYM raporcie
# z prawdziwej analizy faktycznie sa. Lamie sie, gdy ktos dopisze piaty poziom
# wagi do rubryki i zapomni o raporcie - kryteria sa czytane z modulu
# produkcyjnego, nigdy z kopii w tym pliku.

HEADER_PATTERN = re.compile(r"^## (.+)$", flags=re.MULTILINE)


def _section_body(text: str, name: str) -> str:
    """Tresc jednej sekcji, od jej naglowka do nastepnego.

    Wycinanie po naglowku nie jest ostroznoscia na wyrost: zdanie kryterium
    obecne gdziekolwiek w raporcie zaliczyloby test szukajacy podciagu w calym
    tekscie, a RISK-01 mowi wprost o sekcji metodyki. Test nad calym plikiem
    przeszedlby takze wtedy, gdyby sekcja metodyki zniknela, a kryteria
    wyladowaly w zaleceniach.
    """
    matches = list(HEADER_PATTERN.finditer(text))
    for index, match in enumerate(matches):
        if match.group(1).strip() != name:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        return text[start:end]
    raise AssertionError(f"Raport nie ma sekcji '{name}'")


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_methodology_section_carries_every_rubric_criterion(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)

    body = _section_body(result.report_markdown, "Methodology")

    for severity, criterion in risk.RUBRIC_CRITERIA.items():
        assert criterion in body, f"{fixture.name}: brak kryterium dla wagi {severity}"


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
        assert severity in body, f"{fixture.name}: brak nazwy wagi {severity}"
