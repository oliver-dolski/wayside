"""Bramka tresci i ksztaltu `SECURITY.md` (PUB-02, D-04 do D-09).

Ktore rozstrzygniecie realizuje kazda grupa asercji:

- D-04: dwa naglowki drugiego poziomu w kolejnosci - podatnosc w narzedziu,
  potem podatnosc w cudzej sieci. `REQUIRED_SECTION_HEADERS`.
- D-05: kanalem sekcji pierwszej jest prywatne zglaszanie podatnosci
  w zakladce bezpieczenstwa repozytorium, nigdy adres poczty elektronicznej.
  `CHANNEL_MARKERS`, `_EMAIL_SHAPE_RE`.
- D-06: dwa terminy sekcji pierwszej (potwierdzenie przyjecia, wstepna
  ocena), zaden termin poprawki, zaden program nagrod.
  `ACKNOWLEDGEMENT_WINDOW`, `ASSESSMENT_WINDOW`, `FORBIDDEN_REMEDIATION_PROMISES`.
- D-07: brak posrednictwa w cudzych sieciach, trzy wlasne drogi czytelnika.
  `COORDINATION_ROUTES`.
- D-08: plik `security.txt` wedlug RFC 9116 nie powstaje.
  `RFC9116_FORBIDDEN_PATHS`.
- D-09: jedno waskie zdanie safe harbor, ograniczone do zakresu sekcji
  pierwszej. `SAFE_HARBOR_MARKERS`.

**Ta bramka sprawdza OBECNOSC fraz i KSZTALT dokumentu, nie to, czy zdanie
mowi dokladnie to, co rozstrzygniecie nazywa.** Czy tresc czyta sie uczciwie
(np. czy zdanie o braku posrednictwa jest dostatecznie wprost) ocenia
czlowiek - kontrola reczna zapisana w `05-VALIDATION.md` pod
`## Manual-Only Verifications`, nie ten plik.

**Zamkniety zbior obietnic zakazanych (`FORBIDDEN_REMEDIATION_PROMISES`)
zyje WYLACZNIE w tym module jako jedyne zrodlo prawdy** - `SECURITY.md`
sam go nie powtarza (bramka skanuje `SECURITY.md`, nie ten modul), a gdyby
powtorzyl, bylby to duplikat, ktory rozjezdza sie po pierwszej poprawce
w jednym z dwoch miejsc. SUMMARY tego planu cytuje pelna zawartosc zbioru
razem z uzasadnieniem kazdej pozycji (wymog `<output>` planu 05-02) - to
jest bezpieczne, bo bramka skanuje wylacznie `SECURITY.md`, nie
`.planning/`.

Kazdy wzorzec ponizej jest zawezony wobec konkretnego zdania negujacego,
ktore SECURITY.md musi umiec wypowiedziec bez zapalania wlasnej bramki -
ten sam problem, ktory faza 3 zaplacila raz w
`tests/test_report_forbidden_phrases.py` (patrz docstring tamtego modulu).

Modul nie zapisuje i nie zmienia zadnego pliku w drzewie repozytorium -
przypadki negatywne budowane sa na tekscie w pamieci, nigdy przez zapis do
`SECURITY.md` (patrz `test_module_source_contains_no_file_write_calls`).
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

# Skopiowane doslownie z tests/test_readme_claims.py i
# tests/test_standard_designation_gate.py - jeden zapis tej reguly.
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

# D-05: fragmenty nazywajace kanal platformy jako jedyny kanal sekcji 1.
# Porownanie w testach idzie po normalizacji bialych znakow (_normalize_ws),
# wiec zawijanie linii markdown nie gubi dopasowania.
CHANNEL_MARKERS: tuple[str, ...] = (
    "private vulnerability reporting in the security tab of this repository",
)

# D-09: fragment waskiego zdania safe harbor.
SAFE_HARBOR_MARKERS: tuple[str, ...] = (
    "faces no claims from the author on that account",
)

# D-07: trzy nazwy publicznych punktow koordynacji, zapisane doslownie.
COORDINATION_ROUTES: tuple[str, ...] = (
    "CISA ICS-CERT",
    "CSIRT NASK",
    "CSIRT GOV",
)

# D-08: sciezki, ktorych ten plan swiadomie NIE tworzy. Absolutne, zeby
# dzialaly niezaleznie od katalogu roboczego, z ktorego wolany jest test.
RFC9116_FORBIDDEN_PATHS: tuple[str, ...] = (
    str(REPO_ROOT / "security.txt"),
    str(REPO_ROOT / ".well-known" / "security.txt"),
)

# Ksztalt adresu poczty elektronicznej: czesc lokalna, znak malpy, domena
# z kropka. Waskie CELOWO - slowa "adres poczty elektronicznej" w prozie
# NIE zapalaja tego wzorca, bo dokument ma prawo tlumaczyc, dlaczego adresu
# nie ma.
_EMAIL_SHAPE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _security_text() -> str:
    return SECURITY_PATH.read_text(encoding="utf-8")


def _section_body(text_or_header, header: str | None = None) -> str:
    """Tresc sekcji `header` od konca linii naglowka do poczatku nastepnego
    naglowka drugiego poziomu (albo konca tekstu).

    Wywolywalna na dwa sposoby, zeby przypadki negatywne mogly dzialac na
    dowolnym tekscie w pamieci (wzorzec `tests/test_readme_claims.py::_section_body`):
    `_section_body(header)` operuje na `_security_text()`, a
    `_section_body(text, header)` na podanym tekscie.
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
    raise AssertionError(f"Tekst nie ma sekcji {header!r}.")


# --- Plik istnieje, ma dokladnie dwa naglowki, w kolejnosci ----------------


def test_security_file_exists():
    assert SECURITY_PATH.is_file(), f"{SECURITY_PATH} nie istnieje."


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


# --- D-06: dwa terminy sekcji pierwszej -------------------------------------


def test_section_one_body_carries_acknowledgement_window():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    found = ACKNOWLEDGEMENT_WINDOW in body
    assert found, "Sekcja 1 nie niesie fragmentu ACKNOWLEDGEMENT_WINDOW."


def test_section_one_body_carries_assessment_window():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    found = ASSESSMENT_WINDOW in body
    assert found, "Sekcja 1 nie niesie fragmentu ASSESSMENT_WINDOW."


def test_assessment_and_acknowledgement_windows_do_not_leak_into_section_two():
    body = _section_body(REQUIRED_SECTION_HEADERS[1])
    acknowledgement_leaked = ACKNOWLEDGEMENT_WINDOW in body
    assessment_leaked = ASSESSMENT_WINDOW in body
    assert not acknowledgement_leaked, "ACKNOWLEDGEMENT_WINDOW przecieka do sekcji 2."
    assert not assessment_leaked, "ASSESSMENT_WINDOW przecieka do sekcji 2."


# --- D-06: zamkniety zbior obietnic zakazanych ------------------------------


def test_forbidden_remediation_promises_constant_has_at_least_four_entries():
    assert len(FORBIDDEN_REMEDIATION_PROMISES) >= 4


def test_security_text_carries_no_forbidden_remediation_promise():
    text = _security_text().lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in text]
    assert hits == [], f"SECURITY.md niesie obietnice zakazane: {hits}"


def test_forbidden_promise_pattern_does_not_catch_the_own_boundary_sentences():
    """Test przeciwny: zbior obietnic zakazanych nie moze zapalac sie na
    wlasnych zdaniach granicy tego samego dokumentu, ktore uzywaja tych
    samych rdzeni slow w formie negacji."""
    boundary_text = (
        "tu nie stoi zaden termin wydania poprawki. "
        "tu nie stoi zaden program wynagrodzen za zgloszenie."
    ).lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in boundary_text]
    assert hits == [], hits


def test_a_genuine_promise_sentence_is_caught_by_the_set():
    """The opposite direction: without this the gate could be empty and pass
    always, regardless of content."""
    promise_text = "the fix release window is fourteen days.".lower()
    hits = [p for p in FORBIDDEN_REMEDIATION_PROMISES if p.lower() in promise_text]
    assert hits


# --- D-05: kanal platformy, brak adresu poczty elektronicznej --------------


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
    assert not has_email_shape, "SECURITY.md niesie lancuch o ksztalcie adresu poczty."


def test_email_shape_pattern_does_not_fire_on_prose_about_email_addresses():
    """Test przeciwny: samo slowo 'adres poczty elektronicznej' w prozie nie
    ma zapalac wzorca ksztaltu adresu."""
    prose = "Dlaczego nie ma tu adresu poczty elektronicznej: kanal platformy..."
    has_email_shape = _EMAIL_SHAPE_RE.search(prose) is not None
    assert not has_email_shape


def test_email_shape_pattern_catches_a_real_looking_address():
    matched = _EMAIL_SHAPE_RE.search("kontakt: przyklad.autor@przyklad-domena.example") is not None
    assert matched


# --- D-09: zdanie safe harbor, waskie i ograniczone do sekcji 1 ------------


def test_safe_harbor_markers_constant_is_nonempty():
    assert len(SAFE_HARBOR_MARKERS) >= 1


def test_section_one_body_carries_safe_harbor_sentence():
    body = _section_body(REQUIRED_SECTION_HEADERS[0])
    normalized = re.sub(r"\s+", " ", body)
    for marker in SAFE_HARBOR_MARKERS:
        found = re.sub(r"\s+", " ", marker) in normalized
        assert found, "Sekcja 1 nie niesie jednego z SAFE_HARBOR_MARKERS."


# --- D-07: brak posrednictwa, trzy drogi czytelnika -------------------------


def test_coordination_routes_constant_has_at_least_three_entries():
    assert len(COORDINATION_ROUTES) >= 3


def test_section_two_body_carries_every_coordination_route():
    body = _section_body(REQUIRED_SECTION_HEADERS[1])
    missing = [route for route in COORDINATION_ROUTES if route not in body]
    assert missing == [], f"Sekcja 2 nie niesie drog koordynacji: {missing}"


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


# --- Test: bramka nie zapisuje niczego w drzewie ----------------------------


def test_module_source_contains_no_file_write_calls():
    """Sprawdzenie PO ZRODLE modulu, ten sam wzorzec co
    `tests/test_readme_claims.py::test_module_source_contains_no_file_write_calls`."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"Modul niesie wzorzec zapisu do pliku: {hits}"
