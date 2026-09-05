"""Bramka jednej ortografii tekstu wychodzacego do dokumentu (REPORT-03,
G-04-4).

Konwencja: caly tekst, ktory laduje w `report.md` albo w `report.pdf`,
niesie pelna polszczyzne z diakrytyka, w postaci znormalizowanej NFC.
Zrodlem tej konwencji jest REPORT-03 ("Raport eksportuje sie do PDF z
poprawnymi polskimi znakami") - wariant bezdiakrytyczny wprost by mu
przeczyl.

Trzy bramki, kazda pokrywajaca inna czesc powierzchni, i to, czego KAZDA
z nich NIE lapie.

1. **Pola YAML** (katalog norm, pliki checkow). Nie ma progu ani wyjatkow -
   kazde z tych pol jest dlugim zdaniem po polsku, wiec brak choc jednego
   znaku diakrytycznego jest w tym korpusie zawsze bledem. NIE lapie: pol
   spoza `DOCUMENT_TEXT_YAML_FIELDS` (np. `standard`, `clause`, `verified`)
   - to sa identyfikatory danych, nie proza.

2. **Dluga proza w kodzie** (`DOCUMENT_TEXT_MODULES`). Parsuje kazdy modul
   drzewem skladni, zbiera kazda stala lancuchowa (takze czesci literalne
   f-stringow), wyklucza docstringi i lancuchy ponizej progu dlugosci/liczby
   wyrazow. NIE lapie: krotkich wartosci slownikowych (np. etykiet statusu)
   - od tego jest bramka trzecia, bez progu.

3. **Wynik renderowania** (kazdy analizowalny fixture, plus zacommitowany
   `examples/4sics/report.md` i warstwa tekstowa `examples/4sics/report.pdf`).
   Slownik wszystkich wyrazow niosacych diakrytyke ze wszystkich zrodel
   tekstu dokumentowego (bramki 1 i 2, bramka 2 tu BEZ progu dlugosci),
   zlozony do ASCII malymi literami. Wyraz BEZ diakrytyki w wyniku, ktorego
   forma zlozona rowna sie formie ze slownika, jest naruszeniem - chyba ze
   stoi na `ORTHOGRAPHY_ALLOWLIST`.

   **Ryzyko rezydualne (zalozenie Z-87), nazwane wprost, nie obiecane:**
   slowo, ktore w CALYM projekcie wystepuje WYLACZNIE bez diakrytyki, nie ma
   bliznika w slowniku i nie zostanie zlapane przez ta bramke. Pierwsze
   wypelnienie slownika po przejsciu calego zamiatania (ten plan) pokrywa
   dzisiejszy tekst; slowo dopisane pozniej wylacznie bezdiakrytycznie
   przejdzie bramke trzecia bez ostrzezenia. Bramka druga lapie ten przypadek
   dla zdan (dlugich stalych w kodzie), ale nie dla pojedynczej, krotkiej
   wartosci slownikowej dopisanej bez towarzyszacego zdania.

`ORTHOGRAPHY_ALLOWLIST` startuje PUSTA (zalozenie Z-88) i rosnie wylacznie
o pozycje z komentarzem podajacym powod - lista zalozona z gory jest
sposobem na przejscie bramki bez naprawienia czegokolwiek.

**Dwa testy nad `examples/4sics/*` (`test_committed_example_report_*`) sa
swiadomie pominiete w tym pliku pytest.ini/CLI podczas planu 04-08 Task 2**
(deselect w komendach weryfikacji tego zadania) - artefakty przykladu sa
regenerowane RAZ, jako zadanie 3 tego planu (zalozenie Z-89), i do tego
momentu niosa stara, bezdiakrytyczna proze. Zadanie 3 uruchamia `uv run
pytest -q` bez zadnego deselect - w tamtym momencie oba testy musza byc
zielone nad zregenerowanymi artefaktami.
"""

from __future__ import annotations

import ast
import re
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import pytest
import yaml
from pypdf import PdfReader

from wayside.checks import engine
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
EXAMPLE_DIR = REPO_ROOT / "examples" / "4sics"
EXAMPLE_REPORT_MD = EXAMPLE_DIR / "report.md"
EXAMPLE_REPORT_PDF = EXAMPLE_DIR / "report.pdf"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# Zamrozony zbior osiemnastu polskich znakow diakrytycznych, w obu
# wielkosciach.
POLISH_DIACRITICS: frozenset[str] = frozenset("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")

# Tablica tlumaczenia znakow do skladania z diakrytyka do ASCII. Rozklad
# kanoniczny Unicode (NFKD) NIE wystarcza: litera przekreslona (ł/Ł) nie ma
# ZADNEJ dekompozycji kanonicznej w Unicode - przekreslenie nie jest
# technicznie znakiem diakrytycznym, tylko modyfikacja ksztaltu litery, wiec
# `unicodedata.normalize("NFKD", "ł")` zwraca "ł" bez zmian. Explicite
# wpisana tablica dziala identycznie dla wszystkich dziewieciu liter.
ASCII_FOLD_MAP: dict[int, str] = str.maketrans(
    {
        "ą": "a", "ć": "c", "ę": "e", "ł": "l", "ń": "n",
        "ó": "o", "ś": "s", "ź": "z", "ż": "z",
        "Ą": "A", "Ć": "C", "Ę": "E", "Ł": "L", "Ń": "N",
        "Ó": "O", "Ś": "S", "Ź": "Z", "Ż": "Z",
    }
)

# Modulow tekstu dokumentowego. Lista RECZNA, nie odkrywanie automatyczne
# (w odroznieniu od `discover_checks` czy `load_catalog`) - modul emitujacy
# tekst dokumentowy dopisany pozniej trzeba dopisac tutaj recznie, inaczej
# bramka druga i trzecia cicho przestana go pokrywac.
#
# `pipeline.py` DOPISANY WZGLEDEM planu 04-08 (deviation Rule 1/2, nie w
# oryginalnym polu <files> zadania 2): cztery zdania ostrzezen budowane w
# `analyze()` (D-01 zrzut pusty, brak rozpoznanego protokolu, snaplen
# obcinajacy ramki, zdarzenie niskiej pewnosci) trafiaja do sekcji
# "Ograniczenia" raportu przez `warnings`, wiec sa tym samym tekstem
# dokumentowym co reszta listy - odkryte empirycznie bramka trzecia tego
# pliku (bezdiakrytyczny biznik w wyrenderowanym `report.md` fixture'u
# `snaplen_truncated_frames.pcap`), nie zalozone z gory.
DOCUMENT_TEXT_MODULES: tuple[Path, ...] = (
    REPO_ROOT / "src" / "wayside" / "report.py",
    REPO_ROOT / "src" / "wayside" / "report_pdf.py",
    REPO_ROOT / "src" / "wayside" / "flow.py",
    REPO_ROOT / "src" / "wayside" / "risk.py",
    REPO_ROOT / "src" / "wayside" / "coverage.py",
    REPO_ROOT / "src" / "wayside" / "assets" / "inventory.py",
    REPO_ROOT / "src" / "wayside" / "pipeline.py",
)

# Odwzorowanie nazw pol dokumentowych na typ pliku YAML.
DOCUMENT_TEXT_YAML_FIELDS: dict[str, tuple[str, ...]] = {
    "check": ("title", "rationale", "remediation"),
    "catalog": ("clause_title", "paraphrase", "verification_note", "paraphrase_note"),
}

# Progi bramki druga (dluga proza w kodzie).
PROSE_MIN_CHARS = 40
PROSE_MIN_TOKENS = 6

# Lista wyjatkow, wspolna dla bramki druga (dluga proza w kodzie - dopasowanie
# na CALYM lancuchu) i bramki trzecia (wynik renderowania - dopasowanie na
# POJEDYNCZYM wyrazie zlozonym do ASCII i zmalowanym). Startuje PUSTA
# (zalozenie Z-88) i rosnie wylacznie o pozycje z komentarzem podajacym powod
# - lista zalozona z gory jest sposobem na przejscie bramki bez naprawienia
# czegokolwiek. Obie pozycje ponizej sa POPRAWNIE napisanym polskim zdaniem,
# ktore po prostu nie zawiera zadnego z osiemnastu polskich znakow
# diakrytycznych - zaden wyraz w nich nie ma diakrytyka w poprawnej pisowni,
# wiec nie ma czego "naprawiac".
ORTHOGRAPHY_ALLOWLIST: tuple[str, ...] = (
    # `report_pdf.py::_require_font_files` - komunikat bledu operacyjnego
    # dla operatora/dewelopera (brak pliku fontu w srodowisku), nigdy tekst
    # trafiajacy do report.md/report.pdf.
    "Brak pliku fontu wymaganego do renderowania PDF: ",
    # `assets/inventory.py::_role_evidence_field` - druga polowa zdania po
    # interpolacji {sent}; zaden wyraz w tym fragmencie nie niesie
    # diakrytyka w poprawnej pisowni (pierwsza polowa tego samego zdania,
    # "Zadania Modbus wysłane...", juz go niesie).
    "; zadania Modbus odebrane przez ten adres: ",
    # Falszywy alarm bramki trzecia (odmiana przez przypadki, nie brakujaca
    # diakrytyka): "brama" (mianownik, etykieta pola "- Brama: ...") jest
    # POPRAWNIE napisane bez diakrytyka - koliduje wylacznie z "bramą"
    # (narzednik, `flow.VANTAGE_POINT_LIMITATIONS`: "za bramą protokołu"),
    # inna forma gramatyczna TEGO SAMEGO rdzenia. Obie formy sa poprawna
    # polszczyzna jednoczesnie.
    "brama",
    # To samo zjawisko: "niska" (mianownik zenski, etykieta pewnosci roli
    # `assets/inventory.py::CONFIDENCE_LEVELS`) koliduje z "niską"
    # (narzednik, `report.py`: "z niską pewnością"). Obie formy poprawne.
    "niska",
)

_WORD_PATTERN = re.compile(r"[^\W\d_]+", re.UNICODE)


def _words(text: str) -> list[str]:
    return _WORD_PATTERN.findall(text)


def _has_diacritic(word: str) -> bool:
    return any(ch in POLISH_DIACRITICS for ch in word)


def _fold(word: str) -> str:
    return word.translate(ASCII_FOLD_MAP).lower()


def _check_specs() -> list[dict]:
    """Surowe slowniki odczytane z kazdego pliku YAML pod katalogiem
    checkow - wzorzec `tests/test_standards_catalog.py::check_specs`."""
    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(engine.CHECKS_ROOT.rglob("*.yaml"))
    ]


def _analyzable_fixtures() -> list[Path]:
    """Kazdy fixture z katalogu, ktory konczy analize bez wyjatku - wzorzec
    `tests/test_report_forbidden_phrases.py::_analyzable_fixtures`."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} nie produkuje artefaktow (brama D-01)")


def _docstring_constant_ids(tree: ast.AST) -> set[int]:
    """Zbiera `id()` wezlow `Constant` bedacych docstringiem modulu, klasy
    albo funkcji - pierwsza instrukcja ciala, gdy jest `Expr(Constant(str))`.
    Docstringi sa tekstem dla dewelopera, nie dla czytelnika raportu, i sa
    poza zakresem bramki druga i trzecia."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            ids.add(id(first.value))
    return ids


def _string_constants(module_path: Path) -> list[tuple[int, str]]:
    """Kazda stala lancuchowa modulu (w tym czesci literalne f-stringow),
    z numerem linii, z pominieciem docstringow. BEZ progu dlugosci - progi
    sa stosowane osobno przez wywolujacego, zaleznie od bramki."""
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_path))
    docstring_ids = _docstring_constant_ids(tree)
    results: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstring_ids:
                continue
            results.append((node.lineno, node.value))
    return results


def _prose_strings(module_path: Path) -> list[tuple[int, str]]:
    """Podzbior `_string_constants` powyzej progu dlugosci i liczby wyrazow -
    wejscie bramki druga."""
    return [
        (lineno, text)
        for lineno, text in _string_constants(module_path)
        if len(text) >= PROSE_MIN_CHARS and len(text.split()) >= PROSE_MIN_TOKENS
    ]


@lru_cache(maxsize=1)
def _dictionary_words() -> frozenset[str]:
    """Slownik wszystkich wyrazow niosacych diakrytyke ze WSZYSTKICH zrodel
    tekstu dokumentowego (pola YAML bramki 1, stale lancuchowe bramki 2 -
    tu BEZ progu dlugosci), zlozony do ASCII malymi literami. Wejscie
    bramki trzecia."""
    words: set[str] = set()

    catalog = mapper.load_catalog()
    for entry in catalog.values():
        for field in DOCUMENT_TEXT_YAML_FIELDS["catalog"]:
            value = entry.get(field)
            if not value:
                continue
            for word in _words(value):
                if _has_diacritic(word):
                    words.add(_fold(word))

    for spec in _check_specs():
        for field in DOCUMENT_TEXT_YAML_FIELDS["check"]:
            value = spec[field]
            for word in _words(value):
                if _has_diacritic(word):
                    words.add(_fold(word))

    for module_path in DOCUMENT_TEXT_MODULES:
        for _lineno, text in _string_constants(module_path):
            for word in _words(text):
                if _has_diacritic(word):
                    words.add(_fold(word))

    return frozenset(words)


def _twin_violations(text: str) -> list[tuple[str, str]]:
    dictionary_words = _dictionary_words()
    violations: list[tuple[str, str]] = []
    for word in _words(text):
        if _has_diacritic(word):
            continue
        lowered = word.lower()
        if lowered in ORTHOGRAPHY_ALLOWLIST:
            continue
        if lowered in dictionary_words:
            violations.append((word, lowered))
    return violations


# --- Mechanizm skladania do ASCII: cztery testy jednostkowe, na przypadkach
# --- spoza korpusu - porazka bramki ma dac sie odroznic od porazki jej
# --- wlasnej mechaniki. -------------------------------------------------


def test_ascii_fold_handles_stroke_letter_with_no_canonical_decomposition():
    """Litera przekreslona (ł/Ł): NFKD jej NIE rozklada, tablica MUSI."""
    assert unicodedata.normalize("NFKD", "ł") == "ł"
    assert "ł".translate(ASCII_FOLD_MAP) == "l"
    assert "Ł".translate(ASCII_FOLD_MAP) == "L"


def test_ascii_fold_handles_ogonek_letters():
    """Litera z ogonkiem (ą, ę)."""
    assert "ą".translate(ASCII_FOLD_MAP) == "a"
    assert "ę".translate(ASCII_FOLD_MAP) == "e"


def test_ascii_fold_handles_acute_and_dot_letters():
    """Litera z kreska/kropka (ć, ń, ó, ś, ź, ż)."""
    assert "ć".translate(ASCII_FOLD_MAP) == "c"
    assert "ń".translate(ASCII_FOLD_MAP) == "n"
    assert "ó".translate(ASCII_FOLD_MAP) == "o"
    assert "ś".translate(ASCII_FOLD_MAP) == "s"
    assert "ź".translate(ASCII_FOLD_MAP) == "z"
    assert "ż".translate(ASCII_FOLD_MAP) == "z"


def test_fold_helper_lowercases_and_folds_whole_word():
    assert _fold("ŻÓŁĆ") == "zolc"
    assert _fold("Zażółć") == "zazolc"


# --- Bramka pierwsza: pola dokumentowe YAML - bez progu, bez wyjatkow ----


def test_catalog_document_fields_carry_polish_diacritics():
    catalog = mapper.load_catalog()
    failures: list[str] = []
    for (standard, clause), entry in catalog.items():
        for field in DOCUMENT_TEXT_YAML_FIELDS["catalog"]:
            if field not in entry:
                continue
            value = entry[field]
            if not _has_diacritic(value):
                failures.append(f"{standard} {clause}: pole {field}")
    assert failures == [], failures


def test_check_document_fields_carry_polish_diacritics():
    failures: list[str] = []
    for spec in _check_specs():
        for field in DOCUMENT_TEXT_YAML_FIELDS["check"]:
            value = spec[field]
            if not _has_diacritic(value):
                failures.append(f"{spec['id']}: pole {field}")
    assert failures == [], failures


# --- Bramka druga: dluga proza w modulach tekstu dokumentowego ----------


def test_document_text_modules_carry_polish_diacritics_or_are_allowlisted():
    failures: list[str] = []
    for module_path in DOCUMENT_TEXT_MODULES:
        for lineno, text in _prose_strings(module_path):
            if _has_diacritic(text):
                continue
            if text in ORTHOGRAPHY_ALLOWLIST:
                continue
            failures.append(f"{module_path}:{lineno}: {text!r}")
    assert failures == [], "\n".join(failures)


# --- Bramka trzecia: wynik renderowania - brak bliznika bezdiakrytycznego -


@pytest.mark.parametrize("fixture", _analyzable_fixtures(), ids=lambda p: p.name)
def test_rendered_report_has_no_undiacriticized_twin_of_dictionary_word(
    fixture, tmp_path
):
    result = _analyze_or_skip(fixture, tmp_path)
    hits = _twin_violations(result.report_markdown)
    assert hits == [], f"{fixture.name}: {hits}"


def test_committed_example_report_markdown_has_no_undiacriticized_twin():
    text = EXAMPLE_REPORT_MD.read_text(encoding="utf-8")
    hits = _twin_violations(text)
    assert hits == [], hits


def test_committed_example_report_pdf_text_layer_has_no_undiacriticized_twin():
    reader = PdfReader(str(EXAMPLE_REPORT_PDF))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    hits = _twin_violations(text)
    assert hits == [], hits


# --- Normalizacja NFC ----------------------------------------------------


def test_rendered_report_is_nfc_normalized(tmp_path):
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    result = analyze(fixture, out_dir=tmp_path, generated_at=GENERATED_AT)
    text = result.report_markdown
    assert unicodedata.normalize("NFC", text) == text
