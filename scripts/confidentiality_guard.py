"""Bramka poufnosci: trzy warstwy detekcji doslownego tekstu normatywnego.

Ten modul jest zaleznosciowo izolowany od reszty pakietu `wayside` i uzywa
WYLACZNIE biblioteki standardowej Pythona. To jest warunek, nie preferencja:
hak pre-commit ma dzialac w srodowisku pre-commit (`language: python`, wlasny
odizolowany venv) i w repozytorium tymczasowym testu integracyjnego, bez
`uv sync` i bez sieci - dowolna zaleznosc zewnetrzna zlamalaby oba te
scenariusze.

Trzy warstwy, od najbardziej do najmniej precyzyjnej:

- Warstwa 0, sciezkowa (`path-local-corpus`): kazda sciezka pod
  `standards/.local/` jest naruszeniem, niezaleznie od tresci. Dziala takze
  na plikach binarnych (dodanych np. przez `git add -f`) i NIGDY nie
  podlega liscie wyjatkow - to jest ostatnia linia obrony dla najgorszego
  przypadku: kogos, kto probuje obejsc pozostale warstwy wprost.
- Warstwa 1, korpusowa (`corpus-shingle`): porownuje skanowany tekst
  z lokalnym, gitignorowanym katalogiem `standards/.local` przez shingle
  dwunastowyrazowe (skroty sha256, nigdy surowy tekst). Dziala WYLACZNIE
  gdy ten katalog istnieje na maszynie - a wiec NIGDY w CI, bo katalog jest
  gitignorowany i nie trafia do zdalnego repozytorium. To jest architektoniczna
  koniecznosc: CI nie moze dostac dostepu do tego katalogu bez zniweczenia
  celu bramki (przeniesienia chronionej tresci do sekretow repozytorium).
- Warstwa 2, strukturalna (`structural-clause-modal`): regex na odcisk
  jezyka normatywnego (kropkowany numer punktu + modalnosc normatywna w tej
  samej linii), dzialajacy bez zadnego korpusu - a wiec takze w CI. Jedyna
  warstwa z liscia wyjatkow (`.confidentiality-allow`), bo jest najbardziej
  podatna na falszywe alarmy na wlasnej dokumentacji projektu.

Zaden obiekt `Violation` ani zaden komunikat wypisany przez ten modul nie
niesie dopasowanego fragmentu tekstu - to jest wlasnosc typu (`Violation` nie
ma pola na tekst), nie tylko konwencja kodowania. Komunikat niesie wylacznie
sciezke, numer linii i identyfikator reguly.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Violation",
    "scan_paths",
    "scan_text_structural",
    "scan_text_corpus",
    "scan_files",
    "main",
]

# --- Stale modulu -----------------------------------------------------------

RULE_PATH_LOCAL_CORPUS = "path-local-corpus"
RULE_CORPUS_SHINGLE = "corpus-shingle"
RULE_STRUCTURAL_CLAUSE_MODAL = "structural-clause-modal"

DEFAULT_CORPUS_DIR = "standards/.local"
DEFAULT_ALLOW_FILE = ".confidentiality-allow"

LOCAL_CORPUS_PATH_PREFIX = "standards/.local"

# Rozmiar shingle'a (w slowach) dla warstwy korpusowej.
SHINGLE_SIZE = 12

# Prog dlugosci fragmentu (w znakach) dla warstwy strukturalnej. Ponizej tego
# progu kropkowany numer i modalnosc w jednej linii sa zbyt czeste (np. listy
# punktowane), zeby traktowac je jako odcisk klauzuli normatywnej.
MIN_STRUCTURAL_FRAGMENT_LENGTH = 60

# Ksztalt kropkowanego numeru punktu: dokladnie cyfry-kropka-cyfry (opcjonalnie
# wiecej segmentow), zeby sygnatury typu "62443-3-3" (myslniki, nie kropki)
# i numery wersji semantycznej same z siebie NIE zapalaly reguly - regula
# zapala sie dopiero w polaczeniu z modalnoscia normatywna w tym samym
# fragmencie (patrz NORMATIVE_MODAL_TERMS nizej).
#
# Negatywne spojrzenie wstecz na `v`/`V` odsiewa numery wersji
# oprogramowania. Doszlo razem z rozszerzeniem NORMATIVE_MODAL_TERMS
# o "must" i "should": samo rozszerzenie listy modalnosci zapalilo warstwe
# na wlasnej prozie projektu (`.planning/research/PITFALLS.md` pisze
# "CVSS v4.0 ... must be reported separately"), bo `v4.0` ma ksztalt
# kropkowanego numeru punktu. Zadna norma nie numeruje swoich klauzul
# jako `v3.4.2`, wiec to wykluczenie nic nie kosztuje po stronie detekcji.
#
# Zawezenie jest swiadomie niepelne: "Python 3.12 must ..." dalej zapali
# warstwe. Od tej reszty jest `.confidentiality-allow`, bo alternatywa -
# zgadywanie, czy kropkowana liczba jest wersja, czy punktem normy - jest
# dokladnie ta heurystyka, ktora zamienia bramke w generator szumu.
CLAUSE_NUMBER_PATTERN = re.compile(r"(?<![vV])\d+\.\d+(?:\.\d+)*")

# Modalnosc normatywna. Fragment jest normalizowany (male litery, bez
# polskich znakow diakrytycznych) przed porownaniem, wiec "nie moze" lapie
# takze "nie może", "nalezy" lapie "należy" itd. - tresc normy prawie na
# pewno ma diakrytyki, a lista ponizej jest pisana bez nich z tego samego
# powodu co reszta repozytorium (bezpieczenstwo kodowania znakow).
#
# Kolejnosc: wariant zaprzeczony przed twierdzacym, zeby dopasowanie
# zwracalo dluzszy, bardziej konkretny termin.
#
# Angielskie "must" i "should" doszly po przegladzie (CR-02 z 01-REVIEW.md):
# lista miala polskie "musi" i "powinien" od poczatku, a ich angielskich
# odpowiednikow nie - to bylo przeoczenie, nie decyzja. Waga tej luki brala
# sie stad, ze warstwa strukturalna jest JEDYNA dzialajaca w CI (korpus
# z natury nie istnieje na runnerze), wiec dziura w niej byla dziura
# w calym backstopie.
#
# Swiadomie NIE ma tu "may" ani "can": w jezyku normatywnym oznaczaja
# przyzwolenie, nie wymaganie, a wystepuja w zwyklej prozie na tyle czesto,
# ze zamienilyby te warstwe w generator falszywych alarmow.
NORMATIVE_MODAL_TERMS: tuple[str, ...] = (
    "shall not",
    "shall",
    "must not",
    "must",
    "should not",
    "should",
    "musi",
    "nie moze",
    "powinien",
    "nalezy",
    "wymaga sie",
    "zaleca sie",
)

# Fragment jest naruszeniem strukturalnym tylko w obrebie jednej linii - nigdy
# na polaczeniu wielu linii. To swiadome zawezenie: dokument prozy (README,
# pyproject.toml) zawiera mnostwo kropkowanych liczb (numery wersji) i
# pojedynczych slow modalnych rozrzuconych po calym pliku; gdyby warstwa 2
# laczyla tresc ponad granicami linii w poszukiwaniu "zdania", falszywe
# alarmy na wlasnej dokumentacji byloby regula, nie wyjatkiem (patrz zagrozenie
# T-1-guard-false-positive w PLAN.md). Kropka miedzy cyframi (numer klauzuli)
# nigdy nie konczy fragmentu - stad negatywne lookaheady/lookbehindy ponizej.
_SENTENCE_TERMINATOR_RE = re.compile(r"(?<!\d)[.!?](?!\d)")


@dataclass(frozen=True)
class Violation:
    """Jedno naruszenie bramki poufnosci.

    Celowo BRAK pola na dopasowany tekst - to jest twarda wlasnosc typu, nie
    zalecenie. Wyciek tej klasy (dopasowany fragment tresci normatywnej albo
    lokalnego korpusu w wyjsciu haka/CI) jest wtedy niemozliwy konstrukcyjnie.
    """

    path: str
    line: int | None
    layer: str
    rule_id: str
    reason: str


def _normalize_path_str(path: str) -> str:
    """Normalizuje separatory sciezki do `/`, niezaleznie od platformy."""
    return path.replace("\\", "/")


def _fold_path_for_match(path: str) -> str:
    """Normalizuje sciezke do porownania - warstwa 0 i lista wyjatkow.

    Poza separatorami zdejmuje takze wielkosc liter. Bez tego warstwa 0 da
    sie obejsc sama zmiana wielkosci liter: jedyna wspierana platforma to
    Windows, ktorego NTFS jest bezwrazliwy na wielkosc liter, a git zapisuje
    w indeksie literalna forme sciezki. `git add -f Standards/.local/x.txt`
    dodaje wiec dokladnie ten sam plik z dysku, a porownanie wrazliwe na
    wielkosc liter go nie widzi (CR-01 z 01-REVIEW.md, potwierdzone
    wywolaniem, nie lektura).

    `casefold()` zamiast `lower()`, bo jest scislejsze dla znakow spoza
    ASCII, a nazwa katalogu nie musi na zawsze zostac czysto angielska.
    """
    return _normalize_path_str(path).casefold()


def _strip_diacritics(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def scan_paths(paths: list[str]) -> list[Violation]:
    """Warstwa 0: sciezka pod `standards/.local/` jest naruszeniem zawsze.

    Dziala na samej sciezce (nie czyta zawartosci pliku), wiec obejmuje takze
    pliki binarne i pliki, ktore nie istnieja jeszcze na dysku. Nie ma tu
    zadnej listy wyjatkow - to jedyna warstwa, ktorej nie da sie obejsc
    wpisem w `.confidentiality-allow`.
    """
    violations: list[Violation] = []
    for raw_path in paths:
        normalized = _fold_path_for_match(raw_path)
        folded_prefix = LOCAL_CORPUS_PATH_PREFIX.casefold()
        if normalized == folded_prefix or normalized.startswith(folded_prefix + "/"):
            violations.append(
                Violation(
                    path=raw_path,
                    line=None,
                    layer="path",
                    rule_id=RULE_PATH_LOCAL_CORPUS,
                    reason=(
                        "Sciezka wskazuje na lokalny korpus norm "
                        "(standards/.local), ktory nigdy nie moze trafic "
                        "do repozytorium."
                    ),
                )
            )
    return violations


def _iter_structural_fragments(line: str) -> list[str]:
    """Dzieli pojedyncza linie na fragmenty ograniczone terminatorami zdan."""
    fragments: list[str] = []
    start = 0
    for match in _SENTENCE_TERMINATOR_RE.finditer(line):
        end = match.end()
        fragment = line[start:end].strip()
        if fragment:
            fragments.append(fragment)
        start = end
    tail = line[start:].strip()
    if tail:
        fragments.append(tail)
    return fragments


def scan_text_structural(text: str, path: str) -> list[Violation]:
    """Warstwa 2: kropkowany numer punktu + modalnosc normatywna w linii.

    Dziala bez zadnego korpusu - a wiec takze w CI. Fragment jest
    naruszeniem, gdy jednoczesnie: zawiera ksztalt numeru klauzuli, zawiera
    jedna z modalnosci z `NORMATIVE_MODAL_TERMS`, oba trafienia leza w tym
    samym fragmencie (linii), a fragment ma co najmniej
    `MIN_STRUCTURAL_FRAGMENT_LENGTH` znakow.
    """
    violations: list[Violation] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for fragment in _iter_structural_fragments(line):
            if len(fragment) < MIN_STRUCTURAL_FRAGMENT_LENGTH:
                continue
            if not CLAUSE_NUMBER_PATTERN.search(fragment):
                continue
            normalized = _strip_diacritics(fragment).lower()
            if not any(term in normalized for term in NORMATIVE_MODAL_TERMS):
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="structural",
                    rule_id=RULE_STRUCTURAL_CLAUSE_MODAL,
                    reason=(
                        "Fragment zawiera jednoczesnie ksztalt numeru "
                        "klauzuli i modalnosc normatywna w tej samej linii."
                    ),
                )
            )
    return violations


_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize_with_lines(text: str) -> list[tuple[str, int]]:
    """Normalizuje tekst do listy (slowo, numer_linii): male litery, bez
    interpunkcji (`\\w+` ja pomija), zwiniete biale znaki (kazde slowo jest
    juz osobnym tokenem)."""
    tokens: list[tuple[str, int]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        for match in _WORD_RE.finditer(lowered):
            tokens.append((match.group(0), line_no))
    return tokens


def _iter_shingles(
    tokens: list[tuple[str, int]], size: int = SHINGLE_SIZE
) -> list[tuple[str, int]]:
    """Zwraca (tekst_shingle'a, numer_linii_pierwszego_slowa) dla kazdego
    okna o dlugosci `size` slow w `tokens`."""
    words = [word for word, _line in tokens]
    lines = [line for _word, line in tokens]
    shingles: list[tuple[str, int]] = []
    for i in range(len(words) - size + 1):
        shingles.append((" ".join(words[i : i + size]), lines[i]))
    return shingles


def _corpus_shingle_hashes(corpus_dir: Path) -> set[str]:
    hashes: set[str] = set()
    for file_path in sorted(p for p in corpus_dir.rglob("*") if p.is_file()):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        tokens = _tokenize_with_lines(content)
        for shingle_text, _line in _iter_shingles(tokens):
            hashes.add(hashlib.sha256(shingle_text.encode("utf-8")).hexdigest())
    return hashes


def scan_text_corpus(text: str, path: str, corpus_dir: Path) -> list[Violation]:
    """Warstwa 1: shingle dwunastowyrazowe wobec lokalnego korpusu.

    Zrodlem porownania jest WYLACZNIE `corpus_dir`. Gdy katalog nie istnieje
    albo jest pusty, wypisuje na stderr jednoznaczne zdanie, ze warstwa nie
    zostala wykonana, i zwraca pusta liste - wynik czysty bez wykonanej
    warstwy korpusowej nie moze wygladac tak samo jak wynik czysty z
    wykonana warstwa korpusowa, wiec ten komunikat jest czescia kontraktu,
    nie kosmetyka.
    """
    if not corpus_dir.is_dir():
        print(
            f"[confidentiality-guard] Warstwa korpusowa POMINIETA: katalog "
            f"korpusu '{corpus_dir}' nie istnieje na tej maszynie. Ten wynik "
            f"NIE potwierdza porownania z lokalnym korpusem.",
            file=sys.stderr,
        )
        return []

    corpus_hashes = _corpus_shingle_hashes(corpus_dir)
    if not corpus_hashes:
        print(
            f"[confidentiality-guard] Warstwa korpusowa POMINIETA: katalog "
            f"korpusu '{corpus_dir}' jest pusty. Ten wynik NIE potwierdza "
            f"porownania z lokalnym korpusem.",
            file=sys.stderr,
        )
        return []

    tokens = _tokenize_with_lines(text)
    violations: list[Violation] = []
    seen_lines: set[int] = set()
    for shingle_text, line_no in _iter_shingles(tokens):
        digest = hashlib.sha256(shingle_text.encode("utf-8")).hexdigest()
        if digest not in corpus_hashes:
            continue
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        violations.append(
            Violation(
                path=path,
                line=line_no,
                layer="corpus",
                rule_id=RULE_CORPUS_SHINGLE,
                reason=(
                    "Wykryto dwunastowyrazowy fragment pokrywajacy sie "
                    "z lokalnym korpusem norm."
                ),
            )
        )
    return violations


def _load_allow_patterns(allow_file: Path) -> list[str]:
    """Wczytuje wzorce `fnmatch` z pliku wyjatkow warstwy strukturalnej.

    Puste linie i linie zaczynajace sie od `#` sa pomijane. Brak pliku
    oznacza brak wyjatkow (nie blad) - CLI woluje domyslna sciezke, ktorej
    nie musi obowiazkowo istniec.
    """
    if not allow_file.is_file():
        return []
    patterns: list[str] = []
    for raw_line in allow_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _matches_allow_list(path: str, allow_patterns: list[str]) -> bool:
    """Sprawdza sciezke wobec wzorcow wyjatkow warstwy strukturalnej.

    Porownanie jest bezwrazliwe na wielkosc liter Z ZALOZENIA, tak samo jak
    warstwa 0 - platforma docelowa to Windows, ktorego NTFS jest bezwrazliwy
    na wielkosc liter. Samo `fnmatch.fnmatch` dawaloby ten efekt tylko na
    Windows, bo zdejmuje wielkosc liter przez `os.path.normcase`; ta sama
    lista wyjatkow zachowywalaby sie inaczej na Linuksie. Jawne `casefold()`
    plus `fnmatchcase` daje jeden wynik na kazdej platformie i domyka rozjazd
    z warstwa 0 opisany w WR-03 z 01-REVIEW.md.
    """
    normalized = _fold_path_for_match(path)
    return any(
        fnmatch.fnmatchcase(normalized, pattern.casefold())
        for pattern in allow_patterns
    )


def scan_files(
    paths: list[str],
    corpus_dir: Path,
    use_corpus: bool,
    allow_patterns: list[str] | None = None,
) -> list[Violation]:
    """Uruchamia wszystkie trzy warstwy na liscie sciezek.

    Warstwa 0 dziala na kazdej sciezce z listy, takze plikow, ktorych nie da
    sie odczytac jako tekst (binarne) - to jest jedyny sposob, w jaki
    `standards/.local/plik.bin` dodany przez `git add -f` zostaje zlapany.
    Warstwy 1 i 2 dzialaja wylacznie na plikach czytelnych jako tekst UTF-8.
    Lista wyjatkow (`allow_patterns`) dotyczy WYLACZNIE warstwy 2.
    """
    allow_patterns = allow_patterns or []
    violations: list[Violation] = []

    violations.extend(scan_paths(paths))

    for raw_path in paths:
        path_obj = Path(raw_path)
        if not path_obj.is_file():
            continue
        try:
            text = path_obj.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Plik binarny albo nieczytelny jako tekst - warstwy 1 i 2 z
            # definicji dzialaja na tresci tekstowej, wiec sa tu pomijane.
            # Warstwa 0 juz go objela wyzej, jesli sciezka na to wskazywala.
            continue

        if use_corpus:
            violations.extend(scan_text_corpus(text, raw_path, corpus_dir))

        if not _matches_allow_list(raw_path, allow_patterns):
            violations.extend(scan_text_structural(text, raw_path))

    return violations


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confidentiality_guard",
        description=(
            "Bramka poufnosci: wykrywa doslowny tekst normatywny i pliki "
            "spod lokalnego korpusu standards/.local."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Sciezki do sprawdzenia (zwykle stagowane pliki z pre-commit).",
    )
    parser.add_argument(
        "--corpus-dir",
        default=DEFAULT_CORPUS_DIR,
        help=f"Katalog lokalnego korpusu norm (domyslnie {DEFAULT_CORPUS_DIR}).",
    )
    parser.add_argument(
        "--no-corpus",
        action="store_true",
        help="Pomija warstwe korpusowa (tryb CI, ktore z zalozenia nie ma dostepu do korpusu).",
    )
    parser.add_argument(
        "--allow-file",
        default=DEFAULT_ALLOW_FILE,
        help=f"Plik z wzorcami wyjatkow dla warstwy strukturalnej (domyslnie {DEFAULT_ALLOW_FILE}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Wypisz naruszenia jako JSON zamiast jednej linii na naruszenie.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    corpus_dir = Path(args.corpus_dir)
    allow_file = Path(args.allow_file)
    allow_patterns = _load_allow_patterns(allow_file)

    violations = scan_files(
        paths=args.paths,
        corpus_dir=corpus_dir,
        use_corpus=not args.no_corpus,
        allow_patterns=allow_patterns,
    )

    if args.json:
        payload = [
            {
                "path": v.path,
                "line": v.line,
                "layer": v.layer,
                "rule_id": v.rule_id,
                "reason": v.reason,
            }
            for v in violations
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for v in violations:
            line_part = str(v.line) if v.line is not None else "?"
            print(f"{v.path}:{line_part}: [{v.rule_id}] {v.reason}")

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
