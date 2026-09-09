"""Bramka poufnosci: cztery warstwy detekcji tresci normatywnej i tozsamosciowej.

Ten modul jest zaleznosciowo izolowany od reszty pakietu `wayside` i uzywa
WYLACZNIE biblioteki standardowej Pythona. To jest warunek, nie preferencja:
hak pre-commit ma dzialac w srodowisku pre-commit (`language: python`, wlasny
odizolowany venv) i w repozytorium tymczasowym testu integracyjnego, bez
`uv sync` i bez sieci - dowolna zaleznosc zewnetrzna zlamalaby oba te
scenariusze.

Cztery warstwy, od najbardziej do najmniej precyzyjnej:

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
  samej linii), dzialajacy bez zadnego korpusu - a wiec takze w CI.
- Warstwa 3, tozsamosciowa (`identity-*`): piec regul lapiacych tresc z sieci
  pracodawcy, ktora moglaby przeciec przez zwykly tekst projektu, nie przez
  cytat normy - adresacja prywatna RFC 1918 poza zadeklarowanymi fixture'ami,
  adres sprzetowy jako sygnatura urzadzenia, nazwa urzadzenia, i nazwa wlasna
  projektu odgrodzonego granica poufnosci. Cztery pierwsze reguly sa regulami
  KSZTALTU, zbudowanymi z publicznie znanych skrotow branzowych i z ksztaltow
  adresowych, nigdy z niczyjego inwentarza (rozstrzygniecie R-1, plan
  05-03) - literalna lista nazw urzadzen albo adresow w publicznym pliku
  ujawnialaby dokladnie te informacje, ktorej ta warstwa ma bronic. Dzialaja
  bez zadnego korpusu, a wiec takze w CI, dokladnie jak warstwa 2, ktorej sa
  siostrzane. Piata regula, literalna, dziala WYLACZNIE lokalnie, z pliku
  gitignorowanego (rozstrzygniecie R-2) - to jest siostra warstwy 1: kontrola,
  ktora zostaje na jednej maszynie, jest kontrola, nie niedogodnoscia.

Warstwy 2 i 3 dziela JEDNA liste wyjatkow (`.confidentiality-allow`), w trzech
rozroznialnych postaciach wiersza (wzorzec sciezki bez przedrostka - warstwa
2; `identity-value:<wartosc>` - deklaracja adresowa warstwy 3; `identity-path:
<regula albo all>:<wzorzec>` - wyjatek sciezki zawezony do jednej reguly
warstwy 3, albo do wszystkich). Wyjatki obu warstw sa NIEZALEZNE: dopuszczenie
jednej reguly nie zdejmuje drugiej z tej samej sciezki.

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
    "scan_text_identity",
    "scan_files",
    "AllowListShapeError",
    "main",
]

# --- Stale modulu -----------------------------------------------------------

RULE_PATH_LOCAL_CORPUS = "path-local-corpus"
RULE_CORPUS_SHINGLE = "corpus-shingle"
RULE_STRUCTURAL_CLAUSE_MODAL = "structural-clause-modal"

# Warstwa 3, tozsamosciowa (D-19, plan 05-03). Kolejnosc jest stala i
# zamknieta - klasyfikator wierszy listy wyjatkow (`_identity_path_exceptions`)
# musi znac caly zbior od pierwszego commita tej warstwy, inaczej wiersz
# odwolujacy sie do reguly dochodzacej w kolejnym zadaniu bylby dzis bledem
# ksztaltu.
RULE_IDENTITY_PRIVATE_IPV4 = "identity-private-ipv4"
RULE_IDENTITY_MAC_ADDRESS = "identity-mac-address"
RULE_IDENTITY_DEVICE_NAME = "identity-device-name"
RULE_IDENTITY_PROJECT_NAME = "identity-project-name"
RULE_IDENTITY_LOCAL_LITERAL = "identity-local-literal"

IDENTITY_RULE_IDS: tuple[str, ...] = (
    RULE_IDENTITY_PRIVATE_IPV4,
    RULE_IDENTITY_MAC_ADDRESS,
    RULE_IDENTITY_DEVICE_NAME,
    RULE_IDENTITY_PROJECT_NAME,
    RULE_IDENTITY_LOCAL_LITERAL,
)

# Dwie reguly adresowe, jedyne honorujace deklaracje wartosci
# (`identity-value:`, zalozenie Z-93 z planu 05-03): deklaracja jest
# oswiadczeniem o pochodzeniu ADRESU, nigdy nazwy urzadzenia ani nazwy
# wlasnej - deklarowanie tamtych po wartosci byloby literalna lista nazw
# w publicznym pliku, dokladnie to, czego rozstrzygniecie R-1 zakazuje.
IDENTITY_ADDRESS_RULE_IDS: tuple[str, ...] = (
    RULE_IDENTITY_PRIVATE_IPV4,
    RULE_IDENTITY_MAC_ADDRESS,
)

# Przedrostki wiersza listy wyjatkow warstwy tozsamosciowej (R-4). Wiersz bez
# zadnego z tych przedrostkow (i bez przedrostka `identity-` w ogole) jest
# wzorcem sciezki warstwy strukturalnej, dokladnie jak dzis.
IDENTITY_VALUE_PREFIX = "identity-value:"
IDENTITY_PATH_PREFIX = "identity-path:"
IDENTITY_PATH_ALL = "all"

# Marker wspolny obu przedrostkow powyzej - wiersz zaczynajacy sie od niego,
# ale niepasujacy do zadnego z dwoch, jest bledem ksztaltu, nie cichym
# wzorcem sciezki warstwy strukturalnej (R-4).
_IDENTITY_LINE_PREFIX = "identity-"

DEFAULT_IDENTITY_LOCAL_FILE = ".confidentiality-identity.local"

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

# Adresacja prywatna RFC 1918: caly pierwszy zakres (maska /8), drugi zakres
# zawezony do wlasciwego przedzialu drugiego oktetu (maska /12), trzeci
# zakres (maska /16) - trzy przedzialy z samego dokumentu RFC 1918, zapisane
# tu jako regula, nigdy jako literalny przyklad (Pitfall 2 badania fazy:
# wlasny przyklad ilustracyjny w komentarzu bramki zapala jej wlasna
# regule). Dopasowanie idzie na tekscie znormalizowanym przez
# `scan_text_identity` (cyfry i kropki sa niewrazliwe na diakrytyke/wielkosc
# liter, wiec to nie zmienia dopasowania, tylko utrzymuje jedna sciezke
# normalizacji).
#
# Negatywne spojrzenie wstecz `(?<![\d.])` odsiewa czlon wewnatrz dluzszego
# ciagu cyfr i kropek (np. piecioczlonowy numer wersji, gdzie bez tego
# zawezenia ostatnie cztery czlony zaczynajace sie od "10." zostalyby
# zlapane jako oddzielny adres) - pomiar z tabeli faktow planu 05-03:
# wzorzec z badania (Pattern 3) tego nie mial. Ogranicznik z prawej strony
# `(?!\d)` odsiewa WYLACZNIE kolejna cyfre, NIE kropke - adres na koncu
# zdania konczy sie kropka, i to jest zapis poprawny, ktory dalej ma dawac
# naruszenie.
PRIVATE_IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})"
    r"(?!\d)"
)

# Adres sprzetowy: szesc grup po dwie cyfry szesnastkowe rozdzielone JEDNYM
# I TYM SAMYM separatorem (dwukropek albo dywiz), z granica slowa po obu
# stronach. Wymog jednakowego separatora w calym dopasowaniu idzie przez
# odwolanie do grupy przechwytujacej `\1`, nie przez alternatywe dwoch
# calych wzorcow - "de:ad-be:ef:00:01" (separatory mieszane) NIE jest wiec
# dopasowaniem.
#
# Dokladnie szesc grup, nie mniej i nie wiecej: krotszy ciag tego ksztaltu
# (trzy grupy rozdzielone dwukropkiem) jest godzina w znaczniku czasu
# ("20:18:15"), a dluzszy nie jest adresem sprzetowym.
#
# Interpretacja slowa "sygnatury" z kryterium 4 fazy (rozstrzygniecie R-3,
# plan 05-03): adres sprzetowy jest sygnatura urzadzenia o ksztalcie scisle
# okreslonym, przecieka z kazdego zrzutu ruchu, i dokladnie w tej dziedzinie
# to narzedzie pracuje (identyfikacja producenta z rejestru OUI). Sygnatury
# innego rodzaju (numery seryjne, wewnetrzne numery dokumentow) sa objete
# regula piata, lokalna (05-03/3) - ich ksztalt jest specyficzny dla
# organizacji, wiec wpisanie go do publicznego pliku bylo by tym samym
# wyciekiem, o ktorym mowi R-1.
MAC_ADDRESS_PATTERN = re.compile(
    r"\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b"
)

# Zamkniety zbior publicznie znanych skrotow branzowych rol urzadzen OT/ICS
# i sieciowych (rozstrzygniecie R-1, plan 05-03) - NIGDY niczyj inwentarz.
# Kazdy skrot stoi w kazdym podreczniku automatyki albo sieci: PLC
# (sterownik programowalny), RTU (terminal zdalny), HMI (panel operatorski),
# IED (urzadzenie elektroniczne inteligentne), MTU (jednostka nadrzedna),
# DCS (system rozproszony), SCADA (system nadzoru), EWS (stacja
# inzynierska), OWS (stacja operatorska), VFD (napednik czestotliwosciowy),
# IPC (komputer przemyslowy), RBC (centrum sterowania radiowego, ETCS),
# LEU (przytorowa jednostka elektroniczna, sygnalizacja kolejowa), SW
# (przelacznik), FW (zapora), AP (punkt dostepowy).
DEVICE_ROLE_PREFIXES: tuple[str, ...] = (
    "PLC",
    "RTU",
    "HMI",
    "IED",
    "MTU",
    "DCS",
    "SCADA",
    "EWS",
    "OWS",
    "VFD",
    "IPC",
    "RBC",
    "LEU",
    "SW",
    "FW",
    "AP",
)

# Prefiks z zamknietego zbioru, potem OBOWIAZKOWY separator (dywiz albo
# podkreslenie), potem od jednej do czterech cyfr, z granica slowa po obu
# stronach. Separator jest OBOWIAZKOWY, nie kosmetyczny: wariant bez niego
# dawal (przy planowaniu) jedno trafienie na nazwie katalogu wyjsciowego w
# artefakcie planowania fazy 3 - falszywy alarm, ktory kupilby wyjatek
# zamiast detekcji, zamiast po prostu wymagac separatora.
DEVICE_NAME_PATTERN = re.compile(
    r"\b(?:" + "|".join(p.casefold() for p in DEVICE_ROLE_PREFIXES) + r")"
    r"[-_]\d{1,4}\b"
)

# Nazwa wlasna projektu odgrodzonego granica poufnosci (D-23 fazy publikacji).
# Dopasowanie idzie na tekscie JUZ znormalizowanym przez `scan_text_identity`
# (zlozona diakrytyka, zdjeta wielkosc liter), wiec wzorzec ponizej jest
# zapisany w formie znormalizowanej (male litery). Miedzy dwoma slowami nazwy
# dopuszczony jest DOWOLNY ciag bialych znakow, dywizow albo podkreslen,
# W TYM CIAG PUSTY - zapis zlepiony ("...sentinel" bezposrednio po pierwszym
# slowie) jest najczestsza forma nazwy wlasnej w identyfikatorach i nazwach
# plikow, i to wlasnie tam nazwy wlasne przeciekaja najczesciej. Sam wzorzec
# musi niesc oba slowa nazwy jako literal, zeby w ogole cokolwiek dopasowac -
# to jest powod, dla ktorego TEN plik (i tylko ten) potrzebuje wlasnego
# wyjatku na `.confidentiality-allow` (zalozenie Z-96): sklejanie literalu
# z czesci w czasie wykonania byloby obejsciem bramki bez zmiany zachowania,
# nie mniejszym wyciekiem.
PROJECT_NAME_PATTERN = re.compile(r"railguard[\s\-_]*sentinel")


class AllowListShapeError(ValueError):
    """Wiersz `.confidentiality-allow` o nierozpoznanym ksztalcie: przedrostek
    `identity-` nierozpoznany, albo nazwa reguly w `identity-path:` spoza
    zamknietego zbioru `IDENTITY_RULE_IDS` (plus `IDENTITY_PATH_ALL`).

    Bez tego wyjatku literowka w nazwie przedrostka albo w nazwie reguly
    zamienialaby sie po cichu w wzorzec sciezki warstwy strukturalnej nad
    plikiem o dziwnej nazwie - czyli w wyjatek, ktorego nikt nie zamierzal
    (R-4, plan 05-03).
    """


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


# --- Klasyfikatory wierszy `.confidentiality-allow` (R-4, zalozenie Z-91) ---
#
# `_load_allow_patterns` powyzej zostaje NIETKNIETA - ani sygnatura, ani
# zachowanie: istniejacy test regresji nad drzewem sledzonym wola ta funkcje
# i przekazuje jej wynik dalej, wiec zmiana typu zwracanego zerwalaby tamten
# test bez zadnego zysku. Trzy funkcje ponizej klasyfikuja jej surowy wynik
# (liste wierszy bez komentarzy i pustych linii) na trzy rozroznialne
# postacie, kazda osobno testowalna.


def _structural_allow_patterns(lines: list[str]) -> list[str]:
    """Wiersze BEZ przedrostka tozsamosciowego: wzorce sciezki warstwy
    strukturalnej (warstwa 2), dokladnie jak dzis."""
    return [line for line in lines if not line.startswith(_IDENTITY_LINE_PREFIX)]


def _normalize_identity_value(raw: str) -> str:
    """Normalizuje wartosc adresowa do postaci porownywalnej: male litery
    (przez `_strip_diacritics` + `casefold`, jak reszta modulu), i - dla
    ksztaltu adresu sprzetowego wylacznie - zamiana dywizu na dwukropek.

    Bez tej normalizacji ten sam adres sprzetowy zapisany dwoma separatorami
    (dywizem i dwukropkiem) trafia na liste zadeklarowanych wartosci jako
    DWIE rozne wartosci, a test kompletnosci deklaracji nie ma jak tego
    rozstrzygnac (pomiar z tabeli faktow planu 05-03: ta sama
    wartosc stoi w drzewie zapisana obydwoma separatorami).
    """
    folded = _strip_diacritics(raw).casefold().strip()
    if MAC_ADDRESS_PATTERN.fullmatch(folded):
        folded = folded.replace("-", ":")
    return folded


def _identity_declared_values(lines: list[str]) -> frozenset[str]:
    """Wiersze `identity-value:<wartosc>`: deklaracje adresowe warstwy 3,
    obowiazujace w calym drzewie niezaleznie od pliku (zalozenie Z-93:
    deklaracja jest oswiadczeniem o pochodzeniu ADRESU, nigdy nazwy
    urzadzenia ani nazwy wlasnej).

    Kazda wartosc jest normalizowana (`_normalize_identity_value`) przed
    dodaniem do zbioru. Wartosc, ktora po normalizacji nie pasuje do
    ZADNEGO z dwoch ksztaltow adresowych (RFC 1918, adres sprzetowy),
    podnosi `AllowListShapeError` - deklaracja jest inwentarzem adresacji,
    nie dowolnym tekstem (rozstrzygniecie R-5).
    """
    values: set[str] = set()
    for line in lines:
        if not line.startswith(IDENTITY_VALUE_PREFIX):
            continue
        raw_value = line[len(IDENTITY_VALUE_PREFIX) :].strip()
        normalized = _normalize_identity_value(raw_value)
        if not (
            PRIVATE_IPV4_PATTERN.fullmatch(normalized)
            or MAC_ADDRESS_PATTERN.fullmatch(normalized)
        ):
            raise AllowListShapeError(
                f"{DEFAULT_ALLOW_FILE}: deklaracja '{raw_value}' nie pasuje "
                "do zadnego z dwoch ksztaltow adresowych (RFC 1918 albo "
                "adres sprzetowy)."
            )
        values.add(normalized)
    return frozenset(values)


def _identity_path_exceptions(lines: list[str]) -> dict[str, list[str]]:
    """Wiersze `identity-path:<regula albo all>:<wzorzec>`: wyjatki sciezki
    zawezone do JEDNEJ reguly warstwy 3, albo - ze slowem `IDENTITY_PATH_ALL`
    - do wszystkich regul naraz (R-4). Klucz zwroconego slownika jest
    identyfikatorem reguly (albo `IDENTITY_PATH_ALL`); wartosc jest lista
    wzorcow sciezki zapisanych dla tego klucza.

    Wiersz zaczynajacy sie od `identity-`, ktory nie pasuje do zadnego z
    dwoch znanych przedrostkow, oraz wiersz `identity-path:` z nazwa reguly
    spoza zamknietego zbioru (i rozna od `all`) podnosza
    `AllowListShapeError` - bez tej galezi literowka w przedrostku albo
    w nazwie reguly zamienialaby sie po cichu w wzorzec sciezki warstwy
    strukturalnej nad plikiem o dziwnej nazwie.
    """
    known_rule_names = set(IDENTITY_RULE_IDS) | {IDENTITY_PATH_ALL}
    exceptions: dict[str, list[str]] = {}
    for line in lines:
        if line.startswith(IDENTITY_PATH_PREFIX):
            remainder = line[len(IDENTITY_PATH_PREFIX) :]
            rule_name, separator, pattern = remainder.partition(":")
            if not separator:
                raise AllowListShapeError(
                    f"{DEFAULT_ALLOW_FILE}: wiersz '{line}' niesie przedrostek "
                    f"'{IDENTITY_PATH_PREFIX}', ale brakuje separatora miedzy "
                    "nazwa reguly a wzorcem sciezki."
                )
            if rule_name not in known_rule_names:
                raise AllowListShapeError(
                    f"{DEFAULT_ALLOW_FILE}: nazwa reguly '{rule_name}' w "
                    f"wierszu '{line}' spoza zamknietego zbioru "
                    f"{sorted(known_rule_names)}."
                )
            exceptions.setdefault(rule_name, []).append(pattern)
        elif line.startswith(IDENTITY_VALUE_PREFIX):
            continue
        elif line.startswith(_IDENTITY_LINE_PREFIX):
            raise AllowListShapeError(
                f"{DEFAULT_ALLOW_FILE}: wiersz '{line}' zaczyna sie od "
                "czlonu tozsamosciowego, ale nie pasuje do zadnego "
                f"rozpoznanego przedrostka ('{IDENTITY_VALUE_PREFIX}', "
                f"'{IDENTITY_PATH_PREFIX}')."
            )
    return exceptions


def _identity_rule_is_suppressed(
    path: str, rule_id: str, exceptions: dict[str, list[str]]
) -> bool:
    """Sprawdza, czy `rule_id` jest wyjeta dla `path`: wzorce zapisane wprost
    dla tej reguly ORAZ wzorce zapisane dla wszystkich regul naraz
    (`IDENTITY_PATH_ALL`). Uzywa tego samego mechanizmu dopasowania sciezki
    co warstwa 2 (`_matches_allow_list`), zeby bezwrazliwosc na wielkosc
    liter byla jedna dla calego pliku (zalozenie Z-92) - wyjatki obu warstw
    pozostaja niezalezne, bo kazda jest stosowana w osobnym miejscu funkcji
    skanujacej pliki.
    """
    patterns = exceptions.get(rule_id, []) + exceptions.get(IDENTITY_PATH_ALL, [])
    if not patterns:
        return False
    return _matches_allow_list(path, patterns)


def scan_text_identity(
    text: str,
    path: str,
    *,
    declared_values: frozenset[str] = frozenset(),
    local_literals: tuple[str, ...] = (),
) -> list[Violation]:
    """Warstwa 3: wzorce tozsamosciowe.

    Dziala bez zadnego korpusu - a wiec takze w CI, jak warstwa 2, ktorej
    jest siostrzana. Cztery reguly ksztaltu dzialaja zawsze: adresacja
    prywatna RFC 1918 poza `declared_values`, adres sprzetowy poza
    `declared_values`, nazwa urzadzenia, i nazwa wlasna projektu odgrodzonego
    (`RULE_IDENTITY_PROJECT_NAME`). Piata regula, literalna, dziala WYLACZNIE
    lokalnie z pliku gitignorowanego (`local_literals`) - dochodzi w zadaniu
    05-03/3.

    Naruszenia sa zwracane posortowane po numerze linii, a przy tym samym
    numerze linii po identyfikatorze reguly - kolejnosc stabilna miedzy
    przebiegami, zeby wyjscie CI dalo sie porownywac (sonda: ordering).
    """
    violations: list[Violation] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        normalized = _strip_diacritics(raw_line).casefold()

        for match in PRIVATE_IPV4_PATTERN.finditer(normalized):
            value = _normalize_identity_value(match.group(0))
            if value in declared_values:
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_PRIVATE_IPV4,
                    reason=(
                        "Linia niesie adres o ksztalcie adresacji prywatnej "
                        "RFC 1918, niezadeklarowany w .confidentiality-allow."
                    ),
                )
            )

        for match in MAC_ADDRESS_PATTERN.finditer(normalized):
            value = _normalize_identity_value(match.group(0))
            if value in declared_values:
                continue
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_MAC_ADDRESS,
                    reason=(
                        "Linia niesie ciag o ksztalcie adresu sprzetowego "
                        "(sygnatura urzadzenia), niezadeklarowany w "
                        ".confidentiality-allow."
                    ),
                )
            )

        for _match in DEVICE_NAME_PATTERN.finditer(normalized):
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_DEVICE_NAME,
                    reason=(
                        "Linia niesie ciag o ksztalcie nazwy urzadzenia "
                        "(przedrostek roli, separator, cyfry)."
                    ),
                )
            )

        if PROJECT_NAME_PATTERN.search(normalized):
            violations.append(
                Violation(
                    path=path,
                    line=line_no,
                    layer="identity",
                    rule_id=RULE_IDENTITY_PROJECT_NAME,
                    reason=(
                        "Linia niesie nazwe projektu odgrodzonego granica "
                        "poufnosci (rekord decyzji D-23, faza publikacji)."
                    ),
                )
            )

    violations.sort(key=lambda v: (v.line, v.rule_id))
    return violations


def scan_files(
    paths: list[str],
    corpus_dir: Path,
    use_corpus: bool,
    allow_patterns: list[str] | None = None,
    identity_local_file: Path | None = None,
) -> list[Violation]:
    """Uruchamia wszystkie cztery warstwy na liscie sciezek.

    Warstwa 0 dziala na kazdej sciezce z listy, takze plikow, ktorych nie da
    sie odczytac jako tekst (binarne) - to jest jedyny sposob, w jaki
    `standards/.local/plik.bin` dodany przez `git add -f` zostaje zlapany.
    Warstwy 1, 2 i 3 dzialaja wylacznie na plikach czytelnych jako tekst
    UTF-8.

    `allow_patterns` niesie SUROWE wiersze `.confidentiality-allow`
    (`_load_allow_patterns`, niezmieniona) w trzech postaciach: wzorzec
    sciezki bez przedrostka trafia do warstwy 2 (`_structural_allow_patterns`);
    `identity-value:` trafia do deklaracji adresowych warstwy 3
    (`_identity_declared_values`); `identity-path:` trafia do wyjatkow
    sciezki warstwy 3 (`_identity_path_exceptions`). Wyjatki obu warstw sa
    NIEZALEZNE - kazdy jest stosowany w osobnym miejscu ponizej (zalozenie
    Z-92), wiec dopuszczenie jednej reguly nie zdejmuje drugiej z tej samej
    sciezki.

    `identity_local_file` jest przyjmowany juz teraz (kazde dzisiejsze
    wywolanie pozostaje poprawne bez zmiany), ale uzywany dopiero od zadania
    05-03/3, ktore dolozy piata regule, literalna.
    """
    allow_patterns = allow_patterns or []
    structural_patterns = _structural_allow_patterns(allow_patterns)
    declared_values = _identity_declared_values(allow_patterns)
    identity_path_exceptions = _identity_path_exceptions(allow_patterns)

    violations: list[Violation] = []

    violations.extend(scan_paths(paths))

    for raw_path in paths:
        path_obj = Path(raw_path)
        if not path_obj.is_file():
            continue
        try:
            text = path_obj.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            # Plik binarny albo nieczytelny jako tekst - warstwy 1, 2 i 3 z
            # definicji dzialaja na tresci tekstowej, wiec sa tu pomijane.
            # Warstwa 0 juz go objela wyzej, jesli sciezka na to wskazywala.
            continue

        if use_corpus:
            violations.extend(scan_text_corpus(text, raw_path, corpus_dir))

        if not _matches_allow_list(raw_path, structural_patterns):
            violations.extend(scan_text_structural(text, raw_path))

        for violation in scan_text_identity(
            text, raw_path, declared_values=declared_values
        ):
            if _identity_rule_is_suppressed(
                raw_path, violation.rule_id, identity_path_exceptions
            ):
                continue
            violations.append(violation)

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
