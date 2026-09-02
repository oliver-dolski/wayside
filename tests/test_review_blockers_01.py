"""Testy regresyjne trzech blokerow z code review fazy 1 (`01-REVIEW.md`).

Kazdy z nich zostal potwierdzony bezposrednim wywolaniem kodu, zanim
powstala poprawka, i kazdy trafia w obietnice, na ktorej stoi ta faza:
FOUND-04 (nic spod `standards/.local` nie trafia do repozytorium),
FOUND-03 (tekst normatywny jest rozpoznawany) oraz PUB-01 (rozstrzygniecie
nosi nazwisko czlowieka).

Testy siedza w osobnym pliku, a nie dopisane do pakietow planow 01-02
i 01-04, celowo: to jest slad po konkretnym przegladzie i ma byc czytelny
jako taki, gdyby ktos wrocil do pytania "skad ta lista modalnosci".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_pub_gate  # noqa: E402
import confidentiality_guard  # noqa: E402


# CR-01. Warstwa 0 jest jedyna, ktorej nie da sie obejsc wpisem w
# `.confidentiality-allow`, wiec porownanie wrazliwe na wielkosc liter jest
# tu obejsciem calej warstwy. Windows/NTFS jest bezwrazliwy na wielkosc
# liter, a git zapisuje w indeksie literalna forme sciezki - `git add -f
# Standards/.local/x.txt` dodaje ten sam plik z dysku pod inna nazwa.
@pytest.mark.parametrize(
    "path",
    [
        "standards/.local/norma.txt",
        "Standards/.local/norma.txt",
        "STANDARDS/.LOCAL/norma.txt",
        "standards/.Local/norma.txt",
        "Standards\\.local\\norma.txt",
    ],
)
def test_layer0_catches_local_corpus_regardless_of_case(path):
    assert confidentiality_guard.scan_paths([path]), (
        f"warstwa 0 przepuscila sciezke do lokalnego korpusu: {path!r}"
    )


def test_layer0_does_not_overreach_to_similar_paths():
    """Bezwrazliwosc na wielkosc liter nie moze zamienic sie w dopasowanie
    po fragmencie nazwy - `standards/public` i `my-standards` zostaja czyste.
    """
    clean = [
        "standards/public/readme.md",
        "docs/standards.md",
        "my-standards/.local/x.txt",
        "standards/.locally-sourced/x.txt",
    ]
    assert not confidentiality_guard.scan_paths(clean)


# CR-02. Warstwa strukturalna jest jedyna dzialajaca w CI (korpus z natury
# nie istnieje na runnerze), wiec luka w niej jest luka w backstopie.
# Polskie odpowiedniki ("musi", "powinien") byly na liscie od poczatku,
# angielskie "must" i "should" nie - asymetria, nie decyzja.
@pytest.mark.parametrize(
    "fragment",
    [
        "3.4.2 The system shall enforce authentication for all write operations.",
        "3.4.2 The system must enforce authentication for all write operations.",
        "3.4.2 The system should enforce authentication for all write operations.",
        "3.4.2 The system must not permit anonymous write operations at any time.",
        "3.4.2 The system should not permit anonymous writes under any circumstances.",
        "3.4.2 System musi wymuszac uwierzytelnienie dla wszystkich operacji zapisu.",
    ],
)
def test_structural_layer_catches_normative_modals(fragment):
    assert confidentiality_guard.scan_text_structural(fragment, "probe.md"), (
        f"warstwa strukturalna przepuscila fragment o ksztalcie klauzuli: {fragment!r}"
    )


def test_structural_layer_ignores_prose_without_clause_number():
    """Sama modalnosc bez kropkowanego numeru punktu to zwykla proza."""
    assert not confidentiality_guard.scan_text_structural(
        "The tool must be run from the repository root before the first commit.",
        "README.md",
    )


@pytest.mark.parametrize(
    "fragment",
    [
        # Prawdziwe zdania z `.planning/research/PITFALLS.md`, ktore zapalily
        # warstwe dopiero po dodaniu "must" do listy modalnosci - numer wersji
        # oprogramowania udawal numer klauzuli.
        "CVSS v4.0 added a Safety supplemental metric, so it must be shown as a "
        "separate field and never folded into the base score silently.",
        "CVSS v4.0 OT/ICS/IoT coverage confirms the base score is not altered by "
        "the Safety supplemental value, must be reported separately.",
    ],
)
def test_structural_layer_ignores_software_version_numbers(fragment):
    """Numer wersji nie jest numerem klauzuli.

    Zadna norma nie numeruje klauzul jako `v4.0`, wiec wykluczenie prefiksu
    `v` nie oslabia detekcji, a zdejmuje cala klase falszywych alarmow na
    wlasnej dokumentacji projektu.
    """
    assert not confidentiality_guard.scan_text_structural(fragment, "PITFALLS.md")


def test_version_exclusion_does_not_swallow_real_clause_numbers():
    """Wykluczenie `v` nie moze zdjac numeru klauzuli stojacego po literze.

    Kontrola przeciwna do testu wyzej: gdyby zawezenie bylo zbyt szerokie,
    wrocilaby luka CR-02, tylko innymi drzwiami.
    """
    assert confidentiality_guard.scan_text_structural(
        "3.4.2 The system must support TLS 1.2 for all remote management sessions "
        "initiated by field operators in this zone.",
        "probe.md",
    )


# CR-03. Pole `reviewer` jest slabym kontrolerem z natury, ale odrzucanie
# golego "bot" przy jednoczesnym przyjmowaniu "gsd-bot" nie jest slaboscia
# heurystyki, tylko bledem tokenizacji: dzielenie wylacznie po bialych
# znakach nie rozbija lacznika ani podkreslnika.
@pytest.mark.parametrize(
    "reviewer",
    [
        "gsd-bot",
        "Automated-Reviewer",
        "claude_agent",
        "AI Assistant",
        "bot",
        "",
        "<imie i nazwisko>",
        "TBD",
    ],
)
def test_reviewer_field_rejects_non_human_values(reviewer):
    assert check_pub_gate._reviewer_is_invalid(reviewer), (
        f"pole reviewer przyjelo wartosc, ktora nie jest nazwiskiem czlowieka: {reviewer!r}"
    )


@pytest.mark.parametrize(
    "reviewer",
    [
        "Oliver Dolski",
        "Anna Nowak-Kowalska",
        "Jean-Luc Picard",
    ],
)
def test_reviewer_field_accepts_human_names(reviewer):
    assert not check_pub_gate._reviewer_is_invalid(reviewer), (
        f"pole reviewer odrzucilo nazwisko czlowieka: {reviewer!r}"
    )


# WR-03. Lista wyjatkow warstwy 2 stala na `fnmatch.fnmatch`, ktore zdejmuje
# wielkosc liter przez `os.path.normcase` - czyli tylko na Windows. Ta sama
# lista zachowywalaby sie inaczej na runnerze linuksowym niz na maszynie
# autora, a warstwa 0 (CR-01 wyzej) jest bezwrazliwa na wielkosc liter na
# obu. Poprawka nie zmienia wyniku na Windows, tylko przestaje go uzalezniac
# od platformy.
@pytest.mark.parametrize(
    "path",
    [
        "tests/test_confidentiality_guard.py",
        "Tests/Test_Confidentiality_Guard.py",
        "tests\\test_confidentiality_guard.py",
    ],
)
def test_allow_list_is_case_insensitive_on_every_platform(path):
    assert confidentiality_guard._matches_allow_list(
        path, ["tests/test_confidentiality_guard.py"]
    )


def test_allow_list_does_not_overreach_to_other_files():
    assert not confidentiality_guard._matches_allow_list(
        "src/wayside/cli.py", ["tests/test_confidentiality_guard.py"]
    )
