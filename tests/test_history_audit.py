"""Audyt PUB-05: skan TRZECH powierzchni CALEJ historii repozytorium.

Dlaczego trzy powierzchnie, nie jedna: nazwa urzadzenia albo adres moze
siedziec w NAZWIE PLIKU albo w OPISIE COMMITA, czego skan po tresci drzew
(`git grep`) nigdy nie zobaczy. `tests/test_no_history_leak.py` (obok, bez
znacznika wolnego, bo jest tani) pokrywa dzis wylacznie sciezke
`standards/.local` i wylacznie dwie z tych trzech powierzchni. Ten modul
domyka trzecia (nazwy plikow) i rozciaga wszystkie trzy na CALY zbior
wzorcow tozsamosciowych warstwy 4 (D-19, D-20).

Dlaczego kazda powierzchnia jest OSOBNYM skanem z OSOBNYM parsowaniem: trzy
polecenia gita (`git grep`, `git log --format=%B`, `git ls-tree --name-only`)
maja trzy rozne ksztalty wyjscia (Pitfall 3 badania fazy 5, potwierdzone
przebiegiem na tej maszynie, nie zalozone) - naiwne zlaczenie ich w jeden
ciag do przeszukania regexem miesza kontekst (nazwa pliku z jednego commita
moglaby "polaczyc sie" wizualnie z trescia innego). Kazda funkcja ponizej
parsuje WYLACZNIE wyjscie WLASNEGO polecenia.

Caly modul stoi obok istniejacego testu jednej sciezki
(`tests/test_no_history_leak.py`), ktory zostaje BEZ znacznika wolnego, bo
jest tani (dwa proste wywolania gita). Ten modul jest drogi (trzy
powierzchnie razy caly zbior rewizji, jedno wywolanie gita na rewizje dla
powierzchni trzeciej - Z-98), wiec nosi znacznik `slow` (D-22): pomijany
domyslnie lokalnie (filtr w `pyproject.toml`), wlaczany jawnie WYLACZNIE
w jobie CI `confidentiality-backstop`, ktory ma checkout z pelna historia.

Skan jest wylacznie ODCZYTEM: nie tworzy zadnego obiektu gita, nie rusza
zadnej referencji, nie zmienia drzewa roboczego (patrz
`test_scan_does_not_change_repository_state` nizej).

DYSCYPLINA TRESCI tego modulu (ten sam kontrakt, co `Violation` w
`confidentiality_guard.py`): zadna funkcja ponizej nie zwraca ani nie
raportuje dopasowanego fragmentu tresci. Trafienie niesie WYLACZNIE rewizje,
identyfikator reguly, i adres wlasciwy dla powierzchni (sciezka+linia dla
tresci drzew, sama rewizja dla komunikatu commita, nazwa pliku dla nazw
plikow) - nigdy tresc linii ani wartosc dopasowania.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Powod tego importu (nie kopii wzorcow): D-19 wymaga JEDNEJ listy wzorcow
# tozsamosciowych dla bramki biezacej i dla audytu przeszlosci. Druga kopia
# tych samych czterech wzorcow w tym pliku rozjechalaby sie z pierwsza przy
# pierwszej kolejnej zmianie ktoregos z nich (dokladnie ten blad, ktoremu
# D-19 ma zapobiegac).
import confidentiality_guard as guard  # noqa: E402

pytestmark = [pytest.mark.slow, pytest.mark.integration]

# --- Stale modulu ------------------------------------------------------------

HISTORY_SURFACES: tuple[str, str, str] = ("tree-content", "commit-message", "file-name")

RECORD_PATH: Path = REPO_ROOT / "compliance" / "history-audit.md"

# Cztery reguly KSZTALTU warstwy tozsamosciowej - te same, ktore README opisuje
# jako dzialajace "bez zadnego lokalnego materialu, a wiec takze w CI". Piata
# regula (`identity-local-literal`, `IDENTITY_RULE_IDS[-1]`) dziala WYLACZNIE
# lokalnie z pliku gitignorowanego (rozstrzygniecie R-2, plan 05-03) i audyt
# historii - ktory ma dzialac w CI, gdzie ten plik z zalozenia nie istnieje -
# swiadomie jej nie obejmuje: `scan_text_identity` wolane ponizej NIGDY nie
# przekazuje `local_literals`, wiec regula piata nie ma z czego dac trafienia.
HISTORY_IDENTITY_RULE_IDS: tuple[str, ...] = guard.IDENTITY_RULE_IDS[:-1]

# Wyrazenie ZGRUBNE (rozszerzone, BEZ spojrzen wstecz - zalozenie Z-97) dla
# przesiewu przez `git grep --extended-regexp`. Powod przesiewu zgrubnego:
# precyzyjne wzorce warstwy tozsamosciowej (`PRIVATE_IPV4_PATTERN`) niosa
# negatywne spojrzenia wstecz, ktore wymagaja od gita silnika wyrazen zgodnego
# z biblioteka rozszerzona (PCRE) - jego dostepnosc zalezy od tego, jak git
# zostal zbudowany, i nie jest wlasnoscia, na ktora ta bramka moze liczyc.
# Przesiew zgrubny (bez spojrzen wstecz, wiec dzialajacy na KAZDYM zbudowanym
# gicie) plus dopasowanie precyzyjne w Pythonie nad kazda zgrubnie trafiona
# linia daje ten sam wynik bez tej zaleznosci. Nadmiarowe trafienia zgrubne
# (np. "ap" wewnatrz innego slowa razem z cyfra) sa oczekiwane i nieszkodliwe -
# odsiewa je dopiero precyzyjny wzorzec w Pythonie.
COARSE_SIEVE_PATTERN = (
    r"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|[0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}"
    r"|(plc|rtu|hmi|ied|mtu|dcs|scada|ews|ows|vfd|ipc|rbc|leu|sw|fw|ap)[_-][0-9]"
    r"|railguard)"
)

# Kontrakt naprawy (D-24), rozciagniety z JEDNEJ sciezki (`standards/.local`,
# `tests/test_no_history_leak.py::REMEDIATION_MESSAGE`) na WSZYSTKIE wzorce
# tozsamosciowe: trafienie w historii to zakaz publicznego pushu, a droga
# naprawy to przepisanie historii, nigdy kolejny commit. Jesli publiczny push
# juz sie odbyl, przepisanie historii nie cofa faktu, ze tresc mogla zostac
# zescrapowana albo zmirrorowana. To samo brzmienie stoi w README i (po
# zadaniu 2) w rekordzie audytu.
REMEDIATION_MESSAGE = (
    "Trafienie wzorca warstwy tozsamosciowej w historii repozytorium (tresc "
    "drzewa, komunikat commita albo nazwa pliku). To NIE jest sytuacja do "
    "naprawienia kolejnym commitem - tresc juz jest w historii. Wymagane "
    "jest przepisanie historii przez `git filter-repo` PRZED jakimkolwiek "
    "publicznym pushem. Jesli publiczny push juz sie odbyl, przepisanie "
    "historii nie cofa faktu, ze tresc mogla zostac zescrapowana albo "
    "zmirrorowana."
)

_COMMIT_RECORD_SEP = "\x00"
_COMMIT_FIELD_SEP = "\x1f"


# --- Wywolania gita -----------------------------------------------------------


def _run_git(args: list[str]) -> str:
    """Wolanie gita z wymogiem ZEROWEGO kodu wyjscia - ten sam idiom
    podprocesu, co `tests/test_no_history_leak.py::_run_git`, z jednym
    swiadomym rozszerzeniem: jawne `encoding="utf-8"` (z `errors="replace"`
    na nieprzewidziany bajt), bo w odroznieniu od tamtego testu (sciezki
    ASCII) ten modul czyta tresc drzew i komunikaty commitow, ktore niosa
    polskie znaki diakrytyczne - poleganie na kodowaniu domyslnym danej
    maszyny psuloby dopasowanie wzorcow na Windows.
    """
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return result.stdout


def _run_git_grep(args: list[str]) -> str:
    """Jak `_run_git`, ale dla `git grep`: kod wyjscia 1 (brak trafien) NIE
    jest bledem - to jest wynik prawidlowy, oznaczajacy "przesiew zgrubny nie
    znalazl niczego". Kazdy INNY niezerowy kod (zly argument, uszkodzone
    drzewo) konczy test porazka niosaca wyjscie bledu, nigdy cichym
    pominieciem.
    """
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in (0, 1):
        raise AssertionError(
            f"git {' '.join(args)} zakonczylo sie kodem {result.returncode}: "
            f"{result.stderr}"
        )
    return result.stdout


def _all_revisions() -> list[str]:
    """Lista rewizji osiagalnych ze WSZYSTKICH referencji (`git rev-list
    --all`). Pusta lista jest stanem BLEDU (historia bez ani jednego commita
    nie ma czego audytowac), nie zielonym przebiegiem - stad `raise`, nie
    ciche `return []`.
    """
    output = _run_git(["rev-list", "--all"])
    revisions = [line.strip() for line in output.splitlines() if line.strip()]
    if not revisions:
        raise AssertionError(
            "git rev-list --all zwrocilo pusta liste rewizji - audyt "
            "historii nie ma czego skanowac; to jest stan bledu, nie sukces."
        )
    return revisions


def _commit_object_exists(sha: str) -> bool:
    """Sprawdza, czy `sha` wskazuje ISTNIEJACY obiekt commita. Ta sama
    kontrola, ktora bramka rekordu audytu (zadanie 2, `check_history_audit_gate.py`)
    stosuje do pola `head_sha` zapisanego rekordu - wydzielona tu jako
    samodzielna jednostka logiki i testowana ponizej na przykladzie znanym
    z gory (biezacy HEAD), zanim rekord audytu (ktory ta funkcja ma
    docelowo weryfikowac) w ogole zacznie istniec (powstaje w zadaniu 2).
    """
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    return result.returncode == 0


# --- Powierzchnia pierwsza: tresc drzew ---------------------------------------


def _tree_content_hits() -> list[tuple[str, str, int, str]]:
    """Powierzchnia pierwsza: tresc drzew wszystkich rewizji.

    Jedno wywolanie `git grep` nad WSZYSTKIMI rewizjami naraz, wyrazeniem
    ZGRUBNYM (`COARSE_SIEVE_PATTERN`). `-I` wymusza traktowanie plikow
    binarnych jako binarnych - ich tresc nigdy nie trafia do wyjscia (wiec
    audyt tresci drzew, tak jak sam skrypt bramki, nie obejmuje plikow
    binarnych - to jest ta sama, juz znana granica, ktora README nazywa
    wprost dla bramki biezacej).

    Kazda zgrubnie trafiona linia idzie POTEM przez precyzyjna warstwe
    tozsamosciowa (`scan_text_identity`) - przesiew zgrubny wylacznie ZAWEZA
    liczbe linii do sprawdzenia, nigdy sam w sobie nie jest werdyktem.
    Zwracana krotka niesie rewizje, sciezke i numer linii Z WYJSCIA GITA
    (nie z wewnetrznego liczenia `scan_text_identity`, ktore dla
    pojedynczej linii zawsze zwrocilyby 1) - to jest adres trafienia
    wlasciwy dla tej powierzchni.
    """
    revisions = _all_revisions()
    output = _run_git_grep(
        [
            "grep",
            "-n",
            "-I",
            "--extended-regexp",
            "--ignore-case",
            "-e",
            COARSE_SIEVE_PATTERN,
            *revisions,
        ]
    )

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)
    path_exceptions = guard._identity_path_exceptions(allow_lines)

    hits: list[tuple[str, str, int, str]] = []
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        revision, path, line_no_str, content = raw_line.split(":", 3)
        for violation in guard.scan_text_identity(
            content, path, declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            if guard._identity_rule_is_suppressed(path, violation.rule_id, path_exceptions):
                continue
            hits.append((revision, path, int(line_no_str), violation.rule_id))
    return hits


# --- Powierzchnia druga: komunikaty commitow ----------------------------------


def _commit_message_hits() -> list[tuple[str, str]]:
    """Powierzchnia druga: komunikaty commitow wszystkich rewizji.

    Jedno wywolanie `git log --all`, w formacie, w ktorym KAZDY rekord
    (commit) jest ograniczony bajtem zerowym (`\\x00`), a WEWNATRZ rekordu
    skrot i tresc komunikatu sa rozdzielone znakiem separatora jednostki
    (`\\x1f`, ASCII Unit Separator). Ksztalt POTWIERDZONY przebiegiem na tej
    maszynie (nie zalozony): kazdy rekord poza pierwszym niesie wiodacy znak
    nowej linii (git dopisuje go po kazdym wpisie formatu), stad
    `record.lstrip("\\n")` przed rozdzieleniem na skrot i tresc.

    Wyjatkow sciezki (`identity-path:...`) NIE stosuje (zalozenie Z-99):
    komunikat commita nie ma sciezki, wiec nie ma czym do nich pasowac -
    komunikat commita ma przez to dyscypline SCISLEJSZA niz plik pod
    katalogiem planowania, i to jest wlasciwe, bo komunikatu nie da sie
    poprawic bez przepisania historii. Deklaracje wartosci adresowych
    (`identity-value:...`) stosuje, bo te dotycza WARTOSCI, nie sciezki.
    """
    # UWAGA: `%x1f` i `%x00` ponizej sa DOSLOWNYM tekstem argumentu (dyrektywy
    # formatu gita each wstawiajace jeden bajt do WYJSCIA) - to NIE to samo,
    # co wstawienie prawdziwego bajtu zerowego DO SAMEGO ARGUMENTU polecenia
    # (`_COMMIT_RECORD_SEP` ponizej sluzy do parsowania WYJSCIA, nigdy do
    # budowy argumentu). Pomylenie tych dwoch konczy sie na Windows bledem
    # `ValueError: embedded null character` z `_winapi.CreateProcess`, bo
    # argument z prawdziwym bajtem zerowym nie da sie przekazac jako C-string.
    output = _run_git(["log", "--all", "--format=%H%x1f%B%x00"])

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)

    hits: set[tuple[str, str]] = set()
    for record in output.split(_COMMIT_RECORD_SEP):
        cleaned = record.lstrip("\n")
        if not cleaned.strip():
            continue
        revision, separator, message = cleaned.partition(_COMMIT_FIELD_SEP)
        if not separator:
            continue
        for violation in guard.scan_text_identity(
            message, "<commit-message>", declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            hits.add((revision, violation.rule_id))
    return sorted(hits)


# --- Powierzchnia trzecia: nazwy plikow ---------------------------------------


def _file_name_hits() -> list[tuple[str, str, str]]:
    """Powierzchnia trzecia: nazwy plikow z drzewa KAZDEJ rewizji.

    Jedno wywolanie `git ls-tree -r --name-only -z` NA REWIZJE (zalozenie
    Z-98): historia zmian (`git log --name-only`) domyslnie pomija commity
    scalajace i wymaga jawnej flagi, zeby ich listy plikow byly widoczne -
    suma nazw po DRZEWACH jest kompletna niezaleznie od tego. Koszt (okolo
    dwoch setek wywolan gita) jest akceptowalny WYLACZNIE wewnatrz testu ze
    znacznikiem wolnym, i to jest dokladnie ten koszt, dla ktorego ten
    znacznik istnieje.

    Nazwy sa zbierane do SUMY (unia po wszystkich rewizjach, kazda nazwa
    raz) PRZED precyzyjnym dopasowaniem - ten sam plik przezywa dziesiatki
    commitow niezmieniony, wiec sprawdzanie go ponownie przy kazdej rewizji
    byloby praca zmarnowana. Dla kazdej unikalnej nazwy z trafieniem
    zapamietywana jest PIERWSZA rewizja, w ktorej ta nazwa wystapila
    (kolejnosc `_all_revisions()`) - adres trafienia wlasciwy dla tej
    powierzchni to sama nazwa pliku, nie jej tresc.
    """
    revisions = _all_revisions()

    name_first_revision: dict[str, str] = {}
    for revision in revisions:
        output = _run_git(["ls-tree", "-r", "--name-only", "-z", revision])
        for raw_name in output.split("\x00"):
            if not raw_name:
                continue
            name_first_revision.setdefault(raw_name, revision)

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)
    path_exceptions = guard._identity_path_exceptions(allow_lines)

    hits: list[tuple[str, str, str]] = []
    for raw_name, revision in name_first_revision.items():
        for violation in guard.scan_text_identity(
            raw_name, raw_name, declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            if guard._identity_rule_is_suppressed(raw_name, violation.rule_id, path_exceptions):
                continue
            hits.append((revision, raw_name, violation.rule_id))
    return hits


# --- Komunikaty porazki: rewizja + adres + regula, NIGDY tresc ---------------


def _format_tree_content_message(hits: list[tuple[str, str, int, str]]) -> str:
    lines = [f"Powierzchnia '{HISTORY_SURFACES[0]}': {len(hits)} trafien poza wyjatkami."]
    for revision, path, line_no, rule_id in hits[:20]:
        lines.append(f"  {revision} {path}:{line_no} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


def _format_commit_message_message(hits: list[tuple[str, str]]) -> str:
    lines = [f"Powierzchnia '{HISTORY_SURFACES[1]}': {len(hits)} trafien poza wyjatkami."]
    for revision, rule_id in hits[:20]:
        lines.append(f"  {revision} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


def _format_file_name_message(hits: list[tuple[str, str, str]]) -> str:
    lines = [f"Powierzchnia '{HISTORY_SURFACES[2]}': {len(hits)} trafien poza wyjatkami."]
    for revision, name, rule_id in hits[:20]:
        lines.append(f"  {revision} {name} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


# --- Testy: kontrakt modulu ----------------------------------------------------


def test_module_defines_three_distinct_surfaces():
    assert len(HISTORY_SURFACES) == 3
    assert len(set(HISTORY_SURFACES)) == 3


def test_remediation_message_names_filter_repo():
    assert "filter-repo" in REMEDIATION_MESSAGE


def test_history_identity_rules_exclude_the_local_only_fifth_rule():
    """HISTORY_IDENTITY_RULE_IDS obejmuje wylacznie cztery reguly KSZTALTU -
    piata (identity-local-literal) dziala WYLACZNIE lokalnie i audyt, ktory
    ma dzialac w CI, nie ma z czego jej sprawdzic (brak pliku lokalnego)."""
    assert guard.RULE_IDENTITY_LOCAL_LITERAL not in HISTORY_IDENTITY_RULE_IDS
    assert len(HISTORY_IDENTITY_RULE_IDS) == 4


def test_all_revisions_covers_every_reachable_revision():
    """Skan ma widziec CALA historie, nie tylko biezaca galaz.

    Porownanie idzie z niezaleznym pomiarem git zamiast ze stalym progiem:
    prog dopasowany do chwilowej liczby commitow starzeje sie przy kazdym
    przepisaniu historii i wtedy czerwieni sie test, a nie bramka. Ta asercja
    lapie to, o co naprawde chodzi - ze `_all_revisions()` nie zwrocilo
    samego HEAD ani pustej listy.
    """
    expected = subprocess.run(
        ["git", "rev-list", "--all", "--count"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    revisions = _all_revisions()
    assert len(revisions) == int(expected)
    assert len(revisions) > 1


def test_each_surface_is_a_separate_function_with_separate_parsing():
    """Sprawdzenie PO ZRODLE modulu - wzorce sklejone z dwoch czesci, zeby to
    sprawdzenie nie zlapalo WLASNEGO zrodla (linii ponizej) jako trzeciego
    wystapienia, dokladnie jak `test_readme_claims.py::test_module_source_contains_no_file_write_calls`."""
    import inspect

    source = inspect.getsource(sys.modules[__name__])
    def_kw = "def" + " "
    assert source.count(def_kw + "_tree_content_hits") == 1
    assert source.count(def_kw + "_commit_message_hits") == 1
    assert source.count(def_kw + "_file_name_hits") == 1


# --- Testy: powiazanie sha -> obiekt commita (test powiazania rekordu) -------


def test_current_head_is_a_reachable_commit_object():
    head = _run_git(["rev-parse", "HEAD"]).strip()
    assert _commit_object_exists(head)


def test_zero_sha_is_not_a_reachable_commit_object():
    assert not _commit_object_exists("0" * 40)


# --- Testy: trzy powierzchnie, zero trafien poza wyjatkami -------------------


def test_tree_content_surface_has_zero_hits_outside_exceptions():
    hits = _tree_content_hits()
    assert hits == [], _format_tree_content_message(hits)


def test_commit_message_surface_has_zero_hits_outside_exceptions():
    hits = _commit_message_hits()
    assert hits == [], _format_commit_message_message(hits)


def test_file_name_surface_has_zero_hits_outside_exceptions():
    hits = _file_name_hits()
    assert hits == [], _format_file_name_message(hits)


# --- Test: skan nie zmienia stanu repozytorium (skan jest wylacznie odczytem) -


def _repo_state() -> tuple[str, str]:
    head = _run_git(["rev-parse", "HEAD"]).strip()
    status = _run_git(["status", "--porcelain"])
    return head, status


def test_scan_does_not_change_repository_state():
    """Skan jest wylacznie odczytem: stan HEAD i drzewa roboczego przed
    trzema skanami i po nich sa identyczne. Test NIE wymaga, zeby skrot
    HEAD zapisany w rekordzie audytu (zadanie 2) byl rowny BIEZACEMU HEAD -
    przerwany przebieg NIE jest przejsciem (werdykt wiaze wylacznie ze
    skrotem zapisanym w rekordzie), ale rownosc z biezacym HEAD wymaga
    dopiero bramka przedpublikacyjna z zadania 2 (flaga --require-current,
    zalozenie Z-100)."""
    before = _repo_state()
    _tree_content_hits()
    _commit_message_hits()
    _file_name_hits()
    after = _repo_state()
    assert before == after
