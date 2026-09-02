"""Test FOUND-04: `standards/.local` nigdy nie trafil do historii repozytorium.

Dwa niezalezne sprawdzenia: `git log --all` (co juz jest w historii commitow)
i `git ls-files` (co jest w indeksie - lapie stan, ktorego log jeszcze nie
widzi, np. plik dodany do indeksu, ale jeszcze nie scommitowany).

Jesli ktorekolwiek z tych sprawdzen kiedykolwiek zwroci wynik: to NIE jest
sytuacja do naprawienia kolejnym commitem, bo tresc juz jest w historii.
Wymagane jest przepisanie historii przez `git filter-repo` PRZED jakimkolwiek
publicznym pushem. Jesli publiczny push juz sie odbyl, przepisanie historii
NIE cofa faktu, ze tresc mogla zostac zescrapowana albo zmirrorowana -
patrz komunikat asercji nizej i Pattern 3 w 01-RESEARCH.md.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

REMEDIATION_MESSAGE = (
    "standards/.local w historii gita. To NIE jest sytuacja do naprawienia "
    "kolejnym commitem - tresc juz jest w historii. Wymagane jest "
    "przepisanie historii przez `git filter-repo` PRZED jakimkolwiek "
    "publicznym pushem. Jesli publiczny push juz sie odbyl, przepisanie "
    "historii nie cofa faktu, ze tresc mogla zostac zescrapowana albo "
    "zmirrorowana."
)


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_standards_local_never_appears_in_commit_history():
    output = _run_git(["log", "--all", "--", "standards/.local"])
    assert output == "", REMEDIATION_MESSAGE


def test_standards_local_not_present_in_current_index():
    # `git log` widzi wylacznie to, co juz zostalo scommitowane - plik
    # dodany do indeksu (np. przez `git add -f`), ale jeszcze nie
    # scommitowany, nie pojawi sie tam wcale. `git ls-files` lapie ten stan.
    output = _run_git(["ls-files", "--", "standards/.local"])
    assert output == "", REMEDIATION_MESSAGE
