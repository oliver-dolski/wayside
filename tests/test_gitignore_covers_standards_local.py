"""Test FOUND-04 / 05-03: `standards/.local` i `.confidentiality-identity.local`
sa ignorowane zachowaniowo.

Sprawdza ZACHOWANIE gita (`git check-ignore`), nie tresc pliku `.gitignore`.
Test czytajacy `.gitignore` szuka linii tekstu i przechodzilby takze wtedy,
gdy inna regula nizej ten wpis odwraca (`!standards/.local/`) - `git
check-ignore` jest jedynym zrodlem prawdy, ktore uwzglednia CALY lancuch
regul, nie tylko jedna linie.

Dwa pilnowane pliki: `standards/.local` (korpus norm, warstwa 1) i
`.confidentiality-identity.local` (literaly lokalne warstwy 3, plan 05-03).
Kazdy ma sonde pozytywna (sciezka jest ignorowana) i negatywna (sasiedni
plik/katalog publiczny NIE jest ignorowany) - regula zbyt szeroka zdjelaby
z pola widzenia gita cos, co ma byc widoczne.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _check_ignore(path: str) -> int:
    result = subprocess.run(
        ["git", "check-ignore", "-q", path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode


def test_standards_local_probe_path_is_ignored():
    assert _check_ignore("standards/.local/probe.txt") == 0


def test_public_standards_probe_path_is_not_ignored():
    # Regula nie moze byc zbyt szeroka - sasiedni katalog publiczny musi
    # zostac widoczny dla gita.
    assert _check_ignore("standards/publiczny.md") == 1


def test_identity_local_literal_file_is_ignored():
    assert _check_ignore(".confidentiality-identity.local") == 0


def test_neighboring_public_local_probe_path_is_not_ignored():
    # Regula nie moze byc zbyt szeroka - sasiedni plik bez czlonu lokalnosci
    # musi zostac widoczny dla gita, inaczej regula zdejmowalaby z pola
    # widzenia cos, co ma byc widoczne.
    assert _check_ignore(".confidentiality-identity-public-probe") == 1
