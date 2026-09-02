"""Test FOUND-04: `standards/.local` jest ignorowany zachowaniowo.

Sprawdza ZACHOWANIE gita (`git check-ignore`), nie tresc pliku `.gitignore`.
Test czytajacy `.gitignore` szuka linii tekstu i przechodzilby takze wtedy,
gdy inna regula nizej ten wpis odwraca (`!standards/.local/`) - `git
check-ignore` jest jedynym zrodlem prawdy, ktore uwzglednia CALY lancuch
regul, nie tylko jedna linie.
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
