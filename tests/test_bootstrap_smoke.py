"""Test dymny FOUND-01: CLI uruchamia sie i czyta fixture, kod wyjscia 0.

CLI jest wolane jako podproces przez `python -m wayside.cli`, nie przez import
w procesie testowym - to odtwarza faktyczna sciezke uzytkownika (`uv run wayside
...`) i dziala bez recznej aktywacji venva w powloce, bo `sys.executable` pod
`uv run pytest` wskazuje juz na interpreter srodowiska projektu, w ktorym
`wayside` jest zainstalowane.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_write_single_register.pcap"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "wayside.cli", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_version_exits_zero_and_prints_version():
    result = _run_cli("--version")
    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_inspect_fixture_exits_zero_and_prints_packet_count():
    result = _run_cli("inspect", str(FIXTURE))
    assert result.returncode == 0
    assert "Liczba pakietow: 2" in result.stdout


def test_inspect_missing_file_exits_two_without_traceback():
    result = _run_cli("inspect", "nie-istnieje.pcap")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
