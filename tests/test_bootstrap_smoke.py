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

import pytest
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


# WR-01 z `01-REVIEW.md`. `read_capture` opiera sie na `Path.exists()`, ktore
# jest prawdziwe takze dla katalogu, a istniejacy plik moze byc uszkodzonym
# albo plikiem nieczytelnym jako pcap. Oba podnosza z `rdpcap` wyjatek spoza
# `FileNotFoundError`, wiec przed poprawka konczyly sie surowym tracebackiem
# zamiast komunikatu i kodu 2. Test na brakujacym pliku wyzej ich nie lapal.
def test_inspect_directory_exits_two_without_traceback(tmp_path):
    result = _run_cli("inspect", str(tmp_path))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("nazwa", "zawartosc"),
    [
        ("smieci.pcap", b"to nie jest pcap w ogole, zupelnie losowe bajty"),
        ("pusty.pcap", b""),
    ],
)
def test_inspect_unreadable_pcap_exits_two_without_traceback(
    tmp_path, nazwa, zawartosc
):
    uszkodzony = tmp_path / nazwa
    uszkodzony.write_bytes(zawartosc)
    result = _run_cli("inspect", str(uszkodzony))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
