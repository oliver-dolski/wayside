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
    assert "Packet count: 2" in result.stdout


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


# Kontrakt ksztaltu `scripts/bootstrap.ps1`, nie test dymny CLI. Powod osobny
# i konkretny: UAT fazy 1, test 2, na czystym Windows 11 pokazal, ze bootstrap
# instaluje `uv` przez winget POPRAWNIE, a potem sam go nie widzi, bo PATH
# procesu pozostaje kopia sprzed instalacji. Skrypt konczyl sie wtedy kodem 1
# i kazal otworzyc nowa powloke - czyli obietnica FOUND-01 "jedno polecenie po
# klonie" wymagala dwoch uruchomien.
#
# Tego nie da sie sprawdzic z maszyny, ktora ma juz `uv` na PATH: warunek
# w ogole nie zachodzi. Ten test pilnuje wiec kolejnosci krokow w skrypcie,
# tak jak `test_ci_workflow_contract.py` pilnuje ksztaltu workflow. Dowodzi
# ksztaltu, nie zachowania, i tak ma byc czytany.
BOOTSTRAP = REPO_ROOT / "scripts" / "bootstrap.ps1"


def _bootstrap_text() -> str:
    return BOOTSTRAP.read_text(encoding="utf-8")


def test_bootstrap_defines_path_refresh_helper():
    tekst = _bootstrap_text()
    assert "function Update-PathFromRegistry" in tekst
    assert "GetEnvironmentVariable('Path', 'Machine')" in tekst
    assert "GetEnvironmentVariable('Path', 'User')" in tekst


def test_bootstrap_refreshes_path_between_winget_install_and_recheck():
    tekst = _bootstrap_text()

    instalacja = tekst.index("winget install --id astral-sh.uv")
    odswiezenie = tekst.index("Update-PathFromRegistry", instalacja)
    ponowne_sprawdzenie = tekst.index("uv nadal niedostepne na PATH", odswiezenie)

    assert instalacja < odswiezenie < ponowne_sprawdzenie, (
        "Odswiezenie PATH musi stac MIEDZY instalacja przez winget a ponownym "
        "sprawdzeniem obecnosci uv. Poza ta kolejnoscia nie naprawia niczego."
    )


def test_bootstrap_does_not_tell_user_to_reopen_shell_as_normal_path():
    """Komunikat o nowej powloce ma zostac wylacznie jako ostatnia deska ratunku.

    Gdyby wrocil jako zwykla sciezka - czyli gdyby zniknelo odswiezenie PATH -
    poprzedni test i tak by padl. Ten pilnuje czegos innego: ze tresc komunikatu
    nadal mowi o odswiezeniu, wiec kto go zobaczy, wie, ze proste obejscie
    zostalo juz sprobowane i nie pomoglo.
    """
    tekst = _bootstrap_text()
    assert "odswiezenia PATH z rejestru" in tekst


# Idempotencja bootstrapu. Wykryte 2026-09-03 przy zmianie nazwy katalogu
# projektu, ktora wymusila drugi przebieg skryptu: odbil sie o `Cowardly
# refusing to install hooks with core.hooksPath set`.
#
# Przyczyna nie miala nic wspolnego ze zmiana nazwy. `core.hooksPath` moze
# siedziec w dwoch zakresach naraz, a skrypt sam przypina `.git/hooks`
# LOKALNIE na koncu swojego pierwszego przebiegu. Obejscie przez
# `GIT_CONFIG_GLOBAL` zdejmuje wylacznie zakres globalny, wiec przy drugim
# przebiegu skrypt widzial wlasne przypiecie i stosowal do niego obejscie
# przeznaczone dla czegos innego. Wywrocilby sie KAZDY drugi przebieg,
# z dowolnego powodu - nie tylko po zmianie nazwy katalogu.


def test_bootstrap_reads_hooks_path_in_both_scopes():
    tekst = _bootstrap_text()
    assert "git config --get core.hooksPath" in tekst, "brak odczytu zakresu efektywnego"
    assert "git config --local --get core.hooksPath" in tekst, "brak odczytu zakresu lokalnego"


def test_bootstrap_unsets_local_hooks_path_before_install():
    tekst = _bootstrap_text()

    zdjecie = tekst.index("git config --local --unset-all core.hooksPath")
    instalacja = tekst.index("uv run pre-commit install", zdjecie)

    assert zdjecie < instalacja, (
        "Lokalne core.hooksPath musi byc zdjete PRZED `pre-commit install`. "
        "Obejscie przez GIT_CONFIG_GLOBAL nie dotyka .git/config, wiec samo "
        "nie wystarcza."
    )


def test_bootstrap_restores_local_hooks_path_even_when_install_failed():
    """Przywrocenie musi stac PRZED rzuceniem wyjatku o kodzie instalacji.

    Inaczej nieudana instalacja zostawia repozytorium bez lokalnego przypiecia,
    czyli git wraca do globalnej sciezki hakow dewelopera, a hak poufnosci nie
    wywola sie przy nastepnym commicie. To gorszy stan niz sama porazka
    instalacji, bo wyglada niewinnie.
    """
    tekst = _bootstrap_text()

    przywrocenie = tekst.index("git config --local core.hooksPath $localHooksPath")
    rzut = tekst.index("uv run pre-commit install zakonczylo sie kodem", przywrocenie)

    assert przywrocenie < rzut, (
        "Przywrocenie lokalnego core.hooksPath musi poprzedzac sprawdzenie "
        "kodu wyjscia instalacji."
    )
