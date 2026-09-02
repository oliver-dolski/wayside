"""Test kontraktowy FOUND-02: cache scapy nigdy nie ladzie w katalogu domowym.

Skad ten test. `scapy.data.scapy_data_cache` sprawdza `cachepath.exists()` bez
obslugi wyjatku, a `pathlib.Path.exists()` przy `EACCES` podnosi
`PermissionError`, zamiast zwrocic `False` (ignoruje tylko ENOENT/ENOTDIR/
EBADF/ELOOP). Na maszynie autora `~/.cache/scapy` mial ACL zabraniajacy
przejscia - typowo slad po uruchomieniu scapy z podniesionymi uprawnieniami -
i kazdy import `wayside.pcap` konczyl sie wyjatkiem, mimo ze sam odczyt pcap
nie potrzebuje tego cache'u do niczego.

Czego ten test NIE robi i dlaczego. Nie odtwarza niedostepnego katalogu:
katalog istniejacy i zabraniajacy przejscia wymaga `icacls` na Windows albo
`chmod 000` na POSIX, wiec taki test nie jest przenosny (a pod pustym
katalogiem domowym scapy po prostu tworzy `~/.cache` od nowa i defekt sie
nie ujawnia - sprawdzone). Test pilnuje wiec mechanizmu obrony, nie
srodowiska: skoro `wayside.pcap` w ogole nie kieruje cache'u scapy do `~`,
stan tego katalogu przestaje miec znaczenie.

Kontrakt jest sprawdzany w podprocesie, bo `scapy.main` wylicza
`SCAPY_CACHE_FOLDER` raz, przy imporcie - w procesie testowym scapy moze byc
zaimportowane wczesniej przez inny test i wynik nie mowilby nic.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Importuje warstwe odczytu, a potem odczytuje faktyczna decyzje scapy.
# `scapy.main` jest w tym momencie zaimportowane juz tranzytywnie przez
# `scapy.data`, wiec ten import nie dodaje nowej zaleznosci.
_PROBE = (
    "import json, os;"
    "import wayside.pcap;"
    "import scapy.main;"
    "print(json.dumps({"
    "'cache_folder': str(scapy.main.SCAPY_CACHE_FOLDER),"
    "'xdg_after_import': os.environ.get('XDG_CACHE_HOME'),"
    "}))"
)


def _probe(env_overrides: dict[str, str | None]) -> dict:
    env = dict(os.environ)
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value

    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_cache_lands_outside_dot_cache_when_xdg_unset():
    probe = _probe({"XDG_CACHE_HOME": None})
    cache_folder = Path(probe["cache_folder"]).resolve()
    expected_root = (Path(tempfile.gettempdir()) / "wayside-scapy-cache").resolve()

    assert cache_folder.is_relative_to(expected_root)
    # Broniona granica to `~/.cache`, nie caly katalog domowy: na Windows
    # per-user temp lezy pod `~` (`AppData\Local\Temp`) i jest wlasciwym
    # miejscem na cache. Defekt dotyczy wylacznie `~/.cache/scapy`.
    assert not cache_folder.is_relative_to((Path.home() / ".cache").resolve())


def test_explicit_xdg_cache_home_is_respected(tmp_path):
    explicit = tmp_path / "cache"
    probe = _probe({"XDG_CACHE_HOME": str(explicit)})

    assert Path(probe["cache_folder"]).resolve().is_relative_to(explicit.resolve())


def test_import_does_not_leak_xdg_cache_home():
    probe = _probe({"XDG_CACHE_HOME": None})

    assert probe["xdg_after_import"] is None
