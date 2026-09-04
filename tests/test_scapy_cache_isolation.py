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

# Importuje cala sciezke odczytu tej fazy (nie tylko `wayside.pcap`), a
# potem odczytuje faktyczna decyzje scapy. `scapy.main` jest w tym momencie
# zaimportowane juz tranzytywnie przez `scapy.data`, wiec ten import nie
# dodaje nowej zaleznosci. Rozszerzenie o `wayside.decode` i
# `wayside.protocols.modbus_tcp` domyka Pitfall 4 z 02-RESEARCH.md: przed
# tym rozszerzeniem import `scapy.layers.*`/`scapy.contrib.modbus` w
# sciezce ODCZYTU nie byl objety zadna bramka maszynowa poza `scapy.all`.
_PROBE = (
    "import json, os, sys;"
    "import wayside.pcap;"
    "import wayside.decode;"
    "import wayside.protocols.modbus_tcp;"
    "import scapy.main;"
    "import scapy.config;"
    "print(json.dumps({"
    "'cache_folder': str(scapy.main.SCAPY_CACHE_FOLDER),"
    "'xdg_after_import': os.environ.get('XDG_CACHE_HOME'),"
    "'scapy_all_imported': 'scapy.all' in sys.modules,"
    "'scapy_libpcap_imported': 'scapy.arch.libpcap' in sys.modules,"
    "'route_autoload': scapy.config.conf.route_autoload,"
    "'route6_autoload': scapy.config.conf.route6_autoload,"
    "'route_count': len(scapy.config.conf.route.routes),"
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


# --- Rozszerzenie sciezki odczytu (Faza 2): decode.py + protocols/modbus_tcp.py ---


def test_scapy_all_not_imported_after_extended_read_path():
    """D-04/LOCK-01 nadal obowiazuje: rozszerzenie sciezki odczytu o
    `wayside.decode` i `wayside.protocols.modbus_tcp` nie wciaga `scapy.all`."""
    probe = _probe({"XDG_CACHE_HOME": None})
    assert probe["scapy_all_imported"] is False


def test_scapy_arch_libpcap_import_is_conscious_widening():
    """Import `scapy.layers.*`/`scapy.contrib.modbus` w sciezce odczytu
    laduje transitywnie `scapy.arch.libpcap` (02-RESEARCH.md, sekcja
    "Konflikt z ARCHITECTURE.md" oraz Pitfall 4). Zweryfikowane odczytem
    `scapy/arch/libpcap.py`: brak Npcap degraduje sie przez przechwycony
    `OSError` do `conf.use_pcap = False`, nie do wyjatku - wiec ta obecnosc
    jest swiadomym poszerzeniem tej fazy, nie regresja."""
    probe = _probe({"XDG_CACHE_HOME": None})
    assert probe["scapy_libpcap_imported"] is True


def test_read_path_never_queries_system_routing_table():
    """Sciezka odczytu nie odpytuje systemu o tablice routingu.

    `scapy.route` przy imporcie wykonuje `conf.route = Route()`, a `Route`
    z domyslnym `conf.route_autoload` woala systemowy odczyt tras. Na Windows
    idzie to przez `GetIpForwardTable2` i konczylo sie niedeterministycznym
    naruszeniem ochrony pamieci (0xC0000005) w `scapy.arch.windows._extract_ip`,
    ubijajac mniej wiecej co trzeci pelny przebieg pakietu testow w losowym
    miejscu. Modul `wayside.pcap` gasi obie flagi przed pierwszym importem
    warstwy - ten test pilnuje, ze gasi je skutecznie i ze zaden przyszly
    import nie wejdzie przed niego.

    Poza stabilnoscia jest to tez granica projektowa: narzedzie jest pasywne,
    wiec nie ma powodu, zeby pytalo system o cokolwiek zwiazanego z wysylka.
    """
    probe = _probe({"XDG_CACHE_HOME": None})

    assert probe["route_autoload"] is False
    assert probe["route6_autoload"] is False
    assert probe["route_count"] == 0


def test_decode_full_fixture_in_subprocess_exits_zero():
    """Dowod, ze import warstw nie tylko przechodzi, ale ze odczyt na nich
    faktycznie dziala: dekoduje istniejacy fixture Fazy 1 w podprocesie."""
    script = (
        "import sys;"
        "from pathlib import Path;"
        "import wayside.pcap as pcap;"
        "import wayside.decode as decode;"
        "packets = pcap.read_capture("
        "Path('tests/fixtures/pcap/modbus_write_single_register.pcap'));"
        "segments = decode.decode_segments(packets);"
        "sys.exit(0 if len(segments) == 2 else 1)"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
