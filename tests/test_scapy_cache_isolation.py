"""Contract test FOUND-02: the scapy cache never lands in the home directory.

Where this test comes from. `scapy.data.scapy_data_cache` calls
`cachepath.exists()` without handling exceptions, and on `EACCES`
`pathlib.Path.exists()` raises `PermissionError` instead of returning `False`
(it ignores only ENOENT/ENOTDIR/EBADF/ELOOP). On the author's machine
`~/.cache/scapy` carried an ACL forbidding traversal - typically a leftover of
running scapy with elevated privileges - and every import of `wayside.pcap`
ended in an exception, even though reading a pcap needs that cache for
nothing.

What this test does NOT do and why. It does not recreate an inaccessible
directory: an existing directory forbidding traversal requires `icacls` on
Windows or `chmod 000` on POSIX, so such a test is not portable (and under an
empty home directory scapy simply creates `~/.cache` afresh and the defect
does not surface - checked). The test therefore guards the defence mechanism
rather than the environment: since `wayside.pcap` never points the scapy cache
at `~` at all, the state of that directory stops mattering.

The contract is checked in a subprocess, because `scapy.main` computes
`SCAPY_CACHE_FOLDER` once, at import - in the test process scapy may have been
imported earlier by another test and the result would say nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# It imports the whole read path of this phase (not only `wayside.pcap`) and
# then reads scapy's actual decision. At that point `scapy.main` has already
# been imported transitively by `scapy.data`, so this import adds no new
# dependency. Widening it to `wayside.decode` and
# `wayside.protocols.modbus_tcp` closes Pitfall 4 of 02-RESEARCH.md: before
# that widening, the `scapy.layers.*`/`scapy.contrib.modbus` import on the READ
# path was covered by no machine gate other than `scapy.all`.
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
    # The defended boundary is `~/.cache`, not the whole home directory: on
    # Windows the per-user temp lives under `~` (`AppData\Local\Temp`) and is
    # the right place for a cache. The defect concerns `~/.cache/scapy` only.
    assert not cache_folder.is_relative_to((Path.home() / ".cache").resolve())


def test_explicit_xdg_cache_home_is_respected(tmp_path):
    explicit = tmp_path / "cache"
    probe = _probe({"XDG_CACHE_HOME": str(explicit)})

    assert Path(probe["cache_folder"]).resolve().is_relative_to(explicit.resolve())


def test_import_does_not_leak_xdg_cache_home():
    probe = _probe({"XDG_CACHE_HOME": None})

    assert probe["xdg_after_import"] is None


# --- Widening the read path (Phase 2): decode.py + protocols/modbus_tcp.py ---


def test_scapy_all_not_imported_after_extended_read_path():
    """D-04/LOCK-01 still holds: widening the read path with `wayside.decode`
    and `wayside.protocols.modbus_tcp` does not pull in `scapy.all`."""
    probe = _probe({"XDG_CACHE_HOME": None})
    assert probe["scapy_all_imported"] is False


def test_scapy_arch_libpcap_import_is_conscious_widening():
    """The `scapy.layers.*`/`scapy.contrib.modbus` import on the read path
    loads `scapy.arch.libpcap` transitively (02-RESEARCH.md, the section on the
    conflict with ARCHITECTURE.md, and Pitfall 4). Verified by reading
    `scapy/arch/libpcap.py`: an absent Npcap degrades through a caught
    `OSError` into `conf.use_pcap = False` rather than into an exception - so
    this presence is a conscious widening of this phase, not a regression."""
    probe = _probe({"XDG_CACHE_HOME": None})
    assert probe["scapy_libpcap_imported"] is True


def test_read_path_never_queries_system_routing_table():
    """The read path never queries the system for the routing table.

    On import `scapy.route` executes `conf.route = Route()`, and `Route` with
    the default `conf.route_autoload` called the system route read. On Windows
    that goes through `GetIpForwardTable2` and used to end in a
    non-deterministic access violation (0xC0000005) in
    `scapy.arch.windows._extract_ip`, killing roughly every third full run of
    the test suite at a random place. The `wayside.pcap` module clears both
    flags before the first layer import - this test guards that it clears them
    effectively and that no future import gets in ahead of it.

    Beyond stability this is also a design boundary: the tool is passive, so
    there is no reason for it to ask the system about anything to do with
    sending.
    """
    probe = _probe({"XDG_CACHE_HOME": None})

    assert probe["route_autoload"] is False
    assert probe["route6_autoload"] is False
    assert probe["route_count"] == 0


def test_decode_full_fixture_in_subprocess_exits_zero():
    """Proof that importing the layers not only succeeds but that reading over
    them actually works: it decodes an existing Phase 1 fixture in a
    subprocess."""
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
