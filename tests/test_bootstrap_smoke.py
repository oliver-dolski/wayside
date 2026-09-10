"""Smoke test FOUND-01: the CLI starts and reads a fixture, exit code 0.

The CLI is called as a subprocess through `python -m wayside.cli` rather than
imported into the test process - that reproduces the actual user path
(`uv run wayside ...`) and works without activating the venv by hand in a
shell, because under `uv run pytest` `sys.executable` already points at the
interpreter of the project environment, where `wayside` is installed.
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
    result = _run_cli("inspect", "does-not-exist.pcap")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


# WR-01 of `01-REVIEW.md`. `read_capture` rests on `Path.exists()`, which is
# true for a directory as well, and an existing file may be damaged or
# unreadable as a pcap. Both raise an exception out of `rdpcap` other than
# `FileNotFoundError`, so before the fix they ended in a raw traceback instead
# of a message and exit code 2. The missing-file test above did not catch them.
def test_inspect_directory_exits_two_without_traceback(tmp_path):
    result = _run_cli("inspect", str(tmp_path))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("garbage.pcap", b"this is not a pcap at all, just random bytes"),
        ("empty.pcap", b""),
    ],
)
def test_inspect_unreadable_pcap_exits_two_without_traceback(tmp_path, name, content):
    damaged = tmp_path / name
    damaged.write_bytes(content)
    result = _run_cli("inspect", str(damaged))
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


# A contract for the shape of `scripts/bootstrap.ps1`, not a CLI smoke test.
# The reason is separate and concrete: the phase 1 UAT, test 2, on a clean
# Windows 11 showed that the bootstrap installs `uv` through winget CORRECTLY
# and then cannot see it, because the process PATH stays a copy of the one from
# before the installation. The script then exited with code 1 and told the user
# to open a new shell - that is, the FOUND-01 promise of "one command after the
# clone" needed two runs.
#
# This cannot be checked from a machine that already has `uv` on PATH: the
# condition never arises. This test therefore guards the order of the steps in
# the script, the way `test_ci_workflow_contract.py` guards the shape of the
# workflow. It proves shape, not behaviour, and is meant to be read that way.
BOOTSTRAP = REPO_ROOT / "scripts" / "bootstrap.ps1"


def _bootstrap_text() -> str:
    return BOOTSTRAP.read_text(encoding="utf-8")


def test_bootstrap_defines_path_refresh_helper():
    text = _bootstrap_text()
    assert "function Update-PathFromRegistry" in text
    assert "GetEnvironmentVariable('Path', 'Machine')" in text
    assert "GetEnvironmentVariable('Path', 'User')" in text


def test_bootstrap_refreshes_path_between_winget_install_and_recheck():
    text = _bootstrap_text()

    install = text.index("winget install --id astral-sh.uv")
    refresh = text.index("Update-PathFromRegistry", install)
    recheck = text.index("uv is still unavailable on PATH", refresh)

    assert install < refresh < recheck, (
        "The PATH refresh has to stand BETWEEN the winget installation and the "
        "recheck for the presence of uv. In any other order it fixes nothing."
    )


def test_bootstrap_does_not_tell_user_to_reopen_shell_as_normal_path():
    """The message about a new shell is meant to stay a last resort only.

    Were it to come back as the ordinary path - that is, were the PATH refresh
    to disappear - the previous test would fail anyway. This one guards
    something else: that the wording of the message still speaks of the
    refresh, so whoever sees it knows the simple workaround has already been
    tried and did not help.
    """
    text = _bootstrap_text()
    assert "the PATH refresh from the registry" in text


# Idempotence of the bootstrap. Discovered 2026-09-03 while renaming the
# project directory, which forced a second run of the script: it bounced off
# `Cowardly refusing to install hooks with core.hooksPath set`.
#
# The cause had nothing to do with the rename. `core.hooksPath` can sit in two
# scopes at once, and the script pins `.git/hooks` LOCALLY itself at the end of
# its first run. The `GIT_CONFIG_GLOBAL` workaround lifts the global scope
# only, so on the second run the script saw its own pin and applied to it a
# workaround meant for something else. EVERY second run would have fallen over,
# for any reason - not only after a directory rename.


def test_bootstrap_reads_hooks_path_in_both_scopes():
    text = _bootstrap_text()
    assert "git config --get core.hooksPath" in text, "no read of the effective scope"
    assert "git config --local --get core.hooksPath" in text, "no read of the local scope"


def test_bootstrap_unsets_local_hooks_path_before_install():
    text = _bootstrap_text()

    unset = text.index("git config --local --unset-all core.hooksPath")
    install = text.index("uv run pre-commit install", unset)

    assert unset < install, (
        "The local core.hooksPath has to be lifted BEFORE `pre-commit install`. "
        "The GIT_CONFIG_GLOBAL workaround does not touch .git/config, so on its "
        "own it is not enough."
    )


def test_bootstrap_restores_local_hooks_path_even_when_install_failed():
    """The restore has to stand BEFORE the throw about the install exit code.

    Otherwise a failed installation leaves the repository without its local
    pin, that is git falls back to the developer's global hook path and the
    confidentiality hook does not fire at the next commit. That is a worse
    state than the installation failure itself, because it looks innocent.
    """
    text = _bootstrap_text()

    restore = text.index("git config --local core.hooksPath $localHooksPath")
    throw = text.index("uv run pre-commit install exited with code", restore)

    assert restore < throw, (
        "The restore of the local core.hooksPath has to precede the check of "
        "the installation exit code."
    )
