"""Snapshot test FOUND-02: the full stdout of the `inspect` command pinned to syrupy.

The fixture is passed as a path relative to the repository root (not an
absolute one), because an absolute path differs between the author's machine
and the CI runner and the snapshot would drift with no change to the code at
all. The timestamps in the output come from the constants set by
`scripts/gen_fixtures.py`, so they are deterministic already.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"


def test_inspect_output_matches_snapshot(snapshot):
    result = subprocess.run(
        [sys.executable, "-m", "wayside.cli", "inspect", FIXTURE_RELATIVE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == snapshot
