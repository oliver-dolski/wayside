"""Test FOUND-04 / 05-03: `standards/.local` and `.confidentiality-identity.local`
are ignored behaviourally.

It checks the BEHAVIOUR of git (`git check-ignore`), not the content of the
`.gitignore` file. A test reading `.gitignore` looks for a line of text and
would pass even when another rule further down reverses that entry
(`!standards/.local/`) - `git check-ignore` is the only source of truth that
takes the WHOLE chain of rules into account, not just one line.

Two guarded files: `standards/.local` (the corpus of standards, layer 1) and
`.confidentiality-identity.local` (the local literals of layer 3, plan 05-03).
Each has a positive probe (the path is ignored) and a negative one (a
neighbouring public file or directory is NOT ignored) - a rule that is too
wide would take something meant to be visible out of git's sight.
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
    # The rule must not be too wide - a neighbouring public directory has to
    # stay visible to git.
    assert _check_ignore("standards/public.md") == 1


def test_identity_local_literal_file_is_ignored():
    assert _check_ignore(".confidentiality-identity.local") == 0


def test_neighboring_public_local_probe_path_is_not_ignored():
    # The rule must not be too wide - a neighbouring file without the locality
    # part has to stay visible to git, otherwise the rule would take something
    # meant to be visible out of sight.
    assert _check_ignore(".confidentiality-identity-public-probe") == 1
