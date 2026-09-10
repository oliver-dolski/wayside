"""Test FOUND-04: `standards/.local` never entered the repository history.

Two independent checks: `git log --all` (what is already in the commit
history) and `git ls-files` (what is in the index - it catches a state the log
cannot see yet, say a file added to the index but not committed).

If either of these checks ever returns a result: that is NOT a situation to be
fixed by another commit, because the content is already in the history.
Rewriting the history with `git filter-repo` is required BEFORE any public
push. If a public push has already happened, rewriting the history does NOT
undo the fact that the content may have been scraped or mirrored - see the
assertion message below and Pattern 3 in 01-RESEARCH.md.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

REMEDIATION_MESSAGE = (
    "standards/.local is in the git history. This is NOT a situation to be "
    "fixed by another commit - the content is already in the history. "
    "Rewriting the history with `git filter-repo` is required BEFORE any "
    "public push. If a public push has already happened, rewriting the "
    "history does not undo the fact that the content may have been scraped "
    "or mirrored."
)


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_standards_local_never_appears_in_commit_history():
    output = _run_git(["log", "--all", "--", "standards/.local"])
    assert output == "", REMEDIATION_MESSAGE


def test_standards_local_not_present_in_current_index():
    # `git log` sees only what has already been committed - a file added to
    # the index (say through `git add -f`) but not yet committed does not show
    # up there at all. `git ls-files` catches that state.
    output = _run_git(["ls-files", "--", "standards/.local"])
    assert output == "", REMEDIATION_MESSAGE
