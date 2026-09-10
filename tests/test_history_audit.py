"""Audit PUB-05: a scan of THREE surfaces of the WHOLE repository history.

Why three surfaces and not one: a device name or an address may sit in a FILE
NAME or in a COMMIT MESSAGE, which a scan over tree content (`git grep`) never
sees. `tests/test_no_history_leak.py` (alongside, without the slow marker,
because it is cheap) covers only the `standards/.local` path today and only
two of these three surfaces. This module closes the third (file names) and
stretches all three over the WHOLE set of layer 4 identity patterns (D-19,
D-20).

Why every surface is a SEPARATE scan with SEPARATE parsing: the three git
commands (`git grep`, `git log --format=%B`, `git ls-tree --name-only`) have
three different output shapes (Pitfall 3 of the phase 5 research, confirmed by
a run on this machine rather than assumed) - naively joining them into one
string to search with a regex mixes contexts (a file name from one commit
could "join up" visually with the content of another). Every function below
parses the output of ITS OWN command ONLY.

The whole module stands alongside the existing single-path test
(`tests/test_no_history_leak.py`), which stays WITHOUT the slow marker because
it is cheap (two simple git calls). This module is expensive (three surfaces
times the whole set of revisions, one git call per revision for the third
surface - Z-98), so it carries the `slow` marker (D-22): skipped by default
locally (the filter in `pyproject.toml`), enabled explicitly ONLY in the CI
job `confidentiality-backstop`, which has a checkout with the full history.

The scan is a READ ONLY: it creates no git object, touches no reference and
changes nothing in the working tree (see
`test_scan_does_not_change_repository_state` below).

THE CONTENT DISCIPLINE of this module (the same contract as `Violation` in
`confidentiality_guard.py`): no function below returns or reports the matched
fragment of content. A hit carries ONLY the revision, the rule identifier and
the address proper to the surface (path plus line for tree content, the
revision alone for a commit message, the file name for file names) - never the
content of the line nor the value of the match.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# The reason for this import (rather than a copy of the patterns): D-19
# demands ONE list of identity patterns for the gate over the present and for
# the audit of the past. A second copy of those same four patterns in this file
# would drift from the first at the next change to any of them (exactly the bug
# D-19 is meant to prevent).
import confidentiality_guard as guard  # noqa: E402

pytestmark = [pytest.mark.slow, pytest.mark.integration]

# --- Module constants -------------------------------------------------------

HISTORY_SURFACES: tuple[str, str, str] = ("tree-content", "commit-message", "file-name")

RECORD_PATH: Path = REPO_ROOT / "compliance" / "history-audit.md"

# The four SHAPE rules of the identity layer - the same ones the README
# describes as working "without any local material, and therefore in CI too".
# The fifth rule (`identity-local-literal`, `IDENTITY_RULE_IDS[-1]`) works ONLY
# locally from a gitignored file (decision R-2, plan 05-03), and the history
# audit - which has to run in CI, where that file by design does not exist -
# deliberately does not cover it: `scan_text_identity` as called below NEVER
# passes `local_literals`, so the fifth rule has nothing to produce a hit
# from.
HISTORY_IDENTITY_RULE_IDS: tuple[str, ...] = guard.IDENTITY_RULE_IDS[:-1]

# A COARSE expression (extended, WITHOUT lookbehinds - assumption Z-97) for
# the sieve run through `git grep --extended-regexp`. The reason for a coarse
# sieve: the precise patterns of the identity layer (`PRIVATE_IPV4_PATTERN`)
# carry negative lookbehinds, which demand of git a regex engine compatible
# with the extended library (PCRE) - its availability depends on how git was
# built and is not a property this gate can count on. A coarse sieve (without
# lookbehinds, and therefore working on EVERY build of git) plus precise
# matching in Python over every coarsely matched line gives the same result
# without that dependency. Excess coarse hits (say "ap" inside another word
# next to a digit) are expected and harmless - it is the precise pattern in
# Python that sifts them out.
COARSE_SIEVE_PATTERN = (
    r"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3}"
    r"|[0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}"
    r"|(plc|rtu|hmi|ied|mtu|dcs|scada|ews|ows|vfd|ipc|rbc|leu|sw|fw|ap)[_-][0-9]"
    r"|railguard)"
)

# The remediation contract (D-24), stretched from ONE path
# (`standards/.local`, `tests/test_no_history_leak.py::REMEDIATION_MESSAGE`) to
# ALL the identity patterns: a hit in the history is a bar on a public push,
# and the route to remediation is rewriting the history, never another commit.
# If a public push has already happened, rewriting the history does not undo
# the fact that the content may have been scraped or mirrored. The same wording
# stands in the README and (since task 2) in the audit record.
REMEDIATION_MESSAGE = (
    "A hit of an identity layer pattern in the repository history (tree "
    "content, a commit message or a file name). This is NOT a situation to be "
    "fixed by another commit - the content is already in the history. "
    "Rewriting the history with `git filter-repo` is required BEFORE any "
    "public push. If a public push has already happened, rewriting the "
    "history does not undo the fact that the content may have been scraped "
    "or mirrored."
)

_COMMIT_RECORD_SEP = "\x00"
_COMMIT_FIELD_SEP = "\x1f"


# --- Git calls --------------------------------------------------------------


def _run_git(args: list[str]) -> str:
    """A git call requiring a ZERO exit code - the same subprocess idiom as
    `tests/test_no_history_leak.py::_run_git`, with one deliberate widening: an
    explicit `encoding="utf-8"` (with `errors="replace"` for an unforeseen
    byte), because unlike that test (ASCII paths) this module reads tree
    content and commit messages, which carry characters outside ASCII - relying
    on the default encoding of a given machine would break pattern matching on
    Windows.
    """
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return result.stdout


def _run_git_grep(args: list[str]) -> str:
    """Like `_run_git`, but for `git grep`: exit code 1 (no hits) is NOT an
    error - it is a valid result, meaning "the coarse sieve found nothing".
    Every OTHER non-zero code (a bad argument, a corrupted tree) ends the test
    as a failure carrying the error output, never as a silent skip.
    """
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in (0, 1):
        raise AssertionError(
            f"git {' '.join(args)} exited with code {result.returncode}: "
            f"{result.stderr}"
        )
    return result.stdout


def _all_revisions() -> list[str]:
    """The list of revisions reachable from ALL references (`git rev-list
    --all`). An empty list is an ERROR state (a history without a single commit
    has nothing to audit), not a green run - hence the `raise` rather than a
    silent `return []`.
    """
    output = _run_git(["rev-list", "--all"])
    revisions = [line.strip() for line in output.splitlines() if line.strip()]
    if not revisions:
        raise AssertionError(
            "git rev-list --all returned an empty list of revisions - the "
            "history audit has nothing to scan; that is an error state, not a "
            "success."
        )
    return revisions


def _commit_object_exists(sha: str) -> bool:
    """Checks whether `sha` points at an EXISTING commit object. The same
    check the audit record gate (task 2, `check_history_audit_gate.py`) applies
    to the `head_sha` field of the recorded audit - extracted here as a
    standalone unit of logic and tested below over an example known in advance
    (the present HEAD), before the audit record (which this function is meant
    to verify eventually) even begins to exist (it comes into being in
    task 2).
    """
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    return result.returncode == 0


# --- Surface one: tree content ----------------------------------------------


def _tree_content_hits() -> list[tuple[str, str, int, str]]:
    """Surface one: the tree content of every revision.

    One `git grep` call over ALL revisions at once, with the COARSE expression
    (`COARSE_SIEVE_PATTERN`). `-I` forces binary files to be treated as binary -
    their content never reaches the output (so the tree content audit, like the
    gate script itself, does not cover binary files - the same already known
    boundary the README names outright for the gate over the present).

    Every coarsely matched line then goes through the precise identity layer
    (`scan_text_identity`) - the coarse sieve only NARROWS the number of lines
    to check, it is never a verdict in itself. The returned tuple carries the
    revision, the path and the line number FROM GIT'S OUTPUT (not from the
    internal counting of `scan_text_identity`, which for a single line would
    always return 1) - that is the hit address proper to this surface.
    """
    revisions = _all_revisions()
    output = _run_git_grep(
        [
            "grep",
            "-n",
            "-I",
            "--extended-regexp",
            "--ignore-case",
            "-e",
            COARSE_SIEVE_PATTERN,
            *revisions,
        ]
    )

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)
    path_exceptions = guard._identity_path_exceptions(allow_lines)

    hits: list[tuple[str, str, int, str]] = []
    for raw_line in output.splitlines():
        if not raw_line:
            continue
        revision, path, line_no_str, content = raw_line.split(":", 3)
        for violation in guard.scan_text_identity(
            content, path, declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            if guard._identity_rule_is_suppressed(path, violation.rule_id, path_exceptions):
                continue
            hits.append((revision, path, int(line_no_str), violation.rule_id))
    return hits


# --- Surface two: commit messages -------------------------------------------


def _commit_message_hits() -> list[tuple[str, str]]:
    """Surface two: the commit messages of every revision.

    One `git log --all` call, in a format where EVERY record (commit) is
    delimited by a zero byte (`\\x00`), and WITHIN a record the hash and the
    message body are separated by the unit separator character (`\\x1f`, the
    ASCII Unit Separator). The shape was CONFIRMED by a run on this machine
    (not assumed): every record but the first carries a leading newline (git
    appends one after each format entry), hence the `record.lstrip("\\n")`
    before splitting into the hash and the body.

    It does NOT apply the path exceptions (`identity-path:...`) (assumption
    Z-99): a commit message has no path, so there is nothing for them to match
    against - a commit message therefore carries a STRICTER discipline than a
    file under the planning directory, and that is right, because a message
    cannot be corrected without rewriting the history. It does apply the
    address value declarations (`identity-value:...`), because those concern
    VALUES rather than paths.
    """
    # NOTE: `%x1f` and `%x00` below are the LITERAL text of the argument (git
    # format directives, each inserting one byte into the OUTPUT) - that is NOT
    # the same as putting a real zero byte INTO THE ARGUMENT ITSELF
    # (`_COMMIT_RECORD_SEP` below serves to parse the OUTPUT, never to build an
    # argument). Confusing the two ends on Windows in a
    # `ValueError: embedded null character` from `_winapi.CreateProcess`,
    # because an argument carrying a real zero byte cannot be passed as a
    # C string.
    output = _run_git(["log", "--all", "--format=%H%x1f%B%x00"])

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)

    hits: set[tuple[str, str]] = set()
    for record in output.split(_COMMIT_RECORD_SEP):
        cleaned = record.lstrip("\n")
        if not cleaned.strip():
            continue
        revision, separator, message = cleaned.partition(_COMMIT_FIELD_SEP)
        if not separator:
            continue
        for violation in guard.scan_text_identity(
            message, "<commit-message>", declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            hits.add((revision, violation.rule_id))
    return sorted(hits)


# --- Surface three: file names ----------------------------------------------


def _file_name_hits() -> list[tuple[str, str, str]]:
    """Surface three: the file names of the tree of EVERY revision.

    One `git ls-tree -r --name-only -z` call PER REVISION (assumption Z-98):
    the change history (`git log --name-only`) skips merge commits by default
    and needs an explicit flag for their file lists to be visible - the union
    of names over the TREES is complete regardless of that. The cost (some two
    hundred git calls) is acceptable ONLY inside a test carrying the slow
    marker, and that is exactly the cost that marker exists for.

    The names are gathered into a UNION (across all revisions, every name once)
    BEFORE the precise matching - the same file survives dozens of commits
    unchanged, so checking it again at every revision would be wasted work. For
    every unique name with a hit, the FIRST revision that name appeared in is
    remembered (the order of `_all_revisions()`) - the hit address proper to
    this surface is the file name itself, not its content.
    """
    revisions = _all_revisions()

    name_first_revision: dict[str, str] = {}
    for revision in revisions:
        output = _run_git(["ls-tree", "-r", "--name-only", "-z", revision])
        for raw_name in output.split("\x00"):
            if not raw_name:
                continue
            name_first_revision.setdefault(raw_name, revision)

    allow_lines = guard._load_allow_patterns(REPO_ROOT / guard.DEFAULT_ALLOW_FILE)
    declared_values = guard._identity_declared_values(allow_lines)
    path_exceptions = guard._identity_path_exceptions(allow_lines)

    hits: list[tuple[str, str, str]] = []
    for raw_name, revision in name_first_revision.items():
        for violation in guard.scan_text_identity(
            raw_name, raw_name, declared_values=declared_values
        ):
            if violation.rule_id not in HISTORY_IDENTITY_RULE_IDS:
                continue
            if guard._identity_rule_is_suppressed(raw_name, violation.rule_id, path_exceptions):
                continue
            hits.append((revision, raw_name, violation.rule_id))
    return hits


# --- Failure messages: revision + address + rule, NEVER content ------------


def _format_tree_content_message(hits: list[tuple[str, str, int, str]]) -> str:
    lines = [f"Surface '{HISTORY_SURFACES[0]}': {len(hits)} hits outside the exceptions."]
    for revision, path, line_no, rule_id in hits[:20]:
        lines.append(f"  {revision} {path}:{line_no} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


def _format_commit_message_message(hits: list[tuple[str, str]]) -> str:
    lines = [f"Surface '{HISTORY_SURFACES[1]}': {len(hits)} hits outside the exceptions."]
    for revision, rule_id in hits[:20]:
        lines.append(f"  {revision} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


def _format_file_name_message(hits: list[tuple[str, str, str]]) -> str:
    lines = [f"Surface '{HISTORY_SURFACES[2]}': {len(hits)} hits outside the exceptions."]
    for revision, name, rule_id in hits[:20]:
        lines.append(f"  {revision} {name} [{rule_id}]")
    lines.append(REMEDIATION_MESSAGE)
    return "\n".join(lines)


# --- Tests: the module contract --------------------------------------------


def test_module_defines_three_distinct_surfaces():
    assert len(HISTORY_SURFACES) == 3
    assert len(set(HISTORY_SURFACES)) == 3


def test_remediation_message_names_filter_repo():
    assert "filter-repo" in REMEDIATION_MESSAGE


def test_history_identity_rules_exclude_the_local_only_fifth_rule():
    """HISTORY_IDENTITY_RULE_IDS covers the four SHAPE rules ONLY - the fifth
    (identity-local-literal) works ONLY locally, and the audit, which has to
    run in CI, has nothing to check it against (no local file)."""
    assert guard.RULE_IDENTITY_LOCAL_LITERAL not in HISTORY_IDENTITY_RULE_IDS
    assert len(HISTORY_IDENTITY_RULE_IDS) == 4


def test_all_revisions_covers_every_reachable_revision():
    """The scan is meant to see the WHOLE history, not only the current branch.

    The comparison goes against an independent git measurement rather than
    against a fixed threshold: a threshold matched to the momentary number of
    commits ages at every rewrite of the history, and then it is the test that
    turns red rather than the gate. This assertion catches what actually
    matters - that `_all_revisions()` returned neither HEAD alone nor an empty
    list.
    """
    expected = subprocess.run(
        ["git", "rev-list", "--all", "--count"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    revisions = _all_revisions()
    assert len(revisions) == int(expected)
    assert len(revisions) > 1


def test_each_surface_is_a_separate_function_with_separate_parsing():
    """A check OVER THE SOURCE of the module - the patterns are joined from two
    parts so that this check does not catch its OWN source (the lines below) as
    a third occurrence, exactly as
    `test_readme_claims.py::test_module_source_contains_no_file_write_calls`
    does."""
    import inspect

    source = inspect.getsource(sys.modules[__name__])
    def_kw = "def" + " "
    assert source.count(def_kw + "_tree_content_hits") == 1
    assert source.count(def_kw + "_commit_message_hits") == 1
    assert source.count(def_kw + "_file_name_hits") == 1


# --- Tests: the sha to commit object binding (the record binding test) -----


def test_current_head_is_a_reachable_commit_object():
    head = _run_git(["rev-parse", "HEAD"]).strip()
    assert _commit_object_exists(head)


def test_zero_sha_is_not_a_reachable_commit_object():
    assert not _commit_object_exists("0" * 40)


# --- Tests: three surfaces, zero hits outside the exceptions ---------------


def test_tree_content_surface_has_zero_hits_outside_exceptions():
    hits = _tree_content_hits()
    assert hits == [], _format_tree_content_message(hits)


def test_commit_message_surface_has_zero_hits_outside_exceptions():
    hits = _commit_message_hits()
    assert hits == [], _format_commit_message_message(hits)


def test_file_name_surface_has_zero_hits_outside_exceptions():
    hits = _file_name_hits()
    assert hits == [], _format_file_name_message(hits)


# --- Test: the scan changes no repository state (the scan is a read only) --


def _repo_state() -> tuple[str, str]:
    head = _run_git(["rev-parse", "HEAD"]).strip()
    status = _run_git(["status", "--porcelain"])
    return head, status


def test_scan_does_not_change_repository_state():
    """The scan is a read only: the state of HEAD and of the working tree
    before the three scans and after them are identical. The test does NOT
    require the HEAD hash recorded in the audit record (task 2) to equal the
    PRESENT HEAD - an interrupted run is NOT a pass (the verdict binds only to
    the hash recorded in the record), while equality with the present HEAD is
    demanded only by the pre-publication gate of task 2 (the --require-current
    flag, assumption Z-100)."""
    before = _repo_state()
    _tree_content_hits()
    _commit_message_hits()
    _file_name_hits()
    after = _repo_state()
    assert before == after
