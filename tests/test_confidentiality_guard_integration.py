"""Integration test FOUND-03: a real `git commit` in a temporary repository.

It reproduces the actual order of FOUND-03/Pitfall 1 in 01-RESEARCH.md:
`git init`, copying the gate mechanism, a first commit WITHOUT the hook (the
starting point), an assertion that the hook is not there yet, installing the
hook, and finally the three commit cases described in the plan's `<behavior>`.

Two environment discoveries force this test to do more than the "bare"
`git init` + `pre_commit install` described in PLAN.md, and both are
documented so that a future reader does not discover them a second time by
trial and error:

1. `pre-commit`'s `Store()` creates its cache directory under
   `PRE_COMMIT_HOME` or `~/.cache/pre-commit` unconditionally, on EVERY call
   (not only on `install`). The test uses a directory in `tmp_path` as
   `PRE_COMMIT_HOME` in order to be hermetic - not to depend on the state of
   the `~/.cache` of the machine in use (on the author's machine that
   directory carries damaged ACLs, see `01-01-SUMMARY.md`, but that is an
   ADDITIONAL reason, not the only one - every integration test should have
   its own one-off cache, regardless of the state of the real `~/.cache`).
2. `pre-commit install` refuses to run when `core.hooksPath` is set in ANY
   scope (local OR global) - and a fresh `git init` in a temporary directory
   INHERITS the developer's global `core.hooksPath` if they have one (a
   typical security or team practice, not one machine's quirk). The test
   overrides that for the duration of THE INSTALLATION ITSELF through
   `GIT_CONFIG_GLOBAL` pointing at an empty file (it writes nothing to the
   developer's real global config), and after the installation it pins
   `core.hooksPath` LOCALLY in the temporary repository to `.git/hooks`, so
   that the installed hook really is called on the following commits in that
   same directory. The same mechanism (and the same reason) now sits in
   `scripts/bootstrap.ps1`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]

FILES_TO_COPY = [
    "scripts/confidentiality_guard.py",
    ".pre-commit-config.yaml",
    ".confidentiality-allow",
    ".gitignore",
]

# An invented sentence of normative clause shape - never a real quote of a
# standard (Pitfall 6 in 01-RESEARCH.md). This file is listed in
# .confidentiality-allow, but it copies that same fragment into the TEMPORARY
# repository, where .confidentiality-allow does not name this file - so the
# fragment is caught by the structural layer exactly as it would catch a real
# violation.
FORBIDDEN_SENTENCE = (
    "3.4.2 The system shall enforce authentication for all write operations "
    "performed against any field-side controller in the demonstration zone."
)

UNIQUE_FRAGMENT_OF_FORBIDDEN_SENTENCE = (
    "authentication for all write operations performed against"
)

# The proper name of the project fenced off by the confidentiality boundary
# (D-23). Assembled from three parts, never written as a single literal - this
# file is tracked by git and covered by the layer 3 regression.
_PROJECT_NAME_JOINED = "Rail" + "Guard" + "Sentinel"


def _run_git(args: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


def _build_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    # Hermetyczny cache pre-commit - patrz punkt 1 w docstringu modulu.
    env["PRE_COMMIT_HOME"] = str(tmp_path / "pre-commit-cache")
    return env


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    env = _build_env(tmp_path)

    init = _run_git(["init", "--initial-branch=main"], cwd=repo_dir, env=env)
    assert init.returncode == 0, init.stderr

    for key, value in (
        ("user.name", "Wayside Test"),
        ("user.email", "wayside-test@example.invalid"),
        ("commit.gpgsign", "false"),
    ):
        cfg = _run_git(["config", "--local", key, value], cwd=repo_dir, env=env)
        assert cfg.returncode == 0, cfg.stderr

    for rel_path in FILES_TO_COPY:
        source = REPO_ROOT / rel_path
        destination = repo_dir / rel_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    add = _run_git(["add", *FILES_TO_COPY], cwd=repo_dir, env=env)
    assert add.returncode == 0, add.stderr

    # The starting point WITHOUT the hook - before it is installed, nothing
    # calls it.
    first_commit = _run_git(
        ["commit", "-m", "starting point without the hook"],
        cwd=repo_dir,
        env=env,
    )
    assert first_commit.returncode == 0, first_commit.stderr

    return repo_dir


def test_hook_file_absent_before_install(temp_repo: Path):
    assert not (temp_repo / ".git" / "hooks" / "pre-commit").exists()


def test_install_hook_creates_hook_file(temp_repo: Path, tmp_path: Path):
    env = _build_env(tmp_path)

    # A `core.hooksPath` inherited from the developer's global config (if
    # there is one) makes `pre-commit install` refuse to run - see point 2 in
    # the module docstring. The override works ONLY for the duration of this
    # one command, by substituting the file `GIT_CONFIG_GLOBAL` points at -
    # nothing is written to the developer's real global config.
    empty_global_config = tmp_path / "empty-gitconfig-for-install"
    empty_global_config.write_text("", encoding="utf-8")
    install_env = dict(env)
    install_env["GIT_CONFIG_GLOBAL"] = str(empty_global_config)

    install = subprocess.run(
        [sys.executable, "-m", "pre_commit", "install"],
        cwd=temp_repo,
        env=install_env,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr

    hook_path = temp_repo / ".git" / "hooks" / "pre-commit"
    assert hook_path.exists()

    # Without this pin the installed hook would never be called on a real
    # `git commit` on a machine carrying its own global `core.hooksPath` - git
    # would look for the hook under THAT path, not under `.git/hooks`. The pin
    # is local to this temporary repository (never global).
    pin = _run_git(["config", "--local", "core.hooksPath", ".git/hooks"], cwd=temp_repo, env=env)
    assert pin.returncode == 0, pin.stderr


def _install_hook(temp_repo: Path, tmp_path: Path) -> None:
    """The same procedure as in `test_install_hook_creates_hook_file`, for
    reuse in the commit tests, which need a working hook as a precondition."""
    env = _build_env(tmp_path)
    empty_global_config = tmp_path / "empty-gitconfig-for-install"
    empty_global_config.write_text("", encoding="utf-8")
    install_env = dict(env)
    install_env["GIT_CONFIG_GLOBAL"] = str(empty_global_config)

    install = subprocess.run(
        [sys.executable, "-m", "pre_commit", "install"],
        cwd=temp_repo,
        env=install_env,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr

    pin = _run_git(["config", "--local", "core.hooksPath", ".git/hooks"], cwd=temp_repo, env=env)
    assert pin.returncode == 0, pin.stderr


def test_commit_with_forbidden_normative_sentence_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    forbidden_file = temp_repo / "note.txt"
    forbidden_file.write_text(FORBIDDEN_SENTENCE, encoding="utf-8")

    add = _run_git(["add", "note.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must not go through"], cwd=temp_repo, env=env
    )

    # Git returns different codes for different hook failure modes - the ONLY
    # thing that matters is that the commit was not accepted.
    assert commit.returncode != 0
    assert "note.txt" in (commit.stdout + commit.stderr)
    assert UNIQUE_FRAGMENT_OF_FORBIDDEN_SENTENCE not in (commit.stdout + commit.stderr)

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must not go through" not in log.stdout


def test_commit_with_standards_local_file_added_with_force_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    local_corpus_dir = temp_repo / "standards" / ".local"
    local_corpus_dir.mkdir(parents=True)
    forbidden_path_file = local_corpus_dir / "standard.bin"
    forbidden_path_file.write_bytes(b"\x00\x01\x02cokolwiek")

    add = _run_git(
        ["add", "-f", "standards/.local/standard.bin"], cwd=temp_repo, env=env
    )
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must not go through either"], cwd=temp_repo, env=env
    )

    assert commit.returncode != 0
    assert "path-local-corpus" in (commit.stdout + commit.stderr)

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must not go through either" not in log.stdout


def test_commit_with_project_name_outside_exempted_path_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    forbidden_file = temp_repo / "note-name.txt"
    forbidden_file.write_text(_PROJECT_NAME_JOINED, encoding="utf-8")

    add = _run_git(["add", "note-name.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must not go through - proper name"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode != 0
    output = commit.stdout + commit.stderr
    assert "identity-project-name" in output
    assert _PROJECT_NAME_JOINED not in output

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must not go through - proper name" not in log.stdout


def test_commit_with_project_name_under_exempted_path_is_accepted(
    temp_repo: Path, tmp_path: Path
):
    # The exempted path checked here is the exception list file itself: a file
    # that declares an exception for the proper name rule has to be allowed to
    # name what it is lifting, in the comment that justifies it. That is a real
    # use of the exception rather than an artificial one - every new entry on
    # the list comes with such a comment.
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    exempted_file = temp_repo / ".confidentiality-allow"
    with exempted_file.open("a", encoding="utf-8") as handle:
        handle.write(f"\n# Justification naming the name: {_PROJECT_NAME_JOINED}\n")

    add = _run_git(["add", ".confidentiality-allow"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must go through - exempted path"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode == 0, commit.stdout + commit.stderr

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must go through - exempted path" in log.stdout


def test_commit_with_ordinary_text_file_is_accepted(temp_repo: Path, tmp_path: Path):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    benign_file = temp_repo / "note-plain.txt"
    benign_file.write_text(
        "This is an ordinary note with no normative clause shape.\n",
        encoding="utf-8",
    )

    add = _run_git(["add", "note-plain.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must go through"], cwd=temp_repo, env=env
    )

    assert commit.returncode == 0, commit.stdout + commit.stderr

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must go through" in log.stdout


def test_commit_with_local_literal_file_present_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    """The literal rule (identity-local-literal) on a real commit.

    `.confidentiality-identity.local` is neither in `FILES_TO_COPY` nor
    committed - it is written straight to the disk of the temporary
    repository, exactly as a developer writes it on their own machine. The
    hook calls the gate without any `--identity-local-file` argument
    (`.pre-commit-config.yaml` does not pass one), so the gate uses the
    default path relative to the hook's working directory - the root directory
    of the temporary repository.
    """
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    local_literal_file = temp_repo / ".confidentiality-identity.local"
    local_literal_file.write_text(
        "# a literal invented for this test\nMUT-PROBE-DEVICE-77\n",
        encoding="utf-8",
    )

    carrying_file = temp_repo / "note-literal.txt"
    carrying_file.write_text("a line with MUT-PROBE-DEVICE-77 in the middle", encoding="utf-8")

    add = _run_git(["add", "note-literal.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "this must not go through - local literal"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode != 0
    output = commit.stdout + commit.stderr
    assert "identity-local-literal" in output
    assert "MUT-PROBE-DEVICE-77" not in output

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "this must not go through - local literal" not in log.stdout
