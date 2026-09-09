"""Test integracyjny FOUND-03: prawdziwy `git commit` w repozytorium tymczasowym.

Odtwarza faktyczna kolejnosc z FOUND-03/Pitfall 1 w 01-RESEARCH.md: `git init`,
skopiowanie mechanizmu bramki, pierwszy commit BEZ haka (punkt startowy),
asercja, ze haka jeszcze nie ma, instalacja haka, i na koniec trzy przypadki
commitu opisane w `<behavior>` planu.

Dwa odkrycia srodowiskowe zmuszaja ten test do wiecej niz "goleg" `git init` +
`pre_commit install` opisanego w PLAN.md, i oba sa udokumentowane, zeby
przyszly czytelnik nie odkrywal ich po raz drugi metoda prob i bledow:

1. `pre-commit`'s `Store()` tworzy katalog cache'u pod `PRE_COMMIT_HOME` albo
   `~/.cache/pre-commit` bezwarunkowo, przy KAZDYM wywolaniu (nie tylko przy
   `install`). Test uzywa katalogu w `tmp_path` jako `PRE_COMMIT_HOME`, zeby
   byc hermetyczny - nie zalezec od stanu `~/.cache` uzywajacego maszyny (na
   maszynie autora ten katalog ma uszkodzone ACL, patrz `01-01-SUMMARY.md`,
   ale to jest powod DODATKOWY, nie jedyny - kazdy test integracyjny powinien
   miec wlasny, jednorazowy cache, niezaleznie od stanu realnego `~/.cache`).
2. `pre-commit install` odmawia dzialania, gdy `core.hooksPath` jest
   ustawione w JAKIMKOLWIEK zakresie (lokalnym LUB globalnym) - a swiezy
   `git init` w katalogu tymczasowym DZIEDZICZY globalny `core.hooksPath`
   dewelopera, jesli ten go ma (typowa praktyka bezpieczenstwa/zespolowa,
   nie tylko jedna maszyna). Test nadpisuje to na czas SAMEJ instalacji przez
   `GIT_CONFIG_GLOBAL` wskazujace na pusty plik (nic nie zapisuje do
   prawdziwego globalnego configu dewelopera), a po instalacji przypina
   `core.hooksPath` LOKALNIE w repozytorium tymczasowym do `.git/hooks`, zeby
   zainstalowany hak faktycznie byl wywolywany przy kolejnych commitach w tym
   samym katalogu. Ten sam mechanizm (i ten sam powod) jest teraz w
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

# Wymyslone zdanie o ksztalcie klauzuli normatywnej - nigdy prawdziwy cytat
# normy (Pitfall 6 w 01-RESEARCH.md). Ten plik jest wpisany do
# .confidentiality-allow, ale on sam kopiuje ten sam fragment do repozytorium
# TYMCZASOWEGO, gdzie .confidentiality-allow nie wymienia tego pliku po
# nazwie - wiec fragment zostaje zlapany przez warstwe strukturalna tak, jak
# zlapalby prawdziwe naruszenie.
FORBIDDEN_SENTENCE = (
    "3.4.2 The system shall enforce authentication for all write operations "
    "performed against any field-side controller in the demonstration zone."
)

UNIQUE_FRAGMENT_OF_FORBIDDEN_SENTENCE = (
    "authentication for all write operations performed against"
)

# Nazwa wlasna projektu odgrodzonego granica poufnosci (D-23). Sklejona z
# trzech czesci, nigdy nie zapisana jako jeden literal - ten plik jest
# sledzony przez gita i objety regresja warstwy 3.
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

    # Punkt startowy BEZ haka - zanim haka zainstalowano, nic go nie wywoluje.
    first_commit = _run_git(
        ["commit", "-m", "punkt startowy bez haka"],
        cwd=repo_dir,
        env=env,
    )
    assert first_commit.returncode == 0, first_commit.stderr

    return repo_dir


def test_hook_file_absent_before_install(temp_repo: Path):
    assert not (temp_repo / ".git" / "hooks" / "pre-commit").exists()


def test_install_hook_creates_hook_file(temp_repo: Path, tmp_path: Path):
    env = _build_env(tmp_path)

    # `core.hooksPath` odziedziczony po dewelopera globalnym configu (jesli
    # istnieje) sprawia, ze `pre-commit install` odmawia dzialania - patrz
    # punkt 2 w docstringu modulu. Nadpisanie dziala WYLACZNIE na czas tej
    # jednej komendy, przez podmiane pliku, na ktory wskazuje
    # `GIT_CONFIG_GLOBAL` - nic nie jest zapisywane do prawdziwego globalnego
    # configu dewelopera.
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

    # Bez tego przypiecia zainstalowany hak nigdy nie zostalby wywolany przy
    # prawdziwym `git commit` na maszynie z wlasnym globalnym
    # `core.hooksPath` - git szukalby haka pod TAMTA sciezka, nie pod
    # `.git/hooks`. Przypiecie jest lokalne dla tego repozytorium
    # tymczasowego (nigdy globalne).
    pin = _run_git(["config", "--local", "core.hooksPath", ".git/hooks"], cwd=temp_repo, env=env)
    assert pin.returncode == 0, pin.stderr


def _install_hook(temp_repo: Path, tmp_path: Path) -> None:
    """Ta sama procedura co w `test_install_hook_creates_hook_file`, do reuzycia
    w testach commitu, ktore potrzebuja dzialajacego haka jako przedwarunku."""
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

    forbidden_file = temp_repo / "notatka.txt"
    forbidden_file.write_text(FORBIDDEN_SENTENCE, encoding="utf-8")

    add = _run_git(["add", "notatka.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to nie powinno przejsc"], cwd=temp_repo, env=env
    )

    # Git zwraca rozne kody dla roznych trybow niepowodzenia haka - liczy sie
    # WYLACZNIE to, ze commit nie zostal zaakceptowany.
    assert commit.returncode != 0
    assert "notatka.txt" in (commit.stdout + commit.stderr)
    assert UNIQUE_FRAGMENT_OF_FORBIDDEN_SENTENCE not in (commit.stdout + commit.stderr)

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to nie powinno przejsc" not in log.stdout


def test_commit_with_standards_local_file_added_with_force_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    local_corpus_dir = temp_repo / "standards" / ".local"
    local_corpus_dir.mkdir(parents=True)
    forbidden_path_file = local_corpus_dir / "norma.bin"
    forbidden_path_file.write_bytes(b"\x00\x01\x02cokolwiek")

    add = _run_git(
        ["add", "-f", "standards/.local/norma.bin"], cwd=temp_repo, env=env
    )
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to rowniez nie powinno przejsc"], cwd=temp_repo, env=env
    )

    assert commit.returncode != 0
    assert "path-local-corpus" in (commit.stdout + commit.stderr)

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to rowniez nie powinno przejsc" not in log.stdout


def test_commit_with_project_name_outside_exempted_path_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    forbidden_file = temp_repo / "notatka-nazwa.txt"
    forbidden_file.write_text(_PROJECT_NAME_JOINED, encoding="utf-8")

    add = _run_git(["add", "notatka-nazwa.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to nie powinno przejsc - nazwa wlasna"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode != 0
    output = commit.stdout + commit.stderr
    assert "identity-project-name" in output
    assert _PROJECT_NAME_JOINED not in output

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to nie powinno przejsc - nazwa wlasna" not in log.stdout


def test_commit_with_project_name_under_exempted_planning_path_is_accepted(
    temp_repo: Path, tmp_path: Path
):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    planning_dir = temp_repo / ".planning"
    planning_dir.mkdir()
    exempted_file = planning_dir / "notatka-nazwa.md"
    exempted_file.write_text(_PROJECT_NAME_JOINED, encoding="utf-8")

    add = _run_git(["add", ".planning/notatka-nazwa.md"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to powinno przejsc - sciezka wyjeta"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode == 0, commit.stdout + commit.stderr

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to powinno przejsc - sciezka wyjeta" in log.stdout


def test_commit_with_ordinary_text_file_is_accepted(temp_repo: Path, tmp_path: Path):
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    benign_file = temp_repo / "notatka-zwykla.txt"
    benign_file.write_text(
        "To jest zwykla notatka bez ksztaltu klauzuli normatywnej.\n",
        encoding="utf-8",
    )

    add = _run_git(["add", "notatka-zwykla.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to powinno przejsc"], cwd=temp_repo, env=env
    )

    assert commit.returncode == 0, commit.stdout + commit.stderr

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to powinno przejsc" in log.stdout


def test_commit_with_local_literal_file_present_is_rejected(
    temp_repo: Path, tmp_path: Path
):
    """Regula literalna (identity-local-literal) na prawdziwym commicie.

    `.confidentiality-identity.local` nie jest w `FILES_TO_COPY` ani
    scommitowany - jest zapisany bezposrednio na dysku repozytorium
    tymczasowego, dokladnie tak jak deweloper zapisze go na swojej maszynie.
    Hak wola bramke bez zadnego argumentu `--identity-local-file`
    (`.pre-commit-config.yaml` go nie przekazuje), wiec bramka uzywa sciezki
    domyslnej wzgledem katalogu roboczego haka - katalogu glownego
    repozytorium tymczasowego.
    """
    _install_hook(temp_repo, tmp_path)
    env = _build_env(tmp_path)

    local_literal_file = temp_repo / ".confidentiality-identity.local"
    local_literal_file.write_text(
        "# literal wymyslony na potrzeby tego testu\nMUT-PROBE-DEVICE-77\n",
        encoding="utf-8",
    )

    carrying_file = temp_repo / "notatka-literal.txt"
    carrying_file.write_text("linia z MUT-PROBE-DEVICE-77 w srodku", encoding="utf-8")

    add = _run_git(["add", "notatka-literal.txt"], cwd=temp_repo, env=env)
    assert add.returncode == 0, add.stderr

    commit = _run_git(
        ["commit", "-m", "to nie powinno przejsc - literal lokalny"],
        cwd=temp_repo,
        env=env,
    )

    assert commit.returncode != 0
    output = commit.stdout + commit.stderr
    assert "identity-local-literal" in output
    assert "MUT-PROBE-DEVICE-77" not in output

    log = _run_git(["log", "--oneline"], cwd=temp_repo, env=env)
    assert "to nie powinno przejsc - literal lokalny" not in log.stdout
