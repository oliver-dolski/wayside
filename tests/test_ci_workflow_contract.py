"""Kontrakt na ksztalt `.github/workflows/ci.yml`, sprawdzany lokalnie.

Bez tego testu rozjazd miedzy tym, co plan 01-05 obiecuje, a tym, co workflow
faktycznie robi, wychodzi dopiero przy pierwszym pushu - i tylko wtedy, gdy
ktos przeczyta log. Plik jest parsowany wylacznie przez `yaml.safe_load`,
sciezka wyznaczona wzgledem `__file__`, zeby test dzialal identycznie
niezaleznie od miejsca uruchomienia `pytest`.

`steps_of()` splaszcza liste krokow joba, zeby asercje ponizej czytaly sie
jako zdania o zawartosci ("krok X zawiera Y"), nie jako zagniezdzone
indeksowanie slownikow YAML.

Klucz `on:` w pliku workflow jest CELOWO cudzyslowiony jako `"on":` - bez
tego PyYAML (YAML 1.1) parsuje ten bareword jako bool `True`, nie string
"on" (znany gotcha; sprawdzone bezposrednio w tej sesji).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

# Piatka modulow krytycznych fazy 1. Dodanie szostej w kolejnej fazie ma byc
# jedna zmiana w tej stalej, nie polowanie po calym pliku testowym.
CRITICAL_TEST_MODULES: tuple[str, ...] = (
    "test_confidentiality_guard_integration",
    "test_no_history_leak",
    "test_fixture_manifest",
    "test_no_external_dissector",
    "test_check_pub_gate",
)


def load_workflow() -> dict[str, Any]:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def steps_of(workflow: dict[str, Any], job_name: str) -> list[dict[str, Any]]:
    """Zwraca plaska liste krokow joba `job_name`."""
    return workflow["jobs"][job_name]["steps"]


def step_commands(steps: list[dict[str, Any]]) -> list[str]:
    """Zwraca tresc `run:` dla kazdego kroku, ktory ja ma (pomija kroki `uses:`)."""
    return [step["run"] for step in steps if "run" in step]


def find_missing_critical_modules(
    collection_gate_command: str, required_modules: tuple[str, ...]
) -> list[str]:
    """Zwraca podzbior `required_modules`, ktorego nazwa NIE wystepuje w
    `collection_gate_command`. Pusta lista znaczy: wszystkie obecne.
    """
    return [name for name in required_modules if name not in collection_gate_command]


# --- Ksztalt globalny --------------------------------------------------------


def test_workflow_parses_as_yaml():
    workflow = load_workflow()
    assert workflow["jobs"]


def test_every_job_runs_on_windows_latest():
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        assert job["runs-on"] == "windows-latest", f"job {job_name} nie jest na windows-latest"


# --- Job `test` ---------------------------------------------------------------


def test_job_test_syncs_locked_and_runs_pytest():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    assert any("uv sync --locked" in cmd for cmd in commands), "brak `uv sync --locked`"
    assert any(cmd.strip() == "uv run pytest" for cmd in commands), "brak `uv run pytest`"


def test_job_test_collection_gate_lists_all_critical_modules():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)
    missing = find_missing_critical_modules(collection_gate, CRITICAL_TEST_MODULES)
    assert missing == [], f"modul(y) brakujace w kroku bramki kolekcji: {missing}"


# --- Job `confidentiality-backstop` -------------------------------------------


def test_backstop_checkout_has_full_history():
    workflow = load_workflow()
    steps = steps_of(workflow, "confidentiality-backstop")
    checkout_step = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
    assert checkout_step.get("with", {}).get("fetch-depth") == 0, (
        "checkout w jobie backstopu nie ma fetch-depth: 0"
    )


def test_backstop_runs_confidentiality_guard_without_corpus():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "confidentiality_guard.py" in cmd and "--no-corpus" in cmd for cmd in commands
    ), "brak wywolania confidentiality_guard.py z flaga --no-corpus"


def test_backstop_checks_empty_history_for_local_corpus_path():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "git log --all" in cmd and "standards/.local" in cmd for cmd in commands
    ), "brak kroku `git log --all -- standards/.local`"


def test_backstop_runs_history_audit_scan_with_slow_marker_enabled():
    """PUB-05/D-22: job backstopu niesie krok wolajacy modul skanu trzech
    powierzchni calej historii z jawnym wlaczeniem znacznika `slow` - bez
    tego jawnego wlaczenia domyslny filtr znacznika (pyproject.toml)
    pomijalby ten modul takze w CI, i skan wygladalby na zielony, w ogole
    sie nie wykonujac."""
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "-m slow" in cmd and "test_history_audit" in cmd for cmd in commands
    ), "brak kroku uruchamiajacego skan historii z jawnym wlaczeniem znacznika slow"


def test_job_test_collection_gate_does_not_list_history_audit_module():
    """Z-101: modul skanu historii NIE ma prawa stac na liscie modulow
    krytycznych kroku kolekcji jobu `test` - po wprowadzeniu domyslnego
    filtra znacznika `slow` ten modul nie pojawia sie w tamtej kolekcji,
    wiec dopisanie go zaczerwienilo by krok natychmiast."""
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)
    assert "test_history_audit" not in collection_gate


# --- Zadny krok nie uzywa lokalnego korpusu jako zrodla danych ---------------


def test_confidentiality_guard_invocations_always_use_no_corpus_flag():
    """Kazde wywolanie `confidentiality_guard.py` w ci.yml niesie `--no-corpus`.

    To jest wprost test na uzycie lokalnego korpusu jako zrodla danych: bez tej
    flagi krok probowalby czytac warstwe korpusowa, ktora w CI nigdy nie
    istnieje (katalog jest gitignorowany) i nie moze istniec, nie zniweczajac
    celu bramki poufnosci - patrz komentarz na gorze ci.yml.
    """
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            run_content = step.get("run", "")
            if "confidentiality_guard.py" in run_content:
                assert "--no-corpus" in run_content, (
                    f"job {job_name} wola confidentiality_guard.py bez --no-corpus"
                )


def test_no_step_references_secrets_context():
    raw_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "secrets." not in raw_text, "krok odwoluje sie do sekretow repozytorium"


# --- Dowod skutecznosci bramki kompletnosci kolekcji --------------------------


def test_missing_critical_module_is_detected_via_mutated_copy():
    """Dowod skutecznosci: bez tego testu asercja o piatce modulow moglaby byc
    zielona dlatego, ze `find_missing_critical_modules` szuka czegos, czego
    nigdzie nie ma. Usuwa jedna nazwe z tresci kroku bramki kolekcji (kopia w
    pamieci, nie modyfikacja pliku na dysku) i sprawdza, ze funkcja
    sprawdzajaca zglasza brak.
    """
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)

    removed_module = CRITICAL_TEST_MODULES[0]
    mutated_gate = collection_gate.replace(removed_module, "")

    missing = find_missing_critical_modules(mutated_gate, CRITICAL_TEST_MODULES)

    assert removed_module in missing, (
        "find_missing_critical_modules nie wykryla brakujacego modulu "
        f"'{removed_module}' po jego usunieciu z kopii w pamieci"
    )
