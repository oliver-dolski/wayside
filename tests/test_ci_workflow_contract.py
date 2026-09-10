"""Contract for the shape of `.github/workflows/ci.yml`, checked locally.

Without this test, a drift between what plan 01-05 promises and what the
workflow actually does only surfaces at the first push - and only if someone
reads the log. The file is parsed solely by `yaml.safe_load`, with the path
derived relative to `__file__`, so that the test behaves identically no
matter where `pytest` was started from.

`steps_of()` flattens a job's step list so that the assertions below read as
sentences about content ("step X contains Y"), not as nested indexing into
YAML dictionaries.

The `on:` key in the workflow file is DELIBERATELY quoted as `"on":` -
without that PyYAML (YAML 1.1) parses the bareword as the bool `True`, not
the string "on" (a known gotcha, checked directly at the time).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

# The five critical phase 1 modules. Adding a sixth one in a later phase is
# meant to be one change to this constant, not a hunt across the whole test file.
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
    """Returns the flat list of steps of the job `job_name`."""
    return workflow["jobs"][job_name]["steps"]


def step_commands(steps: list[dict[str, Any]]) -> list[str]:
    """Returns the `run:` content of every step that has one (skips `uses:` steps)."""
    return [step["run"] for step in steps if "run" in step]


def find_missing_critical_modules(
    collection_gate_command: str, required_modules: tuple[str, ...]
) -> list[str]:
    """Returns the subset of `required_modules` whose name does NOT appear in
    `collection_gate_command`. An empty list means: all of them are present.
    """
    return [name for name in required_modules if name not in collection_gate_command]


# --- Global shape ------------------------------------------------------------


def test_workflow_parses_as_yaml():
    workflow = load_workflow()
    assert workflow["jobs"]


def test_every_job_runs_on_windows_latest():
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        assert job["runs-on"] == "windows-latest", f"job {job_name} does not run on windows-latest"


# --- Job `test` ---------------------------------------------------------------


def test_job_test_syncs_locked_and_runs_pytest():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    assert any("uv sync --locked" in cmd for cmd in commands), "no `uv sync --locked`"
    assert any(cmd.strip() == "uv run pytest" for cmd in commands), "no `uv run pytest`"


def test_job_test_collection_gate_lists_all_critical_modules():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)
    missing = find_missing_critical_modules(collection_gate, CRITICAL_TEST_MODULES)
    assert missing == [], f"module(s) missing from the collection gate step: {missing}"


# --- Job `confidentiality-backstop` -------------------------------------------


def test_backstop_checkout_has_full_history():
    workflow = load_workflow()
    steps = steps_of(workflow, "confidentiality-backstop")
    checkout_step = next(s for s in steps if s.get("uses", "").startswith("actions/checkout"))
    assert checkout_step.get("with", {}).get("fetch-depth") == 0, (
        "the checkout of the backstop job lacks fetch-depth: 0"
    )


def test_backstop_runs_confidentiality_guard_without_corpus():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "confidentiality_guard.py" in cmd and "--no-corpus" in cmd for cmd in commands
    ), "no call of confidentiality_guard.py with the --no-corpus flag"


def test_backstop_checks_empty_history_for_local_corpus_path():
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "git log --all" in cmd and "standards/.local" in cmd for cmd in commands
    ), "no `git log --all -- standards/.local` step"


def test_backstop_runs_history_audit_scan_with_slow_marker_enabled():
    """PUB-05/D-22: the backstop job carries a step calling the module that
    scans the three surfaces of the whole history, with the `slow` marker
    explicitly enabled - without that explicit enabling the default marker
    filter (pyproject.toml) would skip the module in CI as well, and the scan
    would look green without ever executing."""
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "confidentiality-backstop"))
    assert any(
        "-m slow" in cmd and "test_history_audit" in cmd for cmd in commands
    ), "no step running the history scan with the slow marker explicitly enabled"


def test_job_test_collection_gate_does_not_list_history_audit_module():
    """Z-101: the history scan module has no business on the critical module
    list of the `test` job's collection step - once the default `slow` marker
    filter was introduced, that module no longer shows up in that collection,
    so adding it there would turn the step red immediately."""
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)
    assert "test_history_audit" not in collection_gate


# --- No step uses the local corpus as a data source --------------------------


def test_confidentiality_guard_invocations_always_use_no_corpus_flag():
    """Every call of `confidentiality_guard.py` in ci.yml carries `--no-corpus`.

    This is outright a test for the use of the local corpus as a data source:
    without that flag the step would try to read the corpus layer, which in CI
    never exists (the directory is gitignored) and cannot exist without
    defeating the purpose of the confidentiality gate - see the comment at the
    top of ci.yml.
    """
    workflow = load_workflow()
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            run_content = step.get("run", "")
            if "confidentiality_guard.py" in run_content:
                assert "--no-corpus" in run_content, (
                    f"job {job_name} calls confidentiality_guard.py without --no-corpus"
                )


def test_no_step_references_secrets_context():
    raw_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "secrets." not in raw_text, "a step references the repository secrets"


# --- Proof that the collection completeness gate works -----------------------


def test_missing_critical_module_is_detected_via_mutated_copy():
    """Proof of effectiveness: without this test the assertion about the five
    modules could be green because `find_missing_critical_modules` looks for
    something that is nowhere to be found. It removes one name from the content
    of the collection gate step (an in-memory copy, not a modification of the
    file on disk) and checks that the checking function reports the absence.
    """
    workflow = load_workflow()
    commands = step_commands(steps_of(workflow, "test"))
    collection_gate = next(cmd for cmd in commands if "collect-only" in cmd)

    removed_module = CRITICAL_TEST_MODULES[0]
    mutated_gate = collection_gate.replace(removed_module, "")

    missing = find_missing_critical_modules(mutated_gate, CRITICAL_TEST_MODULES)

    assert removed_module in missing, (
        "find_missing_critical_modules did not detect the missing module "
        f"'{removed_module}' after its removal from the in-memory copy"
    )
