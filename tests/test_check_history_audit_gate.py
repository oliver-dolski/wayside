"""Unit tests for PUB-05: the shape gate `scripts/check_history_audit_gate.py`.

This suite checks the SHAPE of the record ONLY (presence of the fields,
allowed values, whether the dates parse, the rule for the `author` field) and
the mapping of shape onto SIX distinguishable exit codes, following
`tests/test_check_pub_gate.py`. There is not one test here forcing a
particular `result` on the real repository record beyond the dependency
isolation check and the shape check - the machine verdict over the real state
of the history belongs to `tests/test_history_audit.py` (the slow marker).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_history_audit_gate as gate  # noqa: E402
import check_pub_gate  # noqa: E402


def _valid_fields(**overrides: str) -> dict[str, str]:
    fields = {
        "requirement": "PUB-05",
        "scope": "repository-history-identity-patterns",
        "audited_on": "2026-09-09",
        "head_sha": "0" * 40,
        "surfaces": ", ".join(gate.REQUIRED_SURFACES),
        "rules_checked": ", ".join(gate.REQUIRED_RULES),
        "exceptions_file": ".confidentiality-allow",
        "result": "clean",
        "author": "",
        "confirmed_on": "",  # empty on purpose: the pending state
    }
    fields.update(overrides)
    return fields


VALID_BODY = (
    "## Scope\n\nThree surfaces of the whole history.\n\n"
    "## Result\n\nNo hits outside the exceptions.\n\n"
    "## Exceptions\n\nSee .confidentiality-allow.\n\n"
    "## Remediation contract\n\ngit filter-repo before a public push.\n\n"
    "## Revision conditions\n\nA changed set of patterns or exceptions.\n"
)


def _write_record(path: Path, fields: dict[str, str], body: str) -> None:
    lines = ["---"]
    for key, value in fields.items():
        lines.append(f"{key}: {value}")
    lines.append("---")
    lines.append(body)
    path.write_text("\n".join(lines), encoding="utf-8")


# --- Module contract and dependency isolation --------------------------------


def test_module_defines_required_symbols():
    assert callable(gate.validate_record)
    assert callable(gate.main)
    assert (
        gate.EXIT_OK,
        gate.EXIT_REQUIRE_CLEAN_FAILED,
        gate.EXIT_MISSING_FILE,
        gate.EXIT_INVALID_SHAPE,
        gate.EXIT_PENDING,
        gate.EXIT_STALE_HEAD,
    ) == (0, 1, 3, 4, 5, 6)
    assert len(gate.REQUIRED_KEYS) >= 10
    assert len(gate.REQUIRED_SURFACES) == 3
    assert gate.VALID_RESULTS == {"clean", "hits-outside-exceptions", "pending"}


def test_module_imports_only_standard_library_and_sibling_gate():
    """Dependency isolation over the syntax tree, following
    `tests/test_check_pub_gate.py::test_module_imports_only_standard_library` -
    this module additionally allows `check_pub_gate` (the sibling gate) ONLY,
    without which import it would be copying that gate's check of the `author`
    field instead of using it."""
    import ast

    source = (SCRIPTS_DIR / "check_history_audit_gate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    stdlib_names = set(sys.stdlib_module_names) | {"check_pub_gate"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                assert top_level in stdlib_names, f"External import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top_level = node.module.split(".")[0]
            assert top_level in stdlib_names, f"External import: {node.module}"


def test_reviewer_check_is_the_same_object_as_sibling_gate():
    """The check of the `author` field is THE SAME object the record gate of
    the publication gate uses - not a copy behaving identically."""
    assert gate.check_pub_gate.reviewer_is_invalid is check_pub_gate.reviewer_is_invalid


# --- main(): the file is absent -----------------------------------------------


def test_main_missing_file_exits_3(tmp_path):
    missing = tmp_path / "no-such-file.md"
    exit_code = gate.main(["--record", str(missing)])
    assert exit_code == 3


# --- validate_record: missing frontmatter separators (via load_record) -------


def test_missing_opening_separator_exits_4(tmp_path):
    record = tmp_path / "record.md"
    record.write_text("no opening separator\n---\nbody\n", encoding="utf-8")
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


def test_missing_closing_separator_exits_4(tmp_path):
    record = tmp_path / "record.md"
    record.write_text("---\nrequirement: PUB-05\nscope: x\n", encoding="utf-8")
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


# --- validate_record: incomplete fields --------------------------------------


def test_missing_required_key_exits_4_shape_error():
    fields = _valid_fields()
    del fields["exceptions_file"]
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_missing_required_key_via_main_exits_4(tmp_path):
    fields = _valid_fields()
    del fields["exceptions_file"]
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


# --- validate_record: result outside the allowed set -------------------------


def test_result_outside_valid_set_is_a_shape_error():
    fields = _valid_fields(result="maybe")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_result_outside_valid_set_via_main_exits_4(tmp_path):
    fields = _valid_fields(result="maybe", author="Jan Kowalski", confirmed_on="2026-09-09")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


# --- validate_record: the list of surfaces and rules -------------------------


def test_incomplete_surfaces_list_is_a_shape_error():
    fields = _valid_fields(surfaces="tree-content, commit-message")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_incomplete_rules_list_is_a_shape_error():
    fields = _valid_fields(rules_checked="identity-private-ipv4")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


# --- validate_record: unparseable date ---------------------------------------


def test_unparseable_audited_on_is_a_shape_error():
    fields = _valid_fields(audited_on="yesterday")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_unparseable_confirmed_on_is_a_shape_error_when_non_empty():
    fields = _valid_fields(author="Jane Doe", confirmed_on="yesterday")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


# --- validate_record: the author field ---------------------------------------


def test_empty_author_is_not_a_shape_error():
    fields = _valid_fields(author="", confirmed_on="")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors == []


def test_agent_name_author_is_a_shape_error():
    fields = _valid_fields(author="assistant", confirmed_on="2026-09-09")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_agent_name_author_via_main_exits_4(tmp_path):
    fields = _valid_fields(author="assistant", confirmed_on="2026-09-09")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


# --- main(): the pending state -----------------------------------------------


def test_empty_author_via_main_exits_5_pending(tmp_path):
    fields = _valid_fields(author="", confirmed_on="")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 5


def test_empty_confirmed_on_via_main_exits_5_pending(tmp_path):
    fields = _valid_fields(author="Jan Kowalski", confirmed_on="")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 5


# --- main(): properly resolved, the --require-clean flag ---------------------


def test_clean_signed_record_exits_0(tmp_path):
    fields = _valid_fields(result="clean", author="Jan Kowalski", confirmed_on="2026-09-09")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 0


def test_hits_outside_exceptions_without_require_clean_exits_0(tmp_path):
    fields = _valid_fields(
        result="hits-outside-exceptions", author="Jan Kowalski", confirmed_on="2026-09-09"
    )
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 0


def test_hits_outside_exceptions_with_require_clean_exits_1(tmp_path):
    fields = _valid_fields(
        result="hits-outside-exceptions", author="Jan Kowalski", confirmed_on="2026-09-09"
    )
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record), "--require-clean"])
    assert exit_code == 1


# --- main(): the --require-current flag, a stale record ----------------------


def test_stale_head_sha_without_require_current_exits_0(tmp_path):
    fields = _valid_fields(
        head_sha="0" * 40, result="clean", author="Jan Kowalski", confirmed_on="2026-09-09"
    )
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 0


def test_stale_head_sha_with_require_current_exits_6(tmp_path):
    fields = _valid_fields(
        head_sha="0" * 40, result="clean", author="Jan Kowalski", confirmed_on="2026-09-09"
    )
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record), "--require-current"])
    assert exit_code == 6


def test_current_head_sha_with_require_current_exits_0_with_both_flags(tmp_path):
    current_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    fields = _valid_fields(
        head_sha=current_head, result="clean", author="Jan Kowalski", confirmed_on="2026-09-09"
    )
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record), "--require-clean", "--require-current"])
    assert exit_code == 0


# --- Body discipline: the record never carries a fragment of history ---------


def test_failure_messages_never_carry_matched_content(tmp_path, capsys):
    """No failure message carries a fragment of the history content nor the
    name of a file with a hit - the record gate sees only the frontmatter
    fields, never the hits of a scan, so there is nothing for such a fragment
    to leak from; this test documents that property outright."""
    fields = _valid_fields(rules_checked="identity-private-ipv4")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4
    captured = capsys.readouterr()
    assert "SECRET-HIT-DO-NOT-REPEAT" not in captured.err


# --- The repository record: shape only, never a forced result ----------------


def test_repository_record_has_valid_shape_or_is_pending():
    """The record in the repository is meant to be well formed at all times.
    The pending state (code 5, the human fields empty) and the resolved state
    (code 0) are both acceptable - whether the signature has been given is not
    a property this test suite forces."""
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "check_history_audit_gate.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 5), (
        result.returncode,
        result.stdout,
        result.stderr,
    )
