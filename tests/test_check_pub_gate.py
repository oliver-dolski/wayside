"""Unit tests for PUB-01: the shape gate `scripts/check_pub_gate.py`.

This suite checks the SHAPE of the record ONLY (presence of the fields,
whether the date parses, absence of a block quote, the rules for the
`reviewer` field) and the mapping of shape onto exit codes. There is not one
test here forcing a particular `verdict` value (`go` or `no-go`) on the real
repository record - that is a human decision, not a property checked by a
test suite (see `test_repository_record_has_valid_shape` below).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_pub_gate as gate  # noqa: E402

VALID_BODY = (
    "## Scope of the review\n\nIntellectual property and competing activity.\n\n"
    "## Conclusion\n\nA conclusion invented for the purposes of the test.\n\n"
    "## Consequences for the project\n\nA description of both branches.\n\n"
    "## Revision conditions\n\nA changed agreement, employer or scope.\n"
)

QUOTED_BODY = VALID_BODY + "\n> A quote from the agreement that should not be here.\n"


def _valid_fields(**overrides: str) -> dict[str, str]:
    fields = {
        "requirement": "PUB-01",
        "scope": "employment-contract-ip-and-non-compete",
        "reviewed_on": "2026-09-02",
        "reviewer": "Jane Doe",
        "verdict": "go",
    }
    fields.update(overrides)
    return fields


# --- Module contract ---------------------------------------------------------


def test_module_defines_required_symbols():
    assert callable(gate.load_record)
    assert callable(gate.validate_record)
    assert callable(gate.main)


def test_reviewer_is_invalid_public_alias_is_the_same_object_as_private_name():
    """Assumption Z-102 (plan 05-04): `scripts/check_history_audit_gate.py`
    imports this check instead of copying it - the alias must point at
    EXACTLY THE SAME function object, not at a copy behaving identically."""
    assert gate.reviewer_is_invalid is gate._reviewer_is_invalid


def test_all_exports_three_new_public_names():
    assert "reviewer_is_invalid" in gate.__all__
    assert "AGENT_REVIEWER_NAMES" in gate.__all__
    assert "RecordShapeError" in gate.__all__


def test_module_imports_only_standard_library():
    import ast

    source = (SCRIPTS_DIR / "check_pub_gate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    stdlib_names = set(sys.stdlib_module_names)
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


# --- load_record: the file is absent -----------------------------------------


def test_main_missing_file_exits_3(tmp_path):
    missing = tmp_path / "no-such-file.md"
    exit_code = gate.main(["--record-path", str(missing)])
    assert exit_code == 3


# --- validate_record: incomplete fields --------------------------------------


def test_missing_required_key_exits_4():
    fields = _valid_fields()
    del fields["reviewer"]
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_missing_verdict_key_exits_4():
    fields = _valid_fields()
    del fields["verdict"]
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- validate_record: unparseable date ---------------------------------------


def test_unparseable_date_exits_4():
    fields = _valid_fields(reviewed_on="yesterday")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_wrong_date_format_exits_4():
    fields = _valid_fields(reviewed_on="02.09.2026")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- validate_record: the reviewer field -------------------------------------


def test_empty_reviewer_on_resolved_record_exits_4():
    fields = _valid_fields(reviewer="")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_placeholder_reviewer_exits_4():
    fields = _valid_fields(reviewer="<TBD>")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_agent_name_reviewer_exits_4():
    fields = _valid_fields(reviewer="assistant")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_agent_name_reviewer_case_insensitive_exits_4():
    fields = _valid_fields(reviewer="Agent")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- validate_record: block quote --------------------------------------------


def test_blockquote_line_in_body_exits_4():
    fields = _valid_fields()
    code, _message = gate.validate_record(fields, QUOTED_BODY)
    assert code == 4


def test_blockquote_line_flags_even_when_verdict_pending_exits_4():
    fields = _valid_fields(verdict="pending", reviewed_on="", reviewer="")
    code, _message = gate.validate_record(fields, QUOTED_BODY)
    # The body rule applies regardless of the state of the verdict: the record
    # carries the conclusion alone, never a quote, before the verdict is
    # reached as well.
    assert code == 4


# --- validate_record: pending -------------------------------------------------


def test_pending_verdict_exits_5():
    fields = _valid_fields(verdict="pending", reviewed_on="", reviewer="")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 5


# --- validate_record: properly resolved --------------------------------------


def test_complete_go_record_exits_0_and_reports_verdict():
    fields = _valid_fields(verdict="go")
    code, message = gate.validate_record(fields, VALID_BODY)
    assert code == 0
    assert "go" in message


def test_complete_no_go_record_exits_0_and_reports_verdict():
    fields = _valid_fields(verdict="no-go")
    code, message = gate.validate_record(fields, VALID_BODY)
    assert code == 0
    assert "no-go" in message


def test_invalid_verdict_value_exits_4():
    fields = _valid_fields(verdict="maybe")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- main(): stdout and the --require-go flag --------------------------------


def _write_record(path: Path, fields: dict[str, str], body: str) -> None:
    lines = ["---"]
    for key, value in fields.items():
        lines.append(f"{key}: {value}")
    lines.append("---")
    lines.append(body)
    path.write_text("\n".join(lines), encoding="utf-8")


def test_main_prints_verdict_line_on_success(tmp_path, capsys):
    record = tmp_path / "record.md"
    _write_record(record, _valid_fields(verdict="go"), VALID_BODY)
    exit_code = gate.main(["--record-path", str(record)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "verdict=go"


def test_main_require_go_on_no_go_record_exits_1(tmp_path):
    record = tmp_path / "record.md"
    _write_record(record, _valid_fields(verdict="no-go"), VALID_BODY)
    exit_code = gate.main(["--record-path", str(record), "--require-go"])
    assert exit_code == 1


def test_main_require_go_on_go_record_exits_0(tmp_path):
    record = tmp_path / "record.md"
    _write_record(record, _valid_fields(verdict="go"), VALID_BODY)
    exit_code = gate.main(["--record-path", str(record), "--require-go"])
    assert exit_code == 0


def test_main_pending_record_exits_5(tmp_path):
    record = tmp_path / "record.md"
    _write_record(
        record,
        _valid_fields(verdict="pending", reviewed_on="", reviewer=""),
        VALID_BODY,
    )
    exit_code = gate.main(["--record-path", str(record)])
    assert exit_code == 5


# --- The repository record: shape only, never a forced verdict ---------------


def test_repository_record_has_valid_shape():
    """The record is meant to be well formed at all times. Whether the verdict

    has been reached is not a property checked by this test suite - code 0
    (resolved) and code 5 (pending) are both acceptable.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "check_pub_gate.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 5), (
        result.returncode,
        result.stdout,
        result.stderr,
    )
