"""Testy jednostkowe PUB-01: bramka ksztaltu `scripts/check_pub_gate.py`.

Ten pakiet sprawdza WYLACZNIE ksztalt rekordu (obecnosc pol, parsowalnosc
daty, brak cytatu blokowego, reguly pola `reviewer`) i mapowanie ksztaltu na
kody wyjscia. Nie ma tu ani jednego testu wymuszajacego konkretna wartosc
`verdict` (`go` albo `no-go`) na prawdziwym rekordzie repozytorium - to jest
decyzja czlowieka, nie wlasnosc sprawdzana przez pakiet testow (patrz
`test_repository_record_has_valid_shape` nizej).
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
    "## Zakres przegladu\n\nWlasnosc intelektualna i dzialalnosc konkurencyjna.\n\n"
    "## Wniosek\n\nWniosek wymyslony na potrzeby testu.\n\n"
    "## Skutki dla projektu\n\nOpis obu galezi.\n\n"
    "## Warunki rewizji\n\nZmiana umowy, zmiana pracodawcy, zmiana zakresu.\n"
)

QUOTED_BODY = VALID_BODY + "\n> Cytat z umowy, ktory nie powinien tu byc.\n"


def _valid_fields(**overrides: str) -> dict[str, str]:
    fields = {
        "requirement": "PUB-01",
        "scope": "employment-contract-ip-and-non-compete",
        "reviewed_on": "2026-09-02",
        "reviewer": "Jan Kowalski",
        "verdict": "go",
    }
    fields.update(overrides)
    return fields


# --- Kontrakt modulu ---------------------------------------------------------


def test_module_defines_required_symbols():
    assert callable(gate.load_record)
    assert callable(gate.validate_record)
    assert callable(gate.main)


def test_reviewer_is_invalid_public_alias_is_the_same_object_as_private_name():
    """Zalozenie Z-102 (plan 05-04): `scripts/check_history_audit_gate.py`
    importuje ta kontrole zamiast ja kopiowac - alias musi wskazywac
    DOKLADNIE TEN SAM obiekt funkcji, nie kopie o identycznym zachowaniu."""
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
                assert top_level in stdlib_names, f"Zewnetrzny import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top_level = node.module.split(".")[0]
            assert top_level in stdlib_names, f"Zewnetrzny import: {node.module}"


# --- load_record: brak pliku -------------------------------------------------


def test_main_missing_file_exits_3(tmp_path):
    missing = tmp_path / "nie-ma-takiego.md"
    exit_code = gate.main(["--record-path", str(missing)])
    assert exit_code == 3


# --- validate_record: pola niekompletne -------------------------------------


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


# --- validate_record: data nieparsowalna -------------------------------------


def test_unparseable_date_exits_4():
    fields = _valid_fields(reviewed_on="wczoraj")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_wrong_date_format_exits_4():
    fields = _valid_fields(reviewed_on="02.09.2026")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- validate_record: pole reviewer ------------------------------------------


def test_empty_reviewer_on_resolved_record_exits_4():
    fields = _valid_fields(reviewer="")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_placeholder_reviewer_exits_4():
    fields = _valid_fields(reviewer="<TBD>")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_agent_name_reviewer_exits_4():
    fields = _valid_fields(reviewer="claude")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


def test_agent_name_reviewer_case_insensitive_exits_4():
    fields = _valid_fields(reviewer="Agent")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 4


# --- validate_record: cytat blokowy ------------------------------------------


def test_blockquote_line_in_body_exits_4():
    fields = _valid_fields()
    code, _message = gate.validate_record(fields, QUOTED_BODY)
    assert code == 4


def test_blockquote_line_flags_even_when_verdict_pending_exits_4():
    fields = _valid_fields(verdict="pending", reviewed_on="", reviewer="")
    code, _message = gate.validate_record(fields, QUOTED_BODY)
    # Regula tresci dziala niezaleznie od stanu rozstrzygniecia: rekord
    # niesie sam wniosek, nigdy cytat, takze zanim rozstrzygniecie zapadnie.
    assert code == 4


# --- validate_record: pending -------------------------------------------------


def test_pending_verdict_exits_5():
    fields = _valid_fields(verdict="pending", reviewed_on="", reviewer="")
    code, _message = gate.validate_record(fields, VALID_BODY)
    assert code == 5


# --- validate_record: rozstrzygniete poprawnie -------------------------------


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


# --- main(): stdout i flaga --require-go -------------------------------------


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


# --- Rekord z repozytorium: tylko ksztalt, nigdy wymuszone rozstrzygniecie --


def test_repository_record_has_valid_shape():
    """Rekord ma byc zawsze dobrze uformowany. To, czy rozstrzygniecie juz

    zapadlo, nie jest wlasnoscia sprawdzana przez ten pakiet testow - kod 0
    (rozstrzygniete) i kod 5 (pending) sa oba akceptowalne.
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
