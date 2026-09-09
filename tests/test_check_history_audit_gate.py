"""Testy jednostkowe PUB-05: bramka ksztaltu `scripts/check_history_audit_gate.py`.

Ten pakiet sprawdza WYLACZNIE ksztalt rekordu (obecnosc pol, dozwolone
wartosci, parsowalnosc dat, regula pola `author`) i mapowanie ksztaltu na
SZESC rozroznialnych kodow wyjscia, wzorem `tests/test_check_pub_gate.py`.
Nie ma tu ani jednego testu wymuszajacego konkretny `result` na prawdziwym
rekordzie repozytorium poza kontrola izolacji zaleznosciowej i kontrola
ksztaltu - werdykt maszynowy nad prawdziwym stanem historii nalezy do
`tests/test_history_audit.py` (znacznik wolny).
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
        "confirmed_on": "",
    }
    fields.update(overrides)
    return fields


VALID_BODY = (
    "## Zakres\n\nTrzy powierzchnie calej historii.\n\n"
    "## Wynik\n\nBrak trafien poza wyjatkami.\n\n"
    "## Wyjatki\n\nPatrz .confidentiality-allow.\n\n"
    "## Kontrakt naprawy\n\ngit filter-repo przed publicznym pushem.\n\n"
    "## Warunki rewizji\n\nZmiana zbioru wzorcow albo wyjatkow.\n"
)


def _write_record(path: Path, fields: dict[str, str], body: str) -> None:
    lines = ["---"]
    for key, value in fields.items():
        lines.append(f"{key}: {value}")
    lines.append("---")
    lines.append(body)
    path.write_text("\n".join(lines), encoding="utf-8")


# --- Kontrakt modulu i izolacja zaleznosciowa --------------------------------


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
    """Izolacja zaleznosciowa po drzewie skladniowym, wzorem
    `tests/test_check_pub_gate.py::test_module_imports_only_standard_library` -
    ten modul dopuszcza dodatkowo WYLACZNIE `check_pub_gate` (siostrzana
    bramka), bez ktorego importu ten modul kopiowalby jej kontrole pola
    `author` zamiast jej uzywac."""
    import ast

    source = (SCRIPTS_DIR / "check_history_audit_gate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    stdlib_names = set(sys.stdlib_module_names) | {"check_pub_gate"}
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


def test_reviewer_check_is_the_same_object_as_sibling_gate():
    """Kontrola pola `author` jest TYM SAMYM obiektem, ktorego uzywa bramka
    rekordu bramki publikacyjnej - nie kopia o identycznym zachowaniu."""
    assert gate.check_pub_gate.reviewer_is_invalid is check_pub_gate.reviewer_is_invalid


# --- main(): brak pliku -------------------------------------------------------


def test_main_missing_file_exits_3(tmp_path):
    missing = tmp_path / "nie-ma-takiego.md"
    exit_code = gate.main(["--record", str(missing)])
    assert exit_code == 3


# --- validate_record: brak separatorow frontmatteru (przez load_record) -----


def test_missing_opening_separator_exits_4(tmp_path):
    record = tmp_path / "record.md"
    record.write_text("brak separatora otwierajacego\n---\ntresc\n", encoding="utf-8")
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


def test_missing_closing_separator_exits_4(tmp_path):
    record = tmp_path / "record.md"
    record.write_text("---\nrequirement: PUB-05\nscope: x\n", encoding="utf-8")
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4


# --- validate_record: pola niekompletne --------------------------------------


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


# --- validate_record: result spoza zbioru ------------------------------------


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


# --- validate_record: lista powierzchni i regul ------------------------------


def test_incomplete_surfaces_list_is_a_shape_error():
    fields = _valid_fields(surfaces="tree-content, commit-message")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_incomplete_rules_list_is_a_shape_error():
    fields = _valid_fields(rules_checked="identity-private-ipv4")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


# --- validate_record: data nieparsowalna -------------------------------------


def test_unparseable_audited_on_is_a_shape_error():
    fields = _valid_fields(audited_on="wczoraj")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


def test_unparseable_confirmed_on_is_a_shape_error_when_non_empty():
    fields = _valid_fields(author="Jan Kowalski", confirmed_on="wczoraj")
    errors = gate.validate_record(fields, VALID_BODY)
    assert errors != []


# --- validate_record: pole author --------------------------------------------


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


# --- main(): stan oczekujacy (pending) ---------------------------------------


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


# --- main(): rozstrzygniete poprawnie, flaga --require-clean ----------------


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


# --- main(): flaga --require-current, rekord nieaktualny --------------------


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


# --- Dyscyplina tresci: rekord nigdy nie niesie fragmentu tresci historii ----


def test_failure_messages_never_carry_matched_content(tmp_path, capsys):
    """Zaden komunikat porazki nie niesie fragmentu tresci historii ani
    nazwy pliku z trafieniem - bramka rekordu widzi tylko pola frontmatteru,
    nigdy trafienia skanu, wiec nie ma nawet z czego wyciec takiego
    fragmentu; ten test dokumentuje tę wlasnosc wprost."""
    fields = _valid_fields(rules_checked="identity-private-ipv4")
    record = tmp_path / "record.md"
    _write_record(record, fields, VALID_BODY)
    exit_code = gate.main(["--record", str(record)])
    assert exit_code == 4
    captured = capsys.readouterr()
    assert "TAJNE-TRAFIENIE-NIE-POWTORZ" not in captured.err


# --- Rekord z repozytorium: tylko ksztalt, nigdy wymuszony wynik -------------


def test_repository_record_has_valid_shape_or_is_pending():
    """Rekord w repozytorium ma byc zawsze dobrze uformowany. Stan
    oczekujacy (kod 5, pola czlowieka puste) i stan rozstrzygniety (kod 0)
    sa oba akceptowalne - to, czy podpis juz zapadl, nie jest wlasnoscia,
    ktora ten pakiet testow wymusza."""
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
