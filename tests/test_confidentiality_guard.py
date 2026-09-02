"""Testy jednostkowe FOUND-03: trzy warstwy `scripts/confidentiality_guard.py`.

Dane testowe ponizej sa ZAWSZE wymyslone: zdania w stylu klauzuli normatywnej
ulozone na potrzeby testu, nigdy prawdziwy fragment IEC 62443, EN 50701 ani
zadnej innej normy. Wklejenie prawdziwego cytatu tutaj odtworzyloby dokladnie
ten wyciek, ktoremu ta bramka ma zapobiegac - tyle ze w pliku testowym
zamiast w katalogu norm (Pitfall 6 w 01-RESEARCH.md). Ten plik jest dlatego
wpisany do `.confidentiality-allow` (warstwa 2, wylacznie).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import confidentiality_guard as guard  # noqa: E402

# Wymyslone zdanie o ksztalcie klauzuli normatywnej: kropkowany numer punktu
# + modalnosc "shall" + dlugosc powyzej progu. Uzywane wielokrotnie ponizej.
FAKE_CLAUSE_SENTENCE = (
    "3.4.2 The system shall enforce authentication for all write operations "
    "performed against any field-side controller in the demonstration zone."
)

# Wersja polska (bez diakrytykow w danych zrodlowych repo, ale bramka ma
# lapac tez wersje z diakrytykami - patrz test_structural_layer_normalizes_diacritics).
FAKE_CLAUSE_SENTENCE_PL_DIACRITICS = (
    "3.4.2 System nie może dopuścić do zapisu w rejestrze bez uwierzytelnienia "
    "operatora obslugujacego stacje demonstracyjna w tej sieci testowej."
)


def test_module_defines_required_symbols():
    assert hasattr(guard, "Violation")
    assert callable(guard.scan_paths)
    assert callable(guard.scan_text_structural)
    assert callable(guard.scan_text_corpus)
    assert callable(guard.scan_files)
    assert callable(guard.main)


def test_violation_has_no_field_for_matched_text():
    field_names = {f.name for f in guard.Violation.__dataclass_fields__.values()}
    assert field_names == {"path", "line", "layer", "rule_id", "reason"}
    for forbidden in ("text", "match", "matched", "content", "snippet"):
        assert forbidden not in field_names


def test_module_imports_only_standard_library():
    source = (SCRIPTS_DIR / "confidentiality_guard.py").read_text(encoding="utf-8")
    import ast

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


# --- Warstwa 0: sciezkowa ----------------------------------------------------


def test_path_layer_flags_any_path_under_standards_local():
    violations = guard.scan_paths(["standards/.local/probka.txt"])
    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_PATH_LOCAL_CORPUS
    assert violations[0].path == "standards/.local/probka.txt"


def test_path_layer_flags_standards_local_regardless_of_extension_binary_or_not():
    violations = guard.scan_paths(["standards/.local/norma.bin"])
    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_PATH_LOCAL_CORPUS


def test_path_layer_does_not_flag_public_standards_directory():
    violations = guard.scan_paths(["standards/publiczny.md"])
    assert violations == []


# --- Warstwa 2: strukturalna --------------------------------------------------


def test_structural_layer_flags_clause_number_with_modal_in_same_line():
    violations = guard.scan_text_structural(FAKE_CLAUSE_SENTENCE, "wymyslony.txt")
    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_STRUCTURAL_CLAUSE_MODAL
    assert violations[0].line == 1


def test_structural_layer_normalizes_diacritics_before_matching_modal_terms():
    violations = guard.scan_text_structural(
        FAKE_CLAUSE_SENTENCE_PL_DIACRITICS, "wymyslony.txt"
    )
    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_STRUCTURAL_CLAUSE_MODAL


def test_structural_layer_ignores_modal_without_clause_number():
    text = (
        "System musi wymuszac uwierzytelnianie dla wszystkich operacji "
        "zapisu wykonywanych na dowolnym sterowniku w strefie testowej."
    )
    assert guard.scan_text_structural(text, "wymyslony.txt") == []


def test_structural_layer_ignores_clause_number_without_modal():
    text = (
        "Sekcja 3.4.2 opisuje architekture referencyjna strefy testowej "
        "uzywanej w tym srodowisku demonstracyjnym do celow szkoleniowych."
    )
    assert guard.scan_text_structural(text, "wymyslony.txt") == []


def test_structural_layer_ignores_short_fragment_below_threshold():
    text = "3.4.2 shall."
    assert guard.scan_text_structural(text, "wymyslony.txt") == []


def test_structural_layer_ignores_dash_separated_standard_signature():
    text = (
        "Powolanie na punkt normy 62443-3-3 musi znalezc sie w kazdym "
        "raporcie wygenerowanym przez to narzedzie zgodnie z konwencja."
    )
    # "62443-3-3" nie ma ksztaltu \d+\.\d+(\.\d+)* (myslniki, nie kropki),
    # wiec mimo obecnosci "musi" fragment nie jest naruszeniem.
    assert guard.scan_text_structural(text, "wymyslony.txt") == []


def test_structural_layer_allow_list_suppresses_violation_only_for_listed_file():
    allow_patterns = ["tests/test_confidentiality_guard.py"]
    assert guard._matches_allow_list(
        "tests/test_confidentiality_guard.py", allow_patterns
    )
    assert not guard._matches_allow_list("src/wayside/cli.py", allow_patterns)


# --- Warstwa 1: korpusowa -----------------------------------------------------


def test_corpus_layer_flags_matching_twelve_word_shingle(tmp_path):
    corpus_dir = tmp_path / "standards" / ".local"
    corpus_dir.mkdir(parents=True)
    shared_sentence = (
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet "
        "kilo lima"
    )
    (corpus_dir / "norma-wymyslona.txt").write_text(shared_sentence, encoding="utf-8")

    scanned_text = f"Wstep bez znaczenia. {shared_sentence}. Koniec bez znaczenia."
    violations = guard.scan_text_corpus(scanned_text, "wymyslony.txt", corpus_dir)

    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_CORPUS_SHINGLE


def test_corpus_layer_ignores_text_with_no_shingle_overlap(tmp_path):
    corpus_dir = tmp_path / "standards" / ".local"
    corpus_dir.mkdir(parents=True)
    (corpus_dir / "norma-wymyslona.txt").write_text(
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
        encoding="utf-8",
    )

    unrelated_text = "To jest zdanie, ktore nie ma nic wspolnego z korpusem testowym."
    assert guard.scan_text_corpus(unrelated_text, "wymyslony.txt", corpus_dir) == []


def test_corpus_layer_warns_on_stderr_when_corpus_dir_missing(tmp_path, capsys):
    missing_dir = tmp_path / "standards" / ".local"
    assert not missing_dir.exists()

    violations = guard.scan_text_corpus("dowolny tekst", "wymyslony.txt", missing_dir)

    assert violations == []
    captured = capsys.readouterr()
    assert "POMINIETA" in captured.err
    assert captured.out == ""


def test_corpus_layer_warns_on_stderr_when_corpus_dir_empty(tmp_path, capsys):
    empty_dir = tmp_path / "standards" / ".local"
    empty_dir.mkdir(parents=True)

    violations = guard.scan_text_corpus("dowolny tekst", "wymyslony.txt", empty_dir)

    assert violations == []
    captured = capsys.readouterr()
    assert "POMINIETA" in captured.err


# --- Wyciek tresci w wyjsciu --------------------------------------------------


def test_output_never_carries_matched_text(capsys):
    exit_code = guard.main(
        [
            "--no-corpus",
            "--allow-file",
            "/nieistniejacy/plik/wyjatkow.txt",
        ]
    )
    # Bez plikow na wejsciu nic sie nie dzieje - test wlasciwy jest nizej,
    # ten tylko upewnia sie, ze main() dziala bez plikow (kod 0).
    assert exit_code == 0

    fake_file = "wymyslony_do_wyjscia.txt"
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        target = Path(tmp_dir) / fake_file
        target.write_text(FAKE_CLAUSE_SENTENCE, encoding="utf-8")

        exit_code = guard.main(["--no-corpus", str(target)])
        assert exit_code == 1

        captured = capsys.readouterr()
        # "authentication for all write operations performed against" to
        # unikalny fragment zdania wymyslonego wyzej - jego obecnosc w
        # wyjsciu bramki bylaby wyciekiem tresci skanowanej.
        unique_fragment = "authentication for all write operations performed against"
        assert unique_fragment not in captured.out
        assert unique_fragment not in captured.err
        assert guard.RULE_STRUCTURAL_CLAUSE_MODAL in captured.out


# --- Regresja na wlasnym drzewie ----------------------------------------------


def test_guard_is_clean_over_tracked_tree(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    result = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    all_paths = [p for p in result.stdout.splitlines() if p]

    text_paths: list[str] = []
    for rel_path in all_paths:
        # `.planning/` to badania i notatki planistyczne GSD, nie tresc
        # projektu, ktora ta bramka ma chronic. Zawiera m.in.
        # `01-RESEARCH.md`, ktory cytuje - jako przyklad ilustracyjny we
        # wlasnym Pattern 2 - dokladnie ten sam wymyslony ksztalt zdania
        # klauzula+modalnosc, co ten plik testowy. To nie jest tresc
        # normatywna ani realny wyciek, tylko dokumentacja procesu
        # planowania, wiec zostaje poza zakresem tego testu regresyjnego
        # (ktory pilnuje falszywych alarmow na WLASNEJ DOKUMENTACJI
        # PROJEKTU, nie na wewnetrznych notatkach planistycznych).
        if rel_path.startswith(".planning/"):
            continue
        full_path = REPO_ROOT / rel_path
        if not full_path.is_file():
            continue
        try:
            full_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        text_paths.append(rel_path)

    allow_patterns = guard._load_allow_patterns(REPO_ROOT / ".confidentiality-allow")
    violations = guard.scan_files(
        paths=text_paths,
        corpus_dir=REPO_ROOT / "standards" / ".local",
        use_corpus=False,
        allow_patterns=allow_patterns,
    )

    assert violations == [], [
        (v.path, v.line, v.rule_id) for v in violations
    ]
