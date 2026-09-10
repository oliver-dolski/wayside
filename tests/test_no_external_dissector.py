"""Bramka maszynowa decyzji LOCK-01 (FOUND-01): brak zaleznosci od zewnetrznego
dekodera pakietow.

Zakres skanu (`SCAN_SCOPE`) celowo pomija `docs/` i `.planning/` - to tam
stoi zapis decyzji `docs/decisions/0001-decoding-engine-v1.md`, ktory
musi wolno nazwac po imieniu narzedzia, ktorych kod projektu nie uzywa.
Gdyby te katalogi byly w zakresie, sam dokument opisujacy decyzje lamalby
wlasna bramke.

Import `scapy.all` jest sprawdzany osobno, przez AST, a nie przez wzorzec
tekstowy: `src/wayside/pcap.py` opisuje w docstringu, ze modul NIE importuje
`scapy.all`, wiec naiwny skan podciagu zlapalby ten opis jako falszywy
alarm. AST widzi rzeczywiste instrukcje importu, nie prozaiczne wzmianki
o nich.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DECISION_DOC = "docs/decisions/0001-decoding-engine-v1.md"

# Zakres skanu jest czescia kontraktu tej bramki (Task 2, plan 01-03).
# `.github/workflows` powstaje dopiero w planie 01-05 - `scan_tree` jest
# wolany na nim warunkowo, tylko gdy istnieje.
SCAN_SCOPE: tuple[str, ...] = (
    "src",
    "scripts",
    "pyproject.toml",
    "uv.lock",
    ".github/workflows",
)

# Nazwy binarek zewnetrznego dysektora oraz nazwa pakietu, ktory je opakowuje.
# `pyshark` jest realistyczna droga cichego powrotu: instaluje sie jak zwykla
# biblioteka PyPI, a w srodku uruchamia `tshark`. Dopasowanie bez rozrozniania
# wielkosci liter (patrz `scan_tree`).
EXTERNAL_DISSECTOR_PATTERNS: tuple[str, ...] = (
    "tshark",
    "wireshark",
    "pyshark",
)


def scan_tree(root: Path, patterns: tuple[str, ...]) -> list[tuple[Path, int, str]]:
    """Skanuje pliki tekstowe pod `root` w poszukiwaniu `patterns`.

    `root` moze byc plikiem albo katalogiem; katalog jest przeszukiwany
    rekurencyjnie. Dopasowanie jest dopasowaniem podciagu bez rozrozniania
    wielkosci liter. Pliki, ktorych nie da sie zdekodowac jako tekst (np.
    binarki, `.pyc`), sa pomijane. Zwraca liste (sciezka, numer_linii,
    dopasowany_wzorzec) - jedna krotke na kazde trafienie.
    """
    compiled = [(pattern, re.compile(re.escape(pattern), re.IGNORECASE)) for pattern in patterns]

    if root.is_file():
        targets = [root]
    elif root.is_dir():
        targets = [p for p in root.rglob("*") if p.is_file()]
    else:
        return []

    hits: list[tuple[Path, int, str]] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern, compiled_pattern in compiled:
                if compiled_pattern.search(line):
                    hits.append((path, line_no, pattern))
    return hits


def scan_scope_for_external_dissector(scope_root: Path = REPO_ROOT) -> list[tuple[Path, int, str]]:
    """Skanuje cale `SCAN_SCOPE` pod `scope_root` w poszukiwaniu zewnetrznego dysektora."""
    hits: list[tuple[Path, int, str]] = []
    for rel in SCAN_SCOPE:
        target = scope_root / rel
        if target.exists():
            hits.extend(scan_tree(target, EXTERNAL_DISSECTOR_PATTERNS))
    return hits


def find_scapy_all_imports(root: Path) -> list[Path]:
    """Zwraca pliki `.py` pod `root`, ktore importuja `scapy.all` (import lub from-import).

    Uzywa AST, nie dopasowania tekstowego, wlasnie zeby nie zlapac prozaicznej
    wzmianki o `scapy.all` w komentarzu albo w docstringu (patrz naglowek modulu).
    """
    if not root.exists():
        return []

    hits: list[Path] = []
    for path in root.rglob("*.py"):
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "scapy.all" for alias in node.names):
                    hits.append(path)
                    break
            elif isinstance(node, ast.ImportFrom):
                if node.module == "scapy.all":
                    hits.append(path)
                    break
    return hits


def _format_violation_message(hits: list[tuple[Path, int, str]]) -> str:
    lines = "\n".join(f"  {path}:{line}: wzorzec '{pattern}'" for path, line, pattern in hits)
    return (
        "Zewnetrzny dekoder pakietow wykryty w zakresie objetym bramka LOCK-01:\n"
        f"{lines}\n"
        f"Decyzja i droga jej rewizji: {DECISION_DOC}"
    )


# --- Dowod wlasnej skutecznosci bramki: wstrzykniecie trafienia ---------------


def test_scan_tree_detects_injected_external_binary_call(tmp_path):
    malicious = tmp_path / "sneaky_dissector.py"
    malicious.write_text(
        'import subprocess\n'
        'subprocess.run(["tshark", "-r", "capture.pcap", "-T", "json"])\n',
        encoding="utf-8",
    )

    hits = scan_tree(tmp_path, EXTERNAL_DISSECTOR_PATTERNS)

    assert len(hits) == 1
    assert hits[0][0] == malicious
    assert hits[0][2] == "tshark"


def test_scan_tree_matches_regardless_of_case(tmp_path):
    malicious = tmp_path / "sneaky.py"
    malicious.write_text('run("WireShark.exe", "-k")\n', encoding="utf-8")

    hits = scan_tree(tmp_path, EXTERNAL_DISSECTOR_PATTERNS)

    assert any(pattern == "wireshark" for _, _, pattern in hits)


def test_scan_tree_returns_empty_for_clean_tree(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("from scapy.utils import rdpcap\n", encoding="utf-8")

    assert scan_tree(tmp_path, EXTERNAL_DISSECTOR_PATTERNS) == []


def test_violation_message_references_decision_doc():
    fake_hit = [(Path("fake.py"), 1, "tshark")]
    message = _format_violation_message(fake_hit)
    assert DECISION_DOC in message


# --- Bramka na prawdziwym drzewie repozytorium --------------------------------


def test_scan_scope_is_clean_of_external_dissector_patterns():
    hits = scan_scope_for_external_dissector()
    assert hits == [], _format_violation_message(hits)


def test_uv_lock_does_not_contain_pyshark_package():
    uv_lock = REPO_ROOT / "uv.lock"
    hits = scan_tree(uv_lock, ("pyshark",))
    assert hits == [], f"uv.lock zawiera 'pyshark': {hits}. Decyzja: {DECISION_DOC}"


# --- Mechanizm Assumption A1: brak importu scapy.all --------------------------


def test_find_scapy_all_imports_detects_direct_import(tmp_path):
    bad = tmp_path / "bad_direct.py"
    bad.write_text("import scapy.all\n", encoding="utf-8")

    assert find_scapy_all_imports(tmp_path) == [bad]


def test_find_scapy_all_imports_detects_from_import(tmp_path):
    bad = tmp_path / "bad_from.py"
    bad.write_text("from scapy.all import IP\n", encoding="utf-8")

    assert find_scapy_all_imports(tmp_path) == [bad]


def test_find_scapy_all_imports_ignores_docstring_mention(tmp_path):
    # Dokladnie ten przypadek istnieje naprawde w `src/wayside/pcap.py`: modul
    # opisuje w docstringu, ze NIE importuje `scapy.all`. Naiwny skan tekstowy
    # zlapalby to jako falszywy alarm.
    clean = tmp_path / "clean.py"
    clean.write_text(
        '"""Ten modul nigdy nie importuje scapy.all, tylko scapy.utils."""\n'
        "from scapy.utils import rdpcap\n",
        encoding="utf-8",
    )

    assert find_scapy_all_imports(tmp_path) == []


def test_no_scapy_all_import_under_src_or_scripts():
    hits: list[Path] = []
    for rel in ("src", "scripts"):
        hits.extend(find_scapy_all_imports(REPO_ROOT / rel))

    assert hits == [], (
        f"Import scapy.all znaleziony w: {[str(p) for p in hits]}. "
        f"Decyzja: {DECISION_DOC}"
    )
