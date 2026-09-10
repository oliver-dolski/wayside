"""Machine gate for decision LOCK-01 (FOUND-01): no dependency on an external
packet decoder.

The scan scope (`SCAN_SCOPE`) deliberately skips `docs/` and `.planning/` -
that is where the decision record `docs/decisions/0001-decoding-engine-v1.md`
lives, and it has to be free to name the tools the project's code does not
use. If those directories were in scope, the very document describing the
decision would break its own gate.

The `scapy.all` import is checked separately, through the AST rather than
through a text pattern: `src/wayside/pcap.py` states in its docstring that the
module does NOT import `scapy.all`, so a naive substring scan would catch that
description as a false alarm. The AST sees actual import statements, not prose
mentions of them.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DECISION_DOC = "docs/decisions/0001-decoding-engine-v1.md"

# The scan scope is part of this gate's contract (Task 2, plan 01-03).
# `.github/workflows` only comes into being in plan 01-05 - `scan_tree` is
# called on it conditionally, only when it exists.
SCAN_SCOPE: tuple[str, ...] = (
    "src",
    "scripts",
    "pyproject.toml",
    "uv.lock",
    ".github/workflows",
)

# The binary names of the external dissector plus the name of the package that
# wraps them. `pyshark` is the realistic route of a silent return: it installs
# like an ordinary PyPI library and runs `tshark` on the inside. Matching is
# case insensitive (see `scan_tree`).
EXTERNAL_DISSECTOR_PATTERNS: tuple[str, ...] = (
    "tshark",
    "wireshark",
    "pyshark",
)


def scan_tree(root: Path, patterns: tuple[str, ...]) -> list[tuple[Path, int, str]]:
    """Scans the text files under `root` for `patterns`.

    `root` may be a file or a directory; a directory is searched recursively.
    Matching is case-insensitive substring matching. Files that cannot be
    decoded as text (binaries, `.pyc` and the like) are skipped. Returns a list
    of (path, line_number, matched_pattern) - one tuple per hit.
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
    """Returns the `.py` files under `root` that import `scapy.all` (import or from-import).

    It uses the AST rather than text matching, precisely so as not to catch a
    prose mention of `scapy.all` in a comment or a docstring (see the module
    header).
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
        "An external packet decoder detected within the scope of the LOCK-01 gate:\n"
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


# --- The gate over the real repository tree --------------------------------


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
    # Exactly this case really exists in `src/wayside/pcap.py`: the module
    # states in its docstring that it does NOT import `scapy.all`. A naive text
    # scan would catch that as a false alarm.
    clean = tmp_path / "clean.py"
    clean.write_text(
        '"""This module never imports scapy.all, only scapy.utils."""\n'
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
