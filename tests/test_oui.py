"""Bramka maszynowa ASSET-02: lookup producenta z prefiksu adresu MAC,
brak pliku `manuf` Wiresharka w drzewie repozytorium, brak importu sieciowego
w warstwie uruchomieniowej (plan 03-05, Task 1).

Grupa pierwsza (jednostkowa) NIE odwoluje sie do `oui.OUI_TABLE_PATH` i
przechodzi niezaleznie od tego, czy `src/wayside/assets/oui_table.tsv` lezy
w drzewie - to jest zalozenie Z-20 z planu: lookup jest wstrzykiwany jako
argument, kod i jego testy sa wiec calkowicie niezalezne od rozstrzygniecia
checkpointu redystrybucji danych (Task 3 tego planu).

Grupa druga kopiuje wzorzec `scan_tree` z `tests/test_no_external_dissector.py`.
Grupa trzecia skanuje drzewo skladni (AST), nie dopasowanie tekstowe - to samo
uzasadnienie, ktore `tests/test_no_external_dissector.py` niesie dla
`find_scapy_all_imports`: naiwny skan tekstowy zlapalby prozaiczna wzmianke
w docstringu tego wlasnie modulu jako falszywy alarm.

Nazwa tego pliku jest czescia kontraktu wymaganie-na-test z `03-VALIDATION.md`
i nie ulega zmianie.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from wayside.assets.oui import (
    OUI_PREFIX_LEN,
    OUI_TABLE_PATH,
    PROVENANCE_METHOD_OUI,
    OuiTableError,
    load_oui_table,
    lookup_vendor,
    normalize_mac_prefix,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- Stale modulu: ksztalt kontraktu z bloku <interfaces> planu ------------


def test_module_constants_have_expected_shape():
    assert OUI_PREFIX_LEN == 6
    assert PROVENANCE_METHOD_OUI == "oui-lookup"
    assert OUI_TABLE_PATH.name == "oui_table.tsv"


# --- Grupa 1: normalize_mac_prefix, niezalezna od pliku danych -------------


def test_normalize_mac_prefix_colon_separated():
    assert normalize_mac_prefix("02:00:00:00:00:01") == "020000"


def test_normalize_mac_prefix_hyphen_separated():
    assert normalize_mac_prefix("02-00-00-00-00-01") == "020000"


def test_normalize_mac_prefix_dot_separated():
    assert normalize_mac_prefix("0200.0000.0001") == "020000"


def test_normalize_mac_prefix_no_separator_uppercases():
    assert normalize_mac_prefix("aabbcc") == "AABBCC"


def test_normalize_mac_prefix_empty_string_gives_none():
    assert normalize_mac_prefix("") is None


def test_normalize_mac_prefix_too_short_gives_none():
    assert normalize_mac_prefix("02:00") is None


def test_normalize_mac_prefix_non_hex_gives_none():
    assert normalize_mac_prefix("zz:zz:zz:zz:zz:zz") is None


# --- Grupa 1: load_oui_table, tabela zapisana w tmp_path --------------------


def test_load_oui_table_two_data_rows_and_one_comment_row(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# zrodlo: testowe, data pobrania: 2026-01-01, wpisow: 2\n"
        "020000\tOrganizacja Testowa Jeden\n"
        "AABBCC\tOrganizacja Testowa Dwa\n",
        encoding="utf-8",
    )

    table = load_oui_table(table_path)

    assert table == {
        "020000": "Organizacja Testowa Jeden",
        "AABBCC": "Organizacja Testowa Dwa",
    }


def test_load_oui_table_skips_blank_and_comment_lines_without_raising(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# naglowek\n"
        "\n"
        "020000\tOrganizacja Testowa\n"
        "\n"
        "# kolejny komentarz\n",
        encoding="utf-8",
    )

    table = load_oui_table(table_path)

    assert table == {"020000": "Organizacja Testowa"}


def test_load_oui_table_one_column_row_raises_with_line_number(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# naglowek\n"
        "020000-bez-tabulatora\n",
        encoding="utf-8",
    )

    with pytest.raises(OuiTableError) as excinfo:
        load_oui_table(table_path)

    assert "2" in str(excinfo.value)


def test_load_oui_table_three_column_row_raises(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "020000\tOrganizacja\tKolumna Nadmiarowa\n",
        encoding="utf-8",
    )

    with pytest.raises(OuiTableError):
        load_oui_table(table_path)


def test_load_oui_table_nonexistent_path_raises():
    with pytest.raises(OuiTableError):
        load_oui_table(Path("nieistniejaca-sciezka-oui-table.tsv"))


# --- Grupa 1: lookup_vendor --------------------------------------------------


def test_lookup_vendor_matching_prefix_returns_organization_name():
    table = {"020000": "Organizacja Testowa"}
    assert lookup_vendor("02:00:00:00:00:01", table) == "Organizacja Testowa"


def test_lookup_vendor_no_match_returns_none():
    table = {"020000": "Organizacja Testowa"}
    assert lookup_vendor("aa:bb:cc:dd:ee:ff", table) is None


def test_lookup_vendor_invalid_mac_returns_none_without_raising():
    table = {"020000": "Organizacja Testowa"}
    assert lookup_vendor("nie-jest-adresem-mac", table) is None


def test_lookup_vendor_empty_table_returns_none():
    assert lookup_vendor("02:00:00:00:00:01", {}) is None


# --- Grupa 2: brak pliku manuf w calym drzewie repozytorium (poza .git) ----
#
# "Drzewo repozytorium" jest tu scisle rozumiane jako drzewo SLEDZONE przez
# git (`git ls-files`), nie surowy system plikow pod korzeniem projektu.
# Powod: `.venv/Lib/site-packages/scapy/libs/manuf.py` jest WLASNYM,
# wewnetrznym modulem scapy implementujacym lookup OUI - zupelnie innym
# plikiem niz baza danych `manuf` Wiresharka, ktory przypadkiem dzieli
# nazwe. `.venv/` jest gitignorowany (`.gitignore`), wiec ten plik nigdy nie
# trafia do publikowanego repozytorium - dokladnie to jest przedmiotem
# tej bramki (ryzyko redystrybucji, nie obecnosc dowolnego pliku o tej
# nazwie na dysku dewelopera). Ten sam powod, dla ktorego
# tests/test_no_external_dissector.py skanuje SCAN_SCOPE, a nie caly system
# plikow.

_MANUF_HEADER_MARKER = "Wireshark Ethernet OUI"


def _git_tracked_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [repo_root / rel for rel in result.stdout.split("\0") if rel]


def _iter_files(paths: list[Path], *, exclude_dir_names: tuple[str, ...]) -> list[Path]:
    return [
        path
        for path in paths
        if path.is_file() and not any(excluded in path.parts for excluded in exclude_dir_names)
    ]


def test_no_manuf_named_file_anywhere_in_repository_tree():
    tracked = _git_tracked_files(REPO_ROOT)
    hits = [
        path
        for path in _iter_files(tracked, exclude_dir_names=())
        if path.name.lower() == "manuf" or path.name.lower().startswith("manuf.")
    ]
    assert hits == [], f"Plik o nazwie manuf znaleziony w drzewie repozytorium: {hits}"


def test_no_wireshark_manuf_format_header_outside_planning():
    # .planning jest poza zakresem z tego samego powodu, dla ktorego
    # tests/test_no_external_dissector.py wyklucza docs/ i .planning/: tam
    # stoja dokumenty, ktore musza wolno nazwac po imieniu plik, ktorego
    # kod projektu nie uzywa (03-RESEARCH.md, Pattern 6).
    tracked = _git_tracked_files(REPO_ROOT)
    hits: list[Path] = []
    for path in _iter_files(tracked, exclude_dir_names=(".planning",)):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if _MANUF_HEADER_MARKER in text:
            hits.append(path)
    assert hits == [], (
        f"Naglowek formatu pliku manuf Wiresharka znaleziony poza "
        f".planning/: {hits}"
    )


# --- Grupa 3: brak importu sieciowego w src/wayside/, przez AST -----------

NETWORK_MODULE_PREFIXES: tuple[str, ...] = ("urllib", "http", "requests", "socket", "ssl")


def _module_is_network(module_name: str | None) -> bool:
    if module_name is None:
        return False
    return any(
        module_name == prefix or module_name.startswith(f"{prefix}.")
        for prefix in NETWORK_MODULE_PREFIXES
    )


def _find_network_imports(root: Path) -> list[tuple[Path, int]]:
    hits: list[tuple[Path, int]] = []
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
                for alias in node.names:
                    if _module_is_network(alias.name):
                        hits.append((path, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if _module_is_network(node.module):
                    hits.append((path, node.lineno))
    return hits


def test_no_network_module_imports_under_src_wayside():
    # Naiwny skan tekstowy zlapalby wlasny docstring tego modulu (patrz
    # naglowek pliku) jako falszywy alarm - stad AST, nie dopasowanie
    # podciagu, wzorem find_scapy_all_imports w test_no_external_dissector.py.
    hits = _find_network_imports(REPO_ROOT / "src" / "wayside")
    assert hits == [], (
        f"Import sieciowy znaleziony w warstwie uruchomieniowej: {hits}"
    )


def test_find_network_imports_detects_injected_urllib_import(tmp_path):
    malicious = tmp_path / "sneaky.py"
    malicious.write_text("import urllib.request\n", encoding="utf-8")

    hits = _find_network_imports(tmp_path)

    assert hits == [(malicious, 1)]


def test_find_network_imports_ignores_docstring_mention(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text(
        '"""Ten modul nigdy nie importuje urllib, http, requests, socket '
        'ani ssl."""\n'
        "from pathlib import Path\n",
        encoding="utf-8",
    )

    assert _find_network_imports(tmp_path) == []
