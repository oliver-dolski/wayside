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
import re
import subprocess
import sys
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

# Grupa 4 importuje `scripts/gen_oui_db.py` jak `tests/test_standards_catalog.py`
# importuje `scripts/confidentiality_guard.py` - przez wstawienie katalogu
# `scripts/` do `sys.path`, bo `scripts/` nie jest pakietem instalowanym.
_SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import gen_oui_db  # noqa: E402

DECISION_RECORD_PATH = REPO_ROOT / "docs" / "decisions" / "0002-redystrybucja-rejestru-oui.md"


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

# Sklejony w czasie dzialania z osobnych literalow - patrz docstring
# tests/test_standards_catalog.py: zaden POJEDYNCZY fragment zrodla tego
# pliku nie moze niesc calego naglowka doslownie, inaczej ten wlasny plik
# testowy stalby sie wlasnym falszywym alarmem tej bramki.
_MANUF_HEADER_MARKER = " ".join(("Wireshark", "Ethernet", "OUI"))


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


# --- Grupa 4: scripts/gen_oui_db.py, generator tabeli producentow (Task 4) --
#
# CSV minimalny w ksztalcie rejestru IEEE OUI: naglowek z nazwami kolumn
# odczytywanymi przez `csv.DictReader` (nie zakladanymi z pamieci), jeden
# wiersz z prefiksem niepoprawnym, jeden wiersz z nazwa pusta po oczyszczeniu
# bialych znakow i dwa wiersze o TYM SAMYM prefiksie - dowod na regule
# "ostatni wpis wygrywa", zgodna z porzadkiem pierwszenstwa `load_oui_table`.
_SAMPLE_OUI_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,AABBCC,Organizacja Testowa Jeden,Adres jeden\n"
    "MA-L,001122,Organizacja Testowa Dwa,Adres dwa\n"
    "MA-L,zzzzzz,Organizacja Prefiks Niepoprawny,Adres trzy\n"
    "MA-L,334455,   ,Adres cztery\n"
    "MA-L,001122,Organizacja Testowa Dwa Zaktualizowana,Adres piec\n"
)


def test_build_table_parses_sorts_and_keeps_last_occurrence_on_duplicate_prefix():
    rows = gen_oui_db.build_table(_SAMPLE_OUI_CSV)

    assert rows == [
        ("001122", "Organizacja Testowa Dwa Zaktualizowana"),
        ("AABBCC", "Organizacja Testowa Jeden"),
    ]


def test_build_table_rejects_source_missing_expected_columns():
    with pytest.raises(ValueError):
        gen_oui_db.build_table("KolumnaA,KolumnaB\n1,2\n")


def test_fetch_oui_csv_reads_local_source_without_touching_network(tmp_path):
    source_path = tmp_path / "oui.csv"
    source_path.write_text(_SAMPLE_OUI_CSV, encoding="utf-8")

    text = gen_oui_db.fetch_oui_csv(source_path=source_path)

    assert text == _SAMPLE_OUI_CSV


def test_fetch_oui_csv_rejects_non_https_url():
    with pytest.raises(ValueError):
        gen_oui_db.fetch_oui_csv(url="http://example.invalid/oui.csv")


def test_write_table_output_is_loadable_and_matches_input_rows(tmp_path):
    rows = gen_oui_db.build_table(_SAMPLE_OUI_CSV)
    output_path = tmp_path / "oui_table.tsv"

    gen_oui_db.write_table(rows, output_path, source="zrodlo-testowe")
    loaded = load_oui_table(output_path)

    assert loaded == dict(rows)


def test_gen_oui_db_cli_with_source_two_runs_produce_identical_bytes(tmp_path):
    source_path = tmp_path / "oui.csv"
    source_path.write_text(_SAMPLE_OUI_CSV, encoding="utf-8")

    outputs = []
    for name in ("run1.tsv", "run2.tsv"):
        output_path = tmp_path / name
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "gen_oui_db.py"),
                "--source",
                str(source_path),
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(output_path)

    assert outputs[0].read_bytes() == outputs[1].read_bytes()


def test_gen_oui_db_main_with_source_never_calls_urlopen(tmp_path, monkeypatch):
    source_path = tmp_path / "oui.csv"
    source_path.write_text(_SAMPLE_OUI_CSV, encoding="utf-8")
    output_path = tmp_path / "oui_table.tsv"

    def _fail_urlopen(*_args, **_kwargs):
        raise AssertionError(
            "urllib.request.urlopen nie powinien byc wolany, gdy podano --source."
        )

    monkeypatch.setattr(gen_oui_db.urllib.request, "urlopen", _fail_urlopen)

    exit_code = gen_oui_db.main(
        ["--source", str(source_path), "--output", str(output_path)]
    )

    assert exit_code == 0
    assert output_path.exists()


def test_gen_oui_db_main_without_source_uses_network_fetch(tmp_path, monkeypatch):
    # Dowod na druga polowe kryterium: BEZ --source skrypt siega do sieci
    # (tutaj podstawionej), zamiast po cichu spadac na zrodlo lokalne.
    captured_urls: list[str] = []

    class _FakeHeaders:
        def get_content_charset(self):
            return "utf-8"

    class _FakeResponse:
        headers = _FakeHeaders()

        def __enter__(self):
            return self

        def __exit__(self, *_exc_info):
            return False

        def read(self):
            return _SAMPLE_OUI_CSV.encode("utf-8")

    def _fake_urlopen(url, timeout=None):  # noqa: ARG001
        captured_urls.append(url)
        return _FakeResponse()

    monkeypatch.setattr(gen_oui_db.urllib.request, "urlopen", _fake_urlopen)

    output_path = tmp_path / "oui_table.tsv"
    exit_code = gen_oui_db.main(["--output", str(output_path)])

    assert exit_code == 0
    assert captured_urls == [gen_oui_db.IEEE_OUI_CSV_URL]
    assert output_path.exists()


def test_committed_oui_table_loads_without_raising_and_is_non_empty():
    # Nie porownuje sumy kontrolnej pliku: `* text=auto` w `.gitattributes`
    # normalizuje koniec linii przy pobraniu, wiec taka asercja bylaby
    # testem konfiguracji gita, nie testem danych (plan, Task 4).
    table = load_oui_table(OUI_TABLE_PATH)
    assert len(table) > 0


# --- Grupa 5: rekord decyzji 0002 spojny ze stanem drzewa (Task 4) ---------
#
# Bez tego testu rekord decyzji jest notatka, a nie bramka: pierwsza cicha
# zmiana stanu drzewa (usuniecie albo dodanie oui_table.tsv bez rewizji
# rekordu) rozjezdzalaby sie z nim bez sladu.

_RESOLVED_OPTION_RE = re.compile(r"^resolved_option:\s*(\S+)\s*$", re.MULTILINE)
_KNOWN_OPTIONS = frozenset(
    {"commit-pelnej-tabeli", "commit-podzbioru-ot", "bez-danych-w-repo"}
)


def _is_git_tracked(path: Path) -> bool:
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def test_decision_record_resolved_option_matches_tree_state():
    text = DECISION_RECORD_PATH.read_text(encoding="utf-8")
    match = _RESOLVED_OPTION_RE.search(text)
    assert match is not None, (
        "Rekord decyzji 0002 nie niesie pola 'resolved_option' w frontmatterze."
    )
    resolved_option = match.group(1)
    assert resolved_option in _KNOWN_OPTIONS, (
        f"Pole 'resolved_option' niesie wartosc spoza trzech opcji checkpointu: "
        f"{resolved_option!r}."
    )

    table_tracked = _is_git_tracked(OUI_TABLE_PATH)

    if resolved_option in {"commit-pelnej-tabeli", "commit-podzbioru-ot"}:
        assert OUI_TABLE_PATH.exists(), (
            "Rozstrzygniecie zaklada obecnosc tabeli producentow na dysku, "
            "a pliku tam nie ma."
        )
        assert table_tracked, (
            "Rozstrzygniecie zaklada commit tabeli producentow, a plik nie "
            "jest sledzony przez git."
        )
    else:
        assert not table_tracked, (
            "Rozstrzygniecie 'bez-danych-w-repo' zaklada brak tabeli "
            "producentow w repozytorium, a plik jest sledzony przez git."
        )


# --- ASSET-02: POZYTYWNA sciezka lookupu przez caly potok --------------------
#
# Luka zamknieta po weryfikacji fazy 3 (03-VERIFICATION.md, W-1). Wszystkie
# fixture'y w drzewie maja adresy MAC lokalnie administrowane (`02:00:...`),
# wiec producent jest na nich ZAWSZE nieustalony i zadna asercja nad nimi nie
# odroznia dzialajacego lookupu od zepsutego zlozenia w `pipeline.analyze`.
# Ciche rozpiecie `vendor_lookup` przechodzilo caly pakiet bez ani jednej
# porazki.
#
# Zrzut budowany w katalogu tymczasowym, nie dopisywany do `tests/fixtures/`:
# jego jedynym zadaniem jest niesienie prawdziwego prefiksu IEEE, a fixture
# w drzewie ciagnalby za soba wpis w manifescie i sume kontrolna, ktora
# rozjechalaby sie przy kazdym odswiezeniu tabeli producentow.
#
# Nazwa producenta NIE jest wpisana w tescie na sztywno - jest odczytywana
# z tej samej tabeli, ktora czyta potok. Test pilnuje ZLOZENIA (czy nazwa
# z tabeli dochodzi do artefaktow), nie tresci rejestru IEEE, ktora moze sie
# zmienic przy odswiezeniu pliku.

VENDOR_PROBE_MAC = "00:80:F4:11:22:33"
VENDOR_PROBE_IP = "192.0.2.40"
PEER_MAC = "02:00:00:00:00:07"
PEER_IP = "192.0.2.41"


def _write_probe_capture(path: Path) -> None:
    import wayside.pcap  # noqa: F401  - izolacja cache scapy PRZED importem warstw

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    payload = bytes.fromhex("0001000000060106000000ff")
    packet = (
        Ether(src=VENDOR_PROBE_MAC, dst=PEER_MAC)
        / IP(src=VENDOR_PROBE_IP, dst=PEER_IP)
        / TCP(sport=502, dport=50500, flags="PA")
        / payload
    )
    wrpcap(str(path), [packet])


def test_probe_mac_prefix_is_present_in_the_committed_table():
    """Bezpiecznik testu nizej: gdy ten prefiks zniknie z tabeli przy jej
    odswiezeniu, ma sie zapalic TUTAJ, z czytelnym powodem, a nie w tescie
    zlozenia jako niejasna porazka asercji."""
    table = load_oui_table()

    assert lookup_vendor(VENDOR_PROBE_MAC, table) is not None


def test_vendor_from_real_oui_prefix_reaches_analysis_and_report(tmp_path):
    from datetime import datetime, timezone

    from wayside.pipeline import analyze

    capture = tmp_path / "vendor_probe.pcap"
    _write_probe_capture(capture)
    expected_vendor = lookup_vendor(VENDOR_PROBE_MAC, load_oui_table())

    result = analyze(
        capture,
        out_dir=tmp_path / "out",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    host = next(
        entry
        for entry in result.analysis["assets"]
        if entry["ip"]["value"] == VENDOR_PROBE_IP
    )
    assert host["oui_vendor"]["value"] == expected_vendor
    assert host["oui_vendor"]["provenance"] == "inferred:oui-lookup"
    assert f"- Producent: {expected_vendor} (inferred:oui-lookup)" in result.report_markdown


def test_host_with_locally_administered_mac_stays_undetermined_in_the_same_run(tmp_path):
    """Druga polowa: bez niej test wyzej przeszedlby takze wtedy, gdyby potok
    przypisywal te sama nazwe producenta kazdemu hostowi."""
    from datetime import datetime, timezone

    from wayside.pipeline import analyze

    capture = tmp_path / "vendor_probe.pcap"
    _write_probe_capture(capture)

    result = analyze(
        capture,
        out_dir=tmp_path / "out",
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    peer = next(
        entry for entry in result.analysis["assets"] if entry["ip"]["value"] == PEER_IP
    )
    assert peer["oui_vendor"] == {
        "value": None,
        "provenance": "not-derivable-passively",
    }
