"""Machine gate ASSET-02: the vendor lookup from a MAC address prefix, the
absence of a Wireshark `manuf` file in the repository tree, the absence of a
network import in the runtime layer (plan 03-05, Task 1).

The first group (unit tests) does NOT reference `oui.OUI_TABLE_PATH` and
passes regardless of whether `src/wayside/assets/oui_table.tsv` sits in the
tree - that is assumption Z-20 of the plan: the lookup is injected as an
argument, so the code and its tests are entirely independent of the outcome of
the data redistribution checkpoint (Task 3 of that plan).

The second group copies the `scan_tree` pattern of
`tests/test_no_external_dissector.py`. The third group scans the syntax tree
(AST) rather than matching text - the same justification
`tests/test_no_external_dissector.py` carries for `find_scapy_all_imports`: a
naive text scan would catch the prose mention in the docstring of this very
module as a false alarm.

The name of this file is part of the requirement-to-test contract of
`03-VALIDATION.md` and does not change.
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

# Group 4 imports `scripts/gen_oui_db.py` the way
# `tests/test_standards_catalog.py` imports
# `scripts/confidentiality_guard.py` - by inserting the `scripts/` directory
# into `sys.path`, because `scripts/` is not an installed package.
_SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import gen_oui_db  # noqa: E402

DECISION_RECORD_PATH = REPO_ROOT / "docs" / "decisions" / "0002-oui-registry-redistribution.md"


# --- Module constants: the contract shape from the plan's <interfaces> -----


def test_module_constants_have_expected_shape():
    assert OUI_PREFIX_LEN == 6
    assert PROVENANCE_METHOD_OUI == "oui-lookup"
    assert OUI_TABLE_PATH.name == "oui_table.tsv"


# --- Group 1: normalize_mac_prefix, independent of the data file -----------


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


# --- Group 1: load_oui_table, a table written into tmp_path ----------------


def test_load_oui_table_two_data_rows_and_one_comment_row(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# source: test, generated on: 2026-01-01, entries: 2\n"
        "020000\tTest Organisation One\n"
        "AABBCC\tTest Organisation Two\n",
        encoding="utf-8",
    )

    table = load_oui_table(table_path)

    assert table == {
        "020000": "Test Organisation One",
        "AABBCC": "Test Organisation Two",
    }


def test_load_oui_table_skips_blank_and_comment_lines_without_raising(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# header\n"
        "\n"
        "020000\tTest Organisation\n"
        "\n"
        "# another comment\n",
        encoding="utf-8",
    )

    table = load_oui_table(table_path)

    assert table == {"020000": "Test Organisation"}


def test_load_oui_table_one_column_row_raises_with_line_number(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "# header\n"
        "020000-without-a-tab\n",
        encoding="utf-8",
    )

    with pytest.raises(OuiTableError) as excinfo:
        load_oui_table(table_path)

    assert "2" in str(excinfo.value)


def test_load_oui_table_three_column_row_raises(tmp_path):
    table_path = tmp_path / "oui_table.tsv"
    table_path.write_text(
        "020000\tOrganisation\tExtra Column\n",
        encoding="utf-8",
    )

    with pytest.raises(OuiTableError):
        load_oui_table(table_path)


def test_load_oui_table_nonexistent_path_raises():
    with pytest.raises(OuiTableError):
        load_oui_table(Path("nonexistent-oui-table.tsv"))


# --- Group 1: lookup_vendor ------------------------------------------------


def test_lookup_vendor_matching_prefix_returns_organization_name():
    table = {"020000": "Test Organisation"}
    assert lookup_vendor("02:00:00:00:00:01", table) == "Test Organisation"


def test_lookup_vendor_no_match_returns_none():
    table = {"020000": "Test Organisation"}
    assert lookup_vendor("aa:bb:cc:dd:ee:ff", table) is None


def test_lookup_vendor_invalid_mac_returns_none_without_raising():
    table = {"020000": "Test Organisation"}
    assert lookup_vendor("not-a-mac-address", table) is None


def test_lookup_vendor_empty_table_returns_none():
    assert lookup_vendor("02:00:00:00:00:01", {}) is None


# --- Group 2: no manuf file anywhere in the repository tree (outside .git) -
#
# "The repository tree" is understood strictly here as the tree TRACKED by
# git (`git ls-files`), not the raw file system under the project root. The
# reason: `.venv/Lib/site-packages/scapy/libs/manuf.py` is scapy's OWN
# internal module implementing an OUI lookup - an entirely different file from
# the Wireshark `manuf` database, which happens to share the name. `.venv/` is
# gitignored (`.gitignore`), so that file never reaches the published
# repository - and that is exactly what this gate is about (the redistribution
# risk, not the presence of any file with that name on a developer's disk).
# The same reason tests/test_no_external_dissector.py scans SCAN_SCOPE rather
# than the whole file system.

# Assembled at run time from separate literals - see the docstring of
# tests/test_standards_catalog.py: no SINGLE fragment of this file's source may
# carry the whole header verbatim, otherwise this test file would become this
# gate's own false alarm.
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
    assert hits == [], f"A file named manuf found in the repository tree: {hits}"


def test_no_wireshark_manuf_format_header_outside_planning():
    # .planning is out of scope for the same reason
    # tests/test_no_external_dissector.py excludes docs/ and .planning/: that is
    # where the documents live which have to be free to name the file the
    # project's code does not use (03-RESEARCH.md, Pattern 6).
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
        f"The header of the Wireshark manuf file format found outside "
        f".planning/: {hits}"
    )


# --- Group 3: no network import under src/wayside/, through the AST -------

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
    # A naive text scan would catch this module's own docstring (see the file
    # header) as a false alarm - hence the AST rather than substring matching,
    # following find_scapy_all_imports in test_no_external_dissector.py.
    hits = _find_network_imports(REPO_ROOT / "src" / "wayside")
    assert hits == [], (
        f"A network import found in the runtime layer: {hits}"
    )


def test_find_network_imports_detects_injected_urllib_import(tmp_path):
    malicious = tmp_path / "sneaky.py"
    malicious.write_text("import urllib.request\n", encoding="utf-8")

    hits = _find_network_imports(tmp_path)

    assert hits == [(malicious, 1)]


def test_find_network_imports_ignores_docstring_mention(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text(
        '"""This module never imports urllib, http, requests, socket '
        'or ssl."""\n'
        "from pathlib import Path\n",
        encoding="utf-8",
    )

    assert _find_network_imports(tmp_path) == []


# --- Group 4: scripts/gen_oui_db.py, the vendor table generator (Task 4) ---
#
# A minimal CSV in the shape of the IEEE OUI registry: a header with the
# column names read by `csv.DictReader` (not assumed from memory), one row with
# an invalid prefix, one row whose name is empty after whitespace cleaning, and
# two rows carrying THE SAME prefix - proof of the "last entry wins" rule,
# consistent with the order of precedence of `load_oui_table`.
_SAMPLE_OUI_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,AABBCC,Test Organisation One,Address one\n"
    "MA-L,001122,Test Organisation Two,Address two\n"
    "MA-L,zzzzzz,Organisation With An Invalid Prefix,Address three\n"
    "MA-L,334455,   ,Address four\n"
    "MA-L,001122,Test Organisation Two Updated,Address five\n"
)


def test_build_table_parses_sorts_and_keeps_last_occurrence_on_duplicate_prefix():
    rows = gen_oui_db.build_table(_SAMPLE_OUI_CSV)

    assert rows == [
        ("001122", "Test Organisation Two Updated"),
        ("AABBCC", "Test Organisation One"),
    ]


def test_build_table_rejects_source_missing_expected_columns():
    with pytest.raises(ValueError):
        gen_oui_db.build_table("ColumnA,ColumnB\n1,2\n")


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
            "urllib.request.urlopen must not be called when --source was given."
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
    # It does not compare the file checksum: `* text=auto` in `.gitattributes`
    # normalizes line endings at checkout, so such an assertion would be a test
    # of the git configuration rather than a test of the data (plan, Task 4).
    table = load_oui_table(OUI_TABLE_PATH)
    assert len(table) > 0


# --- Group 5: decision record 0002 consistent with the tree state (Task 4) -
#
# Without this test the decision record is a note rather than a gate: the
# first silent change to the state of the tree (removing or adding
# oui_table.tsv without revising the record) would drift from it without a
# trace.

_RESOLVED_OPTION_RE = re.compile(r"^resolved_option:\s*(\S+)\s*$", re.MULTILINE)
_KNOWN_OPTIONS = frozenset(
    {"commit-full-table", "commit-ot-subset", "no-data-in-repo"}
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
        "Decision record 0002 does not carry a 'resolved_option' field in its frontmatter."
    )
    resolved_option = match.group(1)
    assert resolved_option in _KNOWN_OPTIONS, (
        f"The 'resolved_option' field carries a value outside the three "
        f"checkpoint options: {resolved_option!r}."
    )

    table_tracked = _is_git_tracked(OUI_TABLE_PATH)

    if resolved_option in {"commit-full-table", "commit-ot-subset"}:
        assert OUI_TABLE_PATH.exists(), (
            "The decision assumes the vendor table is present on disk, and the "
            "file is not there."
        )
        assert table_tracked, (
            "The decision assumes the vendor table is committed, and the file "
            "is not tracked by git."
        )
    else:
        assert not table_tracked, (
            "The 'no-data-in-repo' decision assumes the vendor table is absent "
            "from the repository, and the file is tracked by git."
        )


# --- ASSET-02: the POSITIVE lookup path through the whole pipeline ---------
#
# A gap closed after the phase 3 verification (03-VERIFICATION.md, W-1).
# Every fixture in the tree carries locally administered MAC addresses
# (`02:00:...`), so over them the vendor is ALWAYS not determined and no
# assertion over them tells a working lookup apart from a broken composition in
# `pipeline.analyze`. Silently unhooking `vendor_lookup` used to pass the whole
# suite without a single failure.
#
# The capture is built in a temporary directory rather than added to
# `tests/fixtures/`: its only job is to carry a real IEEE prefix, and a fixture
# in the tree would drag along a manifest entry and a checksum that would drift
# at every refresh of the vendor table.
#
# The vendor name is NOT hard-coded in the test - it is read from the same
# table the pipeline reads. The test guards the COMPOSITION (whether the name
# from the table reaches the artifacts), not the content of the IEEE registry,
# which may change when the file is refreshed.

VENDOR_PROBE_MAC = "00:80:F4:11:22:33"
VENDOR_PROBE_IP = "192.0.2.40"
PEER_MAC = "02:00:00:00:00:07"
PEER_IP = "192.0.2.41"


def _write_probe_capture(path: Path) -> None:
    import wayside.pcap  # noqa: F401  - scapy cache isolation BEFORE importing the layers

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
    """The fuse for the test below: should this prefix vanish from the table
    at a refresh, it is meant to trip HERE, with a readable reason, rather than
    in the composition test as an opaque assertion failure."""
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
    assert f"- Vendor: {expected_vendor} (inferred:oui-lookup)" in result.report_markdown


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
