"""Test integracyjny INGEST-01/REPORT-04: pelny potok od pliku pcap do dwoch
artefaktow (`analysis.json`, `report.md`), pokrywajacy punkty z bloku
`<behavior>` zadania 1 planu 02-01 oraz zadania 3 planu 02-02 (kontrakt D-01:
zrzut obciety kontra zrzut legalnie pusty, oba formaty z INGEST-01).

Wzorzec identyczny jak w `tests/test_cli_output_snapshot.py`: subprocess na
module CLI, sciezka fixture WZGLEDNA wobec `REPO_ROOT` (nigdy bezwzgledna -
rozjazd CI vs lokalnie), katalog wyjsciowy w `tmp_path`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from wayside.assets.oui import load_oui_table

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_TRUNCATED_RECORD = "tests/fixtures/pcap/truncated_mid_record.pcap"
FIXTURE_TRUNCATED_BLOCK = "tests/fixtures/pcap/truncated_mid_block.pcapng"
FIXTURE_EMPTY_HEADER = "tests/fixtures/pcap/empty_valid_header.pcap"
FIXTURE_WRITE_PCAPNG = "tests/fixtures/pcap/modbus_write_single_register.pcapng"
FIXTURE_SNAPLEN_TRUNCATED = "tests/fixtures/pcap/snaplen_truncated_frames.pcap"
FIXTURE_CORRUPTED_RECORD_LENGTH = "tests/fixtures/pcap/corrupted_record_length.pcap"
FIXTURE_POLL_CYCLE_SHORT_WINDOW = "tests/fixtures/pcap/modbus_poll_cycle_short_window.pcap"
FIXTURE_POLL_CYCLE_FULL_WINDOW = "tests/fixtures/pcap/modbus_poll_cycle_full_window.pcap"
FIXTURE_RTU_OVER_TCP = "tests/fixtures/pcap/modbus_rtu_over_tcp.pcap"
FIXTURE_GATEWAY = "tests/fixtures/pcap/modbus_gateway_multi_unit_id.pcap"

_GENERATED_AT_KEY_PATTERN = re.compile(r"generat|wygenerowan", re.IGNORECASE)


def _run_analyze_path(fixture_relative: str, out_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            fixture_relative,
            "--out-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        # Jawne UTF-8 zamiast `text=True`: narzedzie wymusza UTF-8 na wlasnym
        # wyjsciu (`cli._force_utf8_output`), wiec odczyt w kodowaniu domyslnym
        # maszyny przekłamywalby polskie znaki w komunikatach. Ten sam idiom, co
        # `tests/test_history_audit.py::_run_git`.
        encoding="utf-8",
        errors="replace",
    )


def _run_analyze(out_dir: Path) -> subprocess.CompletedProcess:
    return _run_analyze_path(FIXTURE_RELATIVE, out_dir)


def _load_analysis(out_dir: Path) -> dict:
    return json.loads((out_dir / "analysis.json").read_text(encoding="utf-8"))


def _collect_keys(obj) -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.append(key)
            keys.extend(_collect_keys(value))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_collect_keys(item))
    return keys


def test_analyze_exits_zero_and_writes_both_artifacts(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "analysis.json").exists()
    assert (tmp_path / "report.md").exists()


def test_analysis_json_has_exactly_two_findings_with_expected_evidence(tmp_path):
    """Fixture bazowy niesie zapis do sterownika przez Modbus/TCP, wiec od
    planu 04-04 daje DWA findingi: jeden z checka za zapis
    (`modbus-unauthenticated-write`) i jeden z checka za uzycie protokolu
    bez uwierzytelnienia (`unauthenticated-industrial-protocol`). Finding
    checka za zapis jest odczytywany po identyfikatorze checka, nie po
    pozycji na liscie - test odczytujacy po pozycji zaczerwienilby sie przy
    kazdym kolejnym checku dopisanym do rejestru."""
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    findings = analysis["findings"]
    assert len(findings) == 2

    finding = next(f for f in findings if f["check_id"] == "modbus-unauthenticated-write")
    assert finding["evidence"]["packet_number"] == 1
    assert finding["evidence"]["session_id"] == 0

    standard_ref = finding["standard_refs"][0]
    assert standard_ref["standard"] == "IEC-62443-3-3"
    assert standard_ref["clause"] == "SR 1.1"
    assert standard_ref["verified"] is False


def test_finding_evidence_carries_endpoint_pair_matching_comm_matrix_row(tmp_path):
    """G-04-5b: dowod findingu z prawdziwego przebiegu ma cztery klucze, i
    para adresow zgadza sie z wierszem macierzy komunikacji tej samej sesji -
    para adresow dopisywana przez silnik checkow, nie przez check ani przez
    warstwe potoku."""
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    rows_by_session = {
        row["session_id"]["value"]: (row["source"]["value"], row["target"]["value"])
        for row in analysis["comm_matrix"]
    }

    findings = analysis["findings"]
    assert findings
    for finding in findings:
        evidence = finding["evidence"]
        assert set(evidence) == {"packet_number", "session_id", "source", "target"}
        expected_source, expected_target = rows_by_session[evidence["session_id"]]
        assert evidence["source"] == expected_source
        assert evidence["target"] == expected_target


def test_analysis_json_has_two_protocol_events(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    events = analysis["protocol_events"]
    assert len(events) == 2
    assert any(e["function_code"] == 6 and e["kind"] == "write" for e in events)
    assert any(e["direction"] == "response" for e in events)


def test_analysis_json_has_provisional_single_zone_and_conduit(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    assert len(analysis["zones"]) == 1
    assert analysis["zones"][0]["provisional"] is True
    assert len(analysis["conduits"]) == 1
    assert analysis["conduits"][0]["provisional"] is True


def test_analysis_json_has_no_generation_timestamp_key(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    offending = [key for key in _collect_keys(analysis) if _GENERATED_AT_KEY_PATTERN.search(key)]
    assert offending == [], f"Klucze przypominajace znacznik wygenerowania: {offending}"


def test_report_markdown_has_six_sections_in_order(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    from wayside.report import SECTIONS

    headers = re.findall(r"^## (.+)$", report_text, flags=re.MULTILINE)
    assert headers == list(SECTIONS)


def test_report_markdown_carries_evidence_and_unverified_marker(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert "Evidence: packet no. 1, session no. 0" in report_text
    assert "SR 1.1" in report_text
    assert "PROVISIONAL" in report_text
    assert "UNVERIFIED" in report_text


# --- D-01: zrzut obciety konczy sie kodem != 0, bez tracebacku, bez artefaktow ---


def test_truncated_mid_record_pcap_exits_with_truncated_code_and_no_artifacts(tmp_path):
    result = _run_analyze_path(FIXTURE_TRUNCATED_RECORD, tmp_path)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "truncated" in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_truncated_mid_block_pcapng_exits_with_truncated_code(tmp_path):
    result = _run_analyze_path(FIXTURE_TRUNCATED_BLOCK, tmp_path)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "truncated" in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
    assert list(tmp_path.iterdir()) == []


# --- D-01: zrzut strukturalnie pusty konczy sie kodem 0, z jawnym ostrzezeniem ---


def test_empty_valid_header_exits_zero_with_warning_and_empty_lists(tmp_path):
    result = _run_analyze_path(FIXTURE_EMPTY_HEADER, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Warning:" in result.stderr

    analysis = _load_analysis(tmp_path)
    assert analysis["conversations"] == []
    assert analysis["protocol_events"] == []
    assert analysis["findings"] == []

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    from wayside.report import SECTIONS

    headers = re.findall(r"^## (.+)$", report_text, flags=re.MULTILINE)
    assert headers == list(SECTIONS)
    assert "No findings in this run." in report_text

    ograniczenia_start = report_text.index("## Limitations")
    findingi_start = report_text.index("## Findings")
    ograniczenia_section = report_text[ograniczenia_start:findingi_start]
    assert "contains no packets at all" in ograniczenia_section


# --- D-01/INGEST-01: fixture pcapng przechodzi caly potok jak fixture klasyczny ---


def test_write_fixture_pcapng_produces_same_finding_as_classic_pcap(tmp_path):
    result = _run_analyze_path(FIXTURE_WRITE_PCAPNG, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = _load_analysis(tmp_path)
    findings = analysis["findings"]
    assert len(findings) == 2
    check_ids = {f["check_id"] for f in findings}
    assert check_ids == {"modbus-unauthenticated-write", "unauthenticated-industrial-protocol"}


# --- Format nierozpoznany i sciezka nieistniejaca ---


def test_unrecognized_magic_exits_with_unsupported_format_code(tmp_path):
    bad_file = tmp_path / "not_a_capture.bin"
    bad_file.write_bytes(b"NOTAMAGIC" + b"\x00" * 20)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run_analyze_path(str(bad_file), out_dir)
    assert result.returncode == 4, result.stdout + result.stderr
    assert "Traceback (most recent call last)" not in result.stderr


def test_nonexistent_path_exits_with_unreadable_code(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run_analyze_path(str(tmp_path / "does_not_exist.pcap"), out_dir)
    assert result.returncode == 2, result.stdout + result.stderr


# --- ASSET-01/ASSET-03: inwentarz w analysis.json (plan 03-01, Task 1) --------


def test_assets_has_two_hosts_in_first_seen_order_with_observed_mac(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    assets = analysis["assets"]
    assert len(assets) == 2
    assert assets[0]["ip"] == {"value": "192.0.2.10", "provenance": "observed"}
    assert assets[0]["mac"] == {"value": "02:00:00:00:00:01", "provenance": "observed"}
    assert assets[1]["ip"] == {"value": "192.0.2.20", "provenance": "observed"}
    assert assets[1]["mac"] == {"value": "02:00:00:00:00:02", "provenance": "observed"}


def test_empty_valid_header_has_empty_assets_list(tmp_path):
    result = _run_analyze_path(FIXTURE_EMPTY_HEADER, tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    assert analysis["assets"] == []


# --- INGEST-02: snaplen w capture, obydwa formaty (plan 03-01, Task 1) -------


def test_capture_section_has_snaplen_for_classic_fixture(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    capture = analysis["capture"]
    assert isinstance(capture["snaplen"], int)
    assert capture["snaplen"] > 0
    assert capture["snaplen_note"] is None


def test_capture_section_has_snaplen_for_pcapng_fixture(tmp_path):
    result = _run_analyze_path(FIXTURE_WRITE_PCAPNG, tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    capture = analysis["capture"]
    assert isinstance(capture["snaplen"], int)
    assert capture["snaplen"] > 0
    assert capture["snaplen_note"] is None


# --- REPORT-01/ASSET-01: sekcja Inwentarz w report.md (plan 03-01, Task 1) ---


def test_report_markdown_has_eight_sections_with_macierz_after_inwentarz(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    from wayside.report import SECTIONS

    headers = re.findall(r"^## (.+)$", report_text, flags=re.MULTILINE)
    assert headers == list(SECTIONS)
    assert len(SECTIONS) == 8
    assert SECTIONS.index("Asset inventory") == SECTIONS.index("Methodology") + 1
    assert SECTIONS.index("Communication matrix") == SECTIONS.index("Asset inventory") + 1


def test_report_markdown_inwentarz_section_carries_both_hosts_and_provenance(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    inwentarz_start = report_text.index("## Asset inventory")
    ograniczenia_start = report_text.index("## Limitations")
    inwentarz_section = report_text[inwentarz_start:ograniczenia_start]

    assert "192.0.2.10" in inwentarz_section
    assert "192.0.2.20" in inwentarz_section
    assert "02:00:00:00:00:01" in inwentarz_section
    assert "02:00:00:00:00:02" in inwentarz_section
    assert "observed" in inwentarz_section


def test_report_markdown_zakres_section_carries_window_and_snaplen(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "Snaplen" in zakres_section
    assert "Capture time window" in zakres_section


def test_report_markdown_zakres_section_names_recognized_protocol_from_data(tmp_path):
    """PROTO-05: sekcja Zakres wymienia protokol faktycznie rozpoznany w tym
    zrzucie, budowany z `analysis["protocol_events"]`, nie z zamknietej listy
    stalych (04-RESEARCH.md, Pitfall 4)."""
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "modbus-tcp" in zakres_section


def test_report_markdown_zakres_section_names_no_protocol_recognized_for_empty_dump(tmp_path):
    """Zrzut bez ani jednego zdarzenia protokolu dostaje zdanie o braku
    rozpoznania, nie zdanie o zerowej liczbie protokolow (Pitfall 4)."""
    result = _run_analyze_path(FIXTURE_EMPTY_HEADER, tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "No application protocol was recognised in this capture" in zakres_section


def test_report_markdown_zakres_section_no_longer_claims_single_protocol_exclusivity(tmp_path):
    """Regresja Pitfall 4: sekcja Zakres nie twierdzi, ze analiza obejmuje
    wylacznie jeden protokol - bez tego testu twierdzenie wraca przy
    nastepnej edycji szablonu."""
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "covers only the protocol" not in zakres_section


# --- INGEST-05: zrzut uszkodzony strukturalnie, rozny od zrzutu obcietego ---
# (plan 03-03, Task 1)


def test_corrupted_record_length_exits_with_corrupt_code_and_no_artifacts(tmp_path):
    result = _run_analyze_path(FIXTURE_CORRUPTED_RECORD_LENGTH, tmp_path)
    assert result.returncode == 5, result.stdout + result.stderr
    assert "corrupt" in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_truncated_still_exits_with_truncated_code_after_corrupt_introduced(tmp_path):
    # Regresja: przeklasyfikowanie trzech warunkow na CaptureCorruptError nie
    # przesuwa sciezki bledu obciecia strumienia (Z-11).
    result = _run_analyze_path(FIXTURE_TRUNCATED_RECORD, tmp_path)
    assert result.returncode == 3, result.stdout + result.stderr

    result_pcapng = _run_analyze_path(FIXTURE_TRUNCATED_BLOCK, tmp_path)
    assert result_pcapng.returncode == 3, result_pcapng.stdout + result_pcapng.stderr


def test_unrecognized_magic_still_exits_with_unsupported_format_code_after_corrupt_introduced(
    tmp_path,
):
    bad_file = tmp_path / "not_a_capture.bin"
    bad_file.write_bytes(b"NOTAMAGIC" + b"\x00" * 20)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    result = _run_analyze_path(str(bad_file), out_dir)
    assert result.returncode == 4, result.stdout + result.stderr


# --- Output encoding: the gate for the defect the first real CI run on a
# machine with a foreign codepage revealed --------------------------------


def _vendor_probe_prefix_with_non_ascii_name() -> tuple[str, str]:
    """The first OUI prefix, in sorted order, whose vendor name carries a
    character outside ASCII, together with that name.

    Chosen FROM THE TABLE the pipeline reads, never written into the test by
    hand - the IEEE registry gets refreshed, and a hard-coded name would turn
    a refresh into a test failure with no defect behind it (the
    `tests/test_oui.py::_write_probe_capture` pattern).
    """
    table = load_oui_table()
    for prefix in sorted(table):
        name = table[prefix]
        if any(ord(ch) > 127 for ch in name):
            return prefix, name
    raise AssertionError(
        "The committed OUI table carries no vendor name outside ASCII - this "
        "test has nothing to assert on and its subject has to be revisited."
    )


def _write_non_ascii_vendor_capture(path: Path, mac: str) -> None:
    """One Modbus/TCP packet from a host whose MAC prefix resolves to a
    vendor name outside ASCII - the same shape as
    `tests/test_oui.py::_write_probe_capture`, built in a temporary
    directory rather than added to `tests/fixtures/`."""
    import wayside.pcap  # noqa: F401  - scapy cache isolation BEFORE layers

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    payload = bytes.fromhex("0001000000060106000000ff")
    packet = (
        Ether(src=mac, dst="02:00:00:00:00:07")
        / IP(src="192.0.2.40", dst="192.0.2.41")
        / TCP(sport=502, dport=50500, flags="PA")
        / payload
    )
    wrpcap(str(path), [packet])


def test_cli_emits_non_ascii_as_characters_under_foreign_environment_encoding(
    tmp_path,
):
    """Tool output carries a character outside ASCII AS A CHARACTER, not as
    an escape sequence, even when the environment encoding does not cover it.

    Python sets `sys.stderr.errors` to `backslashreplace`, so on a machine
    with an encoding that lacks the character (cp1252 on English Windows, and
    the CI runner too) it came out as a literal backslash-u sequence. Output
    the user cannot read is not output, and the README promises the tool
    works on Windows 11 with no extra configuration.

    The subject of this gate survived the move of the whole report to
    English. What carried the character then was Polish prose; what carries
    it now is a vendor name from the IEEE OUI registry, which holds names
    from across Europe and Asia - the defect and the code that fixes it
    (`cli._force_utf8_output`) are unchanged, only the source of the
    character is different.
    """
    prefix, expected_name = _vendor_probe_prefix_with_non_ascii_name()
    mac = ":".join(prefix[i : i + 2] for i in range(0, len(prefix), 2)) + ":11:22:33"
    capture = tmp_path / "non_ascii_vendor.pcap"
    _write_non_ascii_vendor_capture(capture, mac)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            str(capture),
            "--out-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )

    assert result.returncode == 0, result.stdout + result.stderr

    report_text = (out_dir / "report.md").read_text(encoding="utf-8")
    assert expected_name in report_text
    assert "\\u" not in report_text


# --- INGEST-03: ostrzezenie o ramkach ucietych przez snaplen (plan 03-03, Task 1) ---


def test_snaplen_truncation_produces_named_warning(tmp_path):
    result = _run_analyze_path(FIXTURE_SNAPLEN_TRUNCATED, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "54" in result.stderr
    assert "falsified" in result.stderr

    analysis = _load_analysis(tmp_path)
    capture = analysis["capture"]
    assert capture["snaplen_truncated_packet_count"] == 2
    assert capture["snaplen_truncated_first_packet_number"] == 1


def test_baseline_fixture_has_zero_snaplen_truncated_packets(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    capture = analysis["capture"]
    assert capture["snaplen_truncated_packet_count"] == 0
    assert capture["snaplen_truncated_first_packet_number"] is None


def test_two_runs_on_snaplen_truncated_fixture_give_byte_identical_analysis_json(tmp_path):
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    result_a = _run_analyze_path(FIXTURE_SNAPLEN_TRUNCATED, out_a)
    result_b = _run_analyze_path(FIXTURE_SNAPLEN_TRUNCATED, out_b)
    assert result_a.returncode == 0, result_a.stderr
    assert result_b.returncode == 0, result_b.stderr

    assert (out_a / "analysis.json").read_bytes() == (out_b / "analysis.json").read_bytes()


def test_report_zakres_section_states_snaplen_truncated_frame_count(tmp_path):
    result = _run_analyze_path(FIXTURE_SNAPLEN_TRUNCATED, tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "Frames truncated by snaplen: 2" in zakres_section


# --- INGEST-04: ostrzezenie o oknie zrzutu krotszym niz prog wobec ---------
# --- zmierzonego odstepu odpytywania (plan 03-03, Task 3) ------------------


def test_poll_cycle_short_window_produces_coverage_warning_with_both_numbers(tmp_path):
    result = _run_analyze_path(FIXTURE_POLL_CYCLE_SHORT_WINDOW, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "5.0" in result.stderr
    assert "5.01" in result.stderr

    analysis = _load_analysis(tmp_path)
    cycles = analysis["coverage"]["polling_cycles"]
    assert len(cycles) == 1
    assert cycles[0]["measured_cycle_s"] == 5.0
    assert cycles[0]["request_count"] == 2


def test_poll_cycle_full_window_produces_no_cycle_warning(tmp_path):
    # Ta polowa jest ta, bez ktorej warunek zawsze prawdziwy przeszedlby
    # niezauwazony: okno obejmujace wiele powtorzen cyklu NIE zapala
    # ostrzezenia o odstepie miedzy zadaniami.
    result = _run_analyze_path(FIXTURE_POLL_CYCLE_FULL_WINDOW, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "odstep miedzy" not in result.stderr


def test_empty_valid_header_report_inwentarz_section_states_no_host(tmp_path):
    result = _run_analyze_path(FIXTURE_EMPTY_HEADER, tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    inwentarz_start = report_text.index("## Asset inventory")
    ograniczenia_start = report_text.index("## Limitations")
    inwentarz_section = report_text[inwentarz_start:ograniczenia_start]

    assert inwentarz_section.strip() != ""


# --- PROTO-03: Modbus RTU tunelowany po TCP rozdzielony strukturalnie od ---
# --- protocol_events, zero findingow (plan 03-04, Task 3) ------------------


def test_rtu_over_tcp_fixture_has_two_low_confidence_events_and_empty_protocol_events(
    tmp_path,
):
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    analysis = _load_analysis(tmp_path)

    assert len(analysis["low_confidence_events"]) == 2
    assert analysis["protocol_events"] == []


def test_rtu_over_tcp_fixture_has_empty_findings(tmp_path):
    # To jest polowa, bez ktorej rozdzielenie strukturalne nie ma dowodu:
    # jesli ktos kiedykolwiek przepnie zdarzenia o niskiej pewnosci do
    # protocol_events, ten test zaczerwieni sie natychmiast, a test na sama
    # dlugosc listy low_confidence_events przeszedlby dalej.
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    analysis = _load_analysis(tmp_path)
    assert analysis["findings"] == []


def test_rtu_over_tcp_low_confidence_events_carry_protocol_confidence_and_basis(tmp_path):
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    analysis = _load_analysis(tmp_path)

    for event in analysis["low_confidence_events"]:
        assert event["protocol"] == "modbus-rtu-over-tcp"
        assert event["confidence"] == "low"
        assert event["basis"] == "crc16-modbus-match"


def test_baseline_fixture_has_empty_low_confidence_events_and_two_protocol_events(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    assert analysis["low_confidence_events"] == []
    assert len(analysis["protocol_events"]) == 2


def test_rtu_over_tcp_report_zakres_section_states_low_confidence_count(tmp_path):
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    zakres_start = report_text.index("## Scope")
    metodyka_start = report_text.index("## Methodology")
    zakres_section = report_text[zakres_start:metodyka_start]

    assert "Events recognised with low confidence" in zakres_section
    assert "2" in zakres_section


def test_rtu_over_tcp_report_ograniczenia_section_names_possible_false_match(tmp_path):
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    ograniczenia_start = report_text.index("## Limitations")
    findingi_start = report_text.index("## Findings")
    ograniczenia_section = report_text[ograniczenia_start:findingi_start]

    assert "false checksum match" in ograniczenia_section


def test_baseline_report_ograniczenia_section_lacks_false_match_sentence(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    ograniczenia_start = report_text.index("## Limitations")
    findingi_start = report_text.index("## Findings")
    ograniczenia_section = report_text[ograniczenia_start:findingi_start]

    assert "false checksum match" not in ograniczenia_section


def test_two_runs_on_rtu_over_tcp_fixture_give_byte_identical_analysis_json(tmp_path):
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    result_a = _run_analyze_path(FIXTURE_RTU_OVER_TCP, out_a)
    result_b = _run_analyze_path(FIXTURE_RTU_OVER_TCP, out_b)
    assert result_a.returncode == 0, result_a.stderr
    assert result_b.returncode == 0, result_b.stderr

    assert (out_a / "analysis.json").read_bytes() == (out_b / "analysis.json").read_bytes()


# --- ASSET-02: pole oui_vendor - inwentarz, raport, ostrzezenie o braku tabeli
# (plan 03-05, Task 2) -------------------------------------------------------


def test_baseline_fixture_assets_carry_oui_vendor_key_with_provenance(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    for host in analysis["assets"]:
        assert "oui_vendor" in host
        assert host["oui_vendor"]["provenance"] in (
            "not-derivable-passively",
            "inferred:oui-lookup",
        )


def test_report_markdown_inwentarz_section_carries_producent_bullet(tmp_path):
    # Adresy MAC fixture'ow tego projektu sa lokalnie administrowane
    # (zalozenie Z-03/gen_fixtures.py) - nie maja dopasowania w rejestrze
    # IEEE niezaleznie od tego, czy tabela lezy w drzewie (Task 4, `<action>`:
    # "producent pozostanie not determined takze z pelna tabela"). Ten test jest
    # wiec bezpieczny wobec kazdego rozstrzygniecia checkpointu Task 3.
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    inwentarz_start = report_text.index("## Asset inventory")
    ograniczenia_start = report_text.index("## Limitations")
    inwentarz_section = report_text[inwentarz_start:ograniczenia_start]

    assert "Vendor" in inwentarz_section
    assert "not determined" in inwentarz_section
    assert "not-derivable-passively" in inwentarz_section


def test_two_runs_on_baseline_fixture_give_byte_identical_analysis_json_with_oui_vendor(
    tmp_path,
):
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    result_a = _run_analyze(out_a)
    result_b = _run_analyze(out_b)
    assert result_a.returncode == 0, result_a.stderr
    assert result_b.returncode == 0, result_b.stderr

    assert (out_a / "analysis.json").read_bytes() == (out_b / "analysis.json").read_bytes()


def test_missing_oui_table_gives_named_warning_and_analyze_still_succeeds(tmp_path, monkeypatch):
    # Robustne wobec obu rozstrzygniec checkpointu Task 3 tego planu: zamiast
    # polegac na faktycznej (nie)obecnosci src/wayside/assets/oui_table.tsv
    # na dysku w chwili uruchomienia testu, ten test wymusza OuiTableError
    # przez monkeypatch na wayside.pipeline.oui.load_oui_table - dokladnie
    # droga, ktora Task 2 tego planu nazywa wprost jako zapasowa, gdyby
    # tabela juz lezala w drzewie po Task 4. Wywoluje pipeline.analyze
    # bezposrednio (nie przez subprocess CLI), bo monkeypatch nie przechodzi
    # granicy procesu.
    from wayside import pipeline as pipeline_module

    def _raise_oui_table_error(path=None):
        raise pipeline_module.oui.OuiTableError(
            "tabela producentow nieobecna (wymuszone testem, Task 2 plan 03-05)"
        )

    monkeypatch.setattr(pipeline_module.oui, "load_oui_table", _raise_oui_table_error)

    result = pipeline_module.analyze(
        REPO_ROOT / FIXTURE_RELATIVE,
        out_dir=tmp_path,
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert any("The OUI vendor table" in warning for warning in result.warnings)
    assert all(
        host["oui_vendor"] == {"value": None, "provenance": "not-derivable-passively"}
        for host in result.analysis["assets"]
    )


# --- Brama z wieloma Unit ID i rola w raporcie (plan 03-06, Task 3) ----------


def test_gateway_fixture_report_names_probable_gateway_with_device_count(tmp_path):
    result = _run_analyze_path(FIXTURE_GATEWAY, tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    gateway_rows = [
        line for line in report_text.splitlines() if line.startswith("- Gateway:")
    ]
    named = [line for line in gateway_rows if "probable gateway" in line]

    # Dwa hosty, ale tylko jeden z nich wystawia wiele wartosci Unit ID -
    # zdanie o bramie ma paść dokladnie raz, nie przy kazdym wierszu.
    assert len(gateway_rows) == 2
    assert len(named) == 1
    assert "3" in named[0]


def test_baseline_fixture_report_never_names_a_probable_gateway(tmp_path):
    """Druga polowa bramki: bez niej zdanie renderowane bezwarunkowo
    przeszlo by test wyzej."""
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert "probable gateway" not in report_text


def test_gateway_fixture_report_host_block_carries_all_five_new_rows(tmp_path):
    result = _run_analyze_path(FIXTURE_GATEWAY, tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    for label in ("- Unit ID sub-addresses:", "- Gateway:", "- Role:", "- Role evidence:", "- Role confidence:"):
        assert label in report_text


def test_gateway_fixture_analysis_has_two_assets_with_unit_ids_and_gateway(tmp_path):
    result = _run_analyze_path(FIXTURE_GATEWAY, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = _load_analysis(tmp_path)
    assert len(analysis["assets"]) == 2

    server = next(
        entry for entry in analysis["assets"] if entry["ip"]["value"] == "192.0.2.30"
    )
    assert server["unit_ids"] == {"value": [1, 2, 3], "provenance": "observed"}
    assert server["gateway"] == {
        "value": True,
        "provenance": "inferred:multiple-unit-ids",
    }


def test_two_runs_on_gateway_fixture_give_byte_identical_analysis_json(tmp_path):
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    result_a = _run_analyze_path(FIXTURE_GATEWAY, out_a)
    result_b = _run_analyze_path(FIXTURE_GATEWAY, out_b)
    assert result_a.returncode == 0, result_a.stderr
    assert result_b.returncode == 0, result_b.stderr

    assert (out_a / "analysis.json").read_bytes() == (out_b / "analysis.json").read_bytes()


# --- Macierz komunikacji w analysis.json i w raporcie (plan 03-07, Task 2) ---

FIXTURE_HANDSHAKE = "tests/fixtures/pcap/modbus_tcp_handshake.pcap"


def test_handshake_fixture_matrix_carries_observed_initiator(tmp_path):
    result = _run_analyze_path(FIXTURE_HANDSHAKE, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = _load_analysis(tmp_path)
    assert len(analysis["comm_matrix"]) == 1
    row = analysis["comm_matrix"][0]

    assert row["initiator"] == {"value": "192.0.2.10:50400", "provenance": "observed"}
    assert row["direction"]["provenance"] == "observed"


def test_handshake_fixture_matrix_packet_count_exceeds_conversations_packet_count(tmp_path):
    result = _run_analyze_path(FIXTURE_HANDSHAKE, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = _load_analysis(tmp_path)

    assert analysis["comm_matrix"][0]["packet_count"]["value"] == 5
    assert analysis["conversations"][0]["packet_count"] == 2


def test_fixture_without_handshake_matrix_has_null_initiator(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr

    row = _load_analysis(tmp_path)["comm_matrix"][0]

    assert row["initiator"] == {"value": None, "provenance": "not-derivable-passively"}
    assert row["direction"]["provenance"] == "inferred:first-observed-sender"


def test_rtu_over_tcp_fixture_matrix_row_carries_tunnel_protocol(tmp_path):
    result = _run_analyze_path(FIXTURE_RTU_OVER_TCP, tmp_path)
    assert result.returncode == 0, result.stderr

    row = _load_analysis(tmp_path)["comm_matrix"][0]

    assert row["protocol"]["value"] == "modbus-rtu-over-tcp"


def test_report_has_macierz_komunikacji_section_with_a_table(tmp_path):
    result = _run_analyze_path(FIXTURE_HANDSHAKE, tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    assert "## Communication matrix" in report_text
    assert "| Session | Source | Target | Direction | Protocol |" in report_text
    assert "192.0.2.10:50400" in report_text


def test_two_runs_on_handshake_fixture_give_byte_identical_analysis_json(tmp_path):
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    result_a = _run_analyze_path(FIXTURE_HANDSHAKE, out_a)
    result_b = _run_analyze_path(FIXTURE_HANDSHAKE, out_b)
    assert result_a.returncode == 0, result_a.stderr
    assert result_b.returncode == 0, result_b.stderr

    assert (out_a / "analysis.json").read_bytes() == (out_b / "analysis.json").read_bytes()


# --- FLOW-03/REPORT-02: sekcja ograniczen w pelnym przebiegu (plan 03-07, Task 3) ---


def test_limitations_section_carries_run_numbers_and_undetermined_field_rows(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    section = report_text.split("## Limitations", 1)[1].split("\n## ", 1)[0]

    assert "Scope of this run" in section
    assert "addresses observed 2" in section
    assert "sessions with payload 1" in section
    assert "field `" in section
    assert " entries" in section


def test_report_from_every_fixture_makes_no_completeness_claim(tmp_path):
    from wayside.flow import COMPLETENESS_CLAIM_TERMS

    for index, fixture in enumerate(
        (FIXTURE_RELATIVE, FIXTURE_RTU_OVER_TCP, FIXTURE_GATEWAY, FIXTURE_HANDSHAKE)
    ):
        out_dir = tmp_path / str(index)
        result = _run_analyze_path(fixture, out_dir)
        assert result.returncode == 0, result.stderr

        text = (out_dir / "report.md").read_text(encoding="utf-8").lower()
        for term in COMPLETENESS_CLAIM_TERMS:
            assert term.lower() not in text, (fixture, term)


def test_limitations_section_carries_every_vantage_point_sentence(tmp_path):
    from wayside.flow import VANTAGE_POINT_LIMITATIONS

    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    for sentence in VANTAGE_POINT_LIMITATIONS:
        assert sentence in report_text
