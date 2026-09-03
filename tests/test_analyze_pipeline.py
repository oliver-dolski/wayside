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
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_TRUNCATED_RECORD = "tests/fixtures/pcap/truncated_mid_record.pcap"
FIXTURE_TRUNCATED_BLOCK = "tests/fixtures/pcap/truncated_mid_block.pcapng"
FIXTURE_EMPTY_HEADER = "tests/fixtures/pcap/empty_valid_header.pcap"
FIXTURE_WRITE_PCAPNG = "tests/fixtures/pcap/modbus_write_single_register.pcapng"

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
        text=True,
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


def test_analysis_json_has_exactly_one_finding_with_expected_evidence(tmp_path):
    result = _run_analyze(tmp_path)
    assert result.returncode == 0, result.stderr
    analysis = _load_analysis(tmp_path)

    findings = analysis["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["check_id"] == "modbus-unauthenticated-write"
    assert finding["evidence"]["packet_number"] == 1
    assert finding["evidence"]["session_id"] == 0

    standard_ref = finding["standard_refs"][0]
    assert standard_ref["standard"] == "IEC-62443-3-3"
    assert standard_ref["clause"] == "SR 1.1"
    assert standard_ref["verified"] is False


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

    assert "Dowod: pakiet nr 1, sesja nr 0" in report_text
    assert "SR 1.1" in report_text
    assert "PROWIZORYCZNE" in report_text
    assert "NIEZWERYFIKOWANE" in report_text


# --- D-01: zrzut obciety konczy sie kodem != 0, bez tracebacku, bez artefaktow ---


def test_truncated_mid_record_pcap_exits_with_truncated_code_and_no_artifacts(tmp_path):
    result = _run_analyze_path(FIXTURE_TRUNCATED_RECORD, tmp_path)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "obciety" in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_truncated_mid_block_pcapng_exits_with_truncated_code(tmp_path):
    result = _run_analyze_path(FIXTURE_TRUNCATED_BLOCK, tmp_path)
    assert result.returncode == 3, result.stdout + result.stderr
    assert "obciety" in result.stderr
    assert "Traceback (most recent call last)" not in result.stderr
    assert list(tmp_path.iterdir()) == []


# --- D-01: zrzut strukturalnie pusty konczy sie kodem 0, z jawnym ostrzezeniem ---


def test_empty_valid_header_exits_zero_with_warning_and_empty_lists(tmp_path):
    result = _run_analyze_path(FIXTURE_EMPTY_HEADER, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Ostrzezenie:" in result.stderr

    analysis = _load_analysis(tmp_path)
    assert analysis["conversations"] == []
    assert analysis["protocol_events"] == []
    assert analysis["findings"] == []

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    from wayside.report import SECTIONS

    headers = re.findall(r"^## (.+)$", report_text, flags=re.MULTILINE)
    assert headers == list(SECTIONS)
    assert "Brak findingow w tym przebiegu." in report_text

    ograniczenia_start = report_text.index("## Ograniczenia")
    findingi_start = report_text.index("## Findingi")
    ograniczenia_section = report_text[ograniczenia_start:findingi_start]
    assert "nie zawiera ani jednego pakietu" in ograniczenia_section


# --- D-01/INGEST-01: fixture pcapng przechodzi caly potok jak fixture klasyczny ---


def test_write_fixture_pcapng_produces_same_finding_as_classic_pcap(tmp_path):
    result = _run_analyze_path(FIXTURE_WRITE_PCAPNG, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = _load_analysis(tmp_path)
    findings = analysis["findings"]
    assert len(findings) == 1
    assert findings[0]["check_id"] == "modbus-unauthenticated-write"


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
