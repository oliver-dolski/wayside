"""Test integracyjny INGEST-01/REPORT-04: pelny potok od pliku pcap do dwoch
artefaktow (`analysis.json`, `report.md`), pokrywajacy punkty z bloku
`<behavior>` zadania 1 planu 02-01.

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

_GENERATED_AT_KEY_PATTERN = re.compile(r"generat|wygenerowan", re.IGNORECASE)


def _run_analyze(out_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


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
