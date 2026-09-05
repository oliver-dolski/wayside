"""Bramka findingu za protokol jawnotekstowy i grupowania po sesji plus
protokole (CHECK-03).

Wieksza czesc testow jest testem jednostkowym czystej funkcji `evaluate` nad
modelem budowanym recznie w tym pliku, bez zadnego pliku pcap - evaluator z
definicji widzi wylacznie `analysis["protocol_events"]`, nigdy pakietow
(02-RESEARCH.md, Anti-Pattern 1). `_event()` jest wspolna funkcja pomocnicza
budujaca jedno zdarzenie protokolu, wzorowana na `tests/test_checks_modbus.py`.

`test_cleartext_fixture_yields_three_findings` i pokrewne sa testami
integracyjnymi w podprocesie, tak samo jak `tests/test_checks_modbus.py`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from wayside import risk
from wayside.checks import engine
from wayside.checks.cleartext_protocol.cleartext_protocol import (
    CLEARTEXT_PROTOCOLS,
    evaluate,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CLEARTEXT = "tests/fixtures/pcap/cleartext_telnet_ftp_http.pcap"
FIXTURE_MODBUS_BASE = "tests/fixtures/pcap/modbus_write_single_register.pcap"


def _event(
    *,
    packet_number: int,
    session_id: int,
    protocol: str = "telnet",
    direction: str = "request",
    **overrides,
) -> dict:
    """Buduje jedno zdarzenie protokolu w ksztalcie zwracanym przez
    `dissect()` po wzbogaceniu z manifestu przez rejestr. Pola nieistotne
    dla `evaluate` maja wartosci domyslne stale, zeby kazdy przypadek
    testowy roznil sie tylko tym, co faktycznie bada."""
    base = {
        "packet_number": packet_number,
        "session_id": session_id,
        "direction": direction,
        "basis": "telnet-iac-negotiation",
        "src_ip": "192.0.2.10",
        "dst_ip": "192.0.2.20",
        "timestamp": 0.0,
        "protocol": protocol,
        "confidence": "high",
    }
    base.update(overrides)
    return base


# --- evaluate: brak klucza zdarzen protokolu podnosi KeyError ---------------


def test_evaluate_raises_keyerror_without_protocol_events_key():
    with pytest.raises(KeyError):
        evaluate({})


# --- evaluate: lista pusta, bez wyjatku ------------------------------------


def test_evaluate_returns_empty_list_for_no_events():
    assert evaluate({"protocol_events": []}) == []


# --- evaluate: jedno zdarzenie protokolu jawnotekstowego daje jeden wynik --


def test_evaluate_returns_one_finding_for_one_cleartext_event():
    analysis = {"protocol_events": [_event(packet_number=1, session_id=0, protocol="telnet")]}

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: dziesiec zdarzen tej samej sesji i protokolu, jeden wynik ---


def test_evaluate_ten_events_same_session_same_protocol_yields_one_finding():
    analysis = {
        "protocol_events": [
            _event(packet_number=n, session_id=0, protocol="http") for n in range(1, 11)
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: dwa protokoly jawnotekstowe w jednej sesji, dwa wyniki ------


def test_evaluate_two_cleartext_protocols_same_session_yields_two_findings():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0, protocol="telnet"),
            _event(packet_number=2, session_id=0, protocol="ftp"),
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 2
    evidences = {(f["evidence"]["packet_number"], f["evidence"]["session_id"]) for f in findings}
    assert evidences == {(1, 0), (2, 0)}


# --- evaluate: zdarzenia poza lista protokolow jawnotekstowych, lista pusta


def test_evaluate_returns_empty_list_for_non_cleartext_protocol_events():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0, protocol="modbus-tcp"),
        ]
    }

    assert evaluate(analysis) == []


# --- evaluate: dowod jest PIERWSZYM zdarzeniem pary w kolejnosci wejscia ---


def test_evidence_is_first_event_of_pair_in_input_order():
    analysis = {
        "protocol_events": [
            _event(packet_number=5, session_id=0, protocol="http"),
            _event(packet_number=1, session_id=0, protocol="http"),
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 5, "session_id": 0}


# --- evaluate: wywolanie dwa razy daje identyczna liste w tej samej kolejnosci


def test_evaluate_called_twice_returns_identical_ordered_list():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0, protocol="telnet"),
            _event(packet_number=2, session_id=1, protocol="ftp"),
            _event(packet_number=3, session_id=2, protocol="http"),
        ]
    }

    first = evaluate(analysis)
    second = evaluate(analysis)

    assert first == second


# --- CLEARTEXT_PROTOCOLS: zbior trzech identyfikatorow ----------------------


def test_cleartext_protocols_is_exactly_three_ids():
    assert CLEARTEXT_PROTOCOLS == frozenset({"telnet", "ftp", "http"})


# --- Zero importu scapy/decode/protocols ------------------------------------


def test_evaluator_module_imports_no_decoding_or_dissector_module():
    import ast

    module_path = (
        REPO_ROOT
        / "src"
        / "wayside"
        / "checks"
        / "cleartext_protocol"
        / "cleartext_protocol.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)] + [
        alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names
    ]
    bad = [
        m
        for m in modules
        if m.startswith("scapy") or m.startswith("wayside.decode") or m.startswith("wayside.protocols")
    ]
    assert not bad, bad


# --- Testy integracyjne: fixture jawnotekstowy i fixture bazowy Modbusa ----


def _analyze(fixture_relative: str, out_dir: Path) -> tuple[dict, str]:
    result = subprocess.run(
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
    assert result.returncode == 0, result.stderr
    analysis = json.loads((out_dir / "analysis.json").read_text(encoding="utf-8"))
    report_text = (out_dir / "report.md").read_text(encoding="utf-8")
    return analysis, report_text


def test_cleartext_fixture_yields_exactly_three_findings(tmp_path):
    analysis, _ = _analyze(FIXTURE_CLEARTEXT, tmp_path)

    findings = [f for f in analysis["findings"] if f["check_id"] == "cleartext-protocol"]
    assert len(findings) == 3


def test_cleartext_fixture_findings_carry_standard_reference_with_nonempty_edition(tmp_path):
    analysis, _ = _analyze(FIXTURE_CLEARTEXT, tmp_path)

    findings = [f for f in analysis["findings"] if f["check_id"] == "cleartext-protocol"]
    for finding in findings:
        assert finding["severity"] == "medium"
        assert finding["risk"] == risk.severity_to_risk("medium")
        refs = finding["standard_refs"]
        assert len(refs) == 1
        assert refs[0]["standard"] == "IEC-62443-3-3"
        assert refs[0]["clause"] == "SR 4.1"
        assert refs[0]["edition"]
        assert refs[0]["verified"] is False


def test_modbus_base_fixture_yields_zero_cleartext_findings(tmp_path):
    analysis, _ = _analyze(FIXTURE_MODBUS_BASE, tmp_path)

    findings = [f for f in analysis["findings"] if f["check_id"] == "cleartext-protocol"]
    assert findings == []


def test_rendered_report_carries_check_id_and_unverified_marker(tmp_path):
    _, report_text = _analyze(FIXTURE_CLEARTEXT, tmp_path)

    assert "cleartext-protocol" in report_text
    assert "PROWIZORYCZNE, NIEZWERYFIKOWANE" in report_text


def test_discover_checks_includes_cleartext_protocol():
    ids = sorted(c.spec["id"] for c in engine.discover_checks())
    assert ids == ["cleartext-protocol", "modbus-unauthenticated-write"]
