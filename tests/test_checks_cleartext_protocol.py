"""Gate for the cleartext protocol finding and for grouping by session plus
protocol (CHECK-03).

Most of the tests are unit tests of the pure `evaluate` function over a model
built by hand in this file, without any pcap file - by definition the
evaluator sees only `analysis["protocol_events"]`, never packets
(02-RESEARCH.md, Anti-Pattern 1). `_event()` is the shared helper building one
protocol event, modelled on `tests/test_checks_modbus.py`.

`test_cleartext_fixture_yields_exactly_three_findings` and its relatives are
integration tests in a subprocess, exactly as in `tests/test_checks_modbus.py`.
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
    """Builds one protocol event in the shape returned by `dissect()` after the
    registry enriched it from the manifest. Fields irrelevant to `evaluate`
    carry constant defaults, so that every test case differs only in what it
    actually examines."""
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


# --- evaluate: a missing protocol events key raises KeyError ---------------


def test_evaluate_raises_keyerror_without_protocol_events_key():
    with pytest.raises(KeyError):
        evaluate({})


# --- evaluate: an empty list, without raising ------------------------------


def test_evaluate_returns_empty_list_for_no_events():
    assert evaluate({"protocol_events": []}) == []


# --- evaluate: one cleartext protocol event yields one finding -------------


def test_evaluate_returns_one_finding_for_one_cleartext_event():
    analysis = {"protocol_events": [_event(packet_number=1, session_id=0, protocol="telnet")]}

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: ten events of the same session and protocol, one finding ----


def test_evaluate_ten_events_same_session_same_protocol_yields_one_finding():
    analysis = {
        "protocol_events": [
            _event(packet_number=n, session_id=0, protocol="http") for n in range(1, 11)
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: two cleartext protocols in one session, two findings --------


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


# --- evaluate: events outside the cleartext protocol list, an empty list ---


def test_evaluate_returns_empty_list_for_non_cleartext_protocol_events():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0, protocol="modbus-tcp"),
        ]
    }

    assert evaluate(analysis) == []


# --- evaluate: the evidence is the FIRST event of the pair in input order --


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


# --- evaluate: calling it twice yields an identical list in the same order -


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


# --- CLEARTEXT_PROTOCOLS: a set of three identifiers -----------------------


def test_cleartext_protocols_is_exactly_three_ids():
    assert CLEARTEXT_PROTOCOLS == frozenset({"telnet", "ftp", "http"})


# --- Zero scapy/decode/protocols imports -----------------------------------


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


# --- Integration tests: the cleartext fixture and the base Modbus fixture --


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
        # Since plan 04-05 every finding carries TWO citations: IEC-62443-3-3
        # (first) and CLC/TS 50701 (second), in the order given in the check file.
        assert len(refs) == 2
        assert refs[0]["standard"] == "IEC-62443-3-3"
        assert refs[0]["clause"] == "SR 4.1"
        assert refs[0]["edition"]
        assert refs[0]["verified"] is False
        assert refs[1]["standard"] == "CLC/TS 50701"
        assert refs[1]["edition"] == "2023"
        assert refs[1]["verified"] is False


def test_modbus_base_fixture_yields_zero_cleartext_findings(tmp_path):
    analysis, _ = _analyze(FIXTURE_MODBUS_BASE, tmp_path)

    findings = [f for f in analysis["findings"] if f["check_id"] == "cleartext-protocol"]
    assert findings == []


def test_rendered_report_carries_check_id_and_unverified_marker(tmp_path):
    _, report_text = _analyze(FIXTURE_CLEARTEXT, tmp_path)

    assert "cleartext-protocol" in report_text
    assert "PROVISIONAL, UNVERIFIED" in report_text


def test_discover_checks_includes_cleartext_protocol():
    ids = sorted(c.spec["id"] for c in engine.discover_checks())
    assert ids == [
        "cleartext-protocol",
        "modbus-unauthenticated-write",
        "unauthenticated-industrial-protocol",
    ]
