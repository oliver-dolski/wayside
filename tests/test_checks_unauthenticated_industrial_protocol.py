"""Gate for the finding about the use of an industrial protocol without an
authentication mechanism, and for its separation from the write finding
(CHECK-05).

Most of the tests are unit tests of the pure `evaluate` function over a model
built by hand in this file, without any pcap file - by definition the
evaluator sees only `analysis["protocol_events"]`, never packets
(02-RESEARCH.md, Anti-Pattern 1). `_event()` is the shared helper building one
protocol event, modelled on `tests/test_checks_cleartext_protocol.py`.

The second group (integration, in a subprocess) is THE MOST IMPORTANT one here
for Pitfall 9 of `04-RESEARCH.md`: a run over a fixture made up of reads alone
yields exactly one finding of this check and ZERO findings of the write check.
That is the test a check implemented as a filter over the write finding does
NOT pass - proof that CHECK-05 is its own independent condition, not a
declaration.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from wayside.checks import engine
from wayside.checks.unauthenticated_industrial_protocol.unauthenticated_industrial_protocol import (
    UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS,
    evaluate,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_READ_ONLY = "tests/fixtures/pcap/modbus_read_only_session.pcap"
FIXTURE_MODBUS_BASE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_CLEARTEXT = "tests/fixtures/pcap/cleartext_telnet_ftp_http.pcap"
FIXTURE_RTU_OVER_TCP = "tests/fixtures/pcap/modbus_rtu_over_tcp.pcap"

CHECK_ID = "unauthenticated-industrial-protocol"
WRITE_CHECK_ID = "modbus-unauthenticated-write"


def _event(
    *,
    packet_number: int,
    session_id: int,
    protocol: str = "modbus-tcp",
    kind: str = "read",
    direction: str = "request",
    **overrides,
) -> dict:
    """Builds one protocol event in the shape returned by `run_dissectors`
    after the registry enriched it from the manifest. Fields irrelevant to
    `evaluate` carry constant defaults, so that every test case differs only
    in what it actually examines."""
    base = {
        "packet_number": packet_number,
        "session_id": session_id,
        "unit_id": 1,
        "transaction_id": 1,
        "function_code": 3,
        "function_name": "Read Holding Registers",
        "kind": kind,
        "direction": direction,
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


# --- evaluate: jedno zdarzenie o protokole ze zbioru daje jeden wynik ------


def test_evaluate_returns_one_finding_for_one_event_in_set():
    analysis = {"protocol_events": [_event(packet_number=1, session_id=0)]}

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: jedenascie zdarzen jednej sesji, jedno z zapisem, jeden wynik


def test_evaluate_eleven_events_one_session_one_write_yields_exactly_one_finding():
    events = [_event(packet_number=n, session_id=0, kind="read") for n in range(1, 11)]
    events.append(_event(packet_number=11, session_id=0, kind="write"))
    analysis = {"protocol_events": events}

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: read-only events yield a finding too (no filter) ------------


def test_evaluate_events_all_read_kind_still_yields_finding():
    analysis = {
        "protocol_events": [
            _event(packet_number=n, session_id=0, kind="read") for n in range(1, 4)
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: dwie sesje tego samego protokolu, dwa wyniki ------------------


def test_evaluate_two_sessions_same_protocol_yields_two_findings():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0),
            _event(packet_number=2, session_id=1),
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 2
    evidences = {(f["evidence"]["packet_number"], f["evidence"]["session_id"]) for f in findings}
    assert evidences == {(1, 0), (2, 1)}


# --- evaluate: protokol poza zbiorem, lista pusta ---------------------------


def test_evaluate_returns_empty_list_for_protocol_outside_set():
    analysis = {
        "protocol_events": [_event(packet_number=1, session_id=0, protocol="telnet")]
    }

    assert evaluate(analysis) == []


# --- evaluate: the evidence is the FIRST event of the session in input order ---


def test_evidence_is_first_event_of_session_in_input_order():
    analysis = {
        "protocol_events": [
            _event(packet_number=5, session_id=0),
            _event(packet_number=1, session_id=0),
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 5, "session_id": 0}


# --- evaluate: wywolanie dwa razy daje identyczna liste w tej samej kolejnosci


def test_evaluate_called_twice_returns_identical_ordered_list():
    analysis = {
        "protocol_events": [
            _event(packet_number=1, session_id=0),
            _event(packet_number=2, session_id=1),
            _event(packet_number=3, session_id=2),
        ]
    }

    first = evaluate(analysis)
    second = evaluate(analysis)

    assert first == second


# --- UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS: zbior jednego identyfikatora ----


def test_unauthenticated_industrial_protocols_is_exactly_one_id():
    assert UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS == frozenset({"modbus-tcp"})


# --- The evaluator never reads the 'kind' field ----------------------------


def test_evaluator_module_never_indexes_kind_field():
    module_path = (
        REPO_ROOT
        / "src"
        / "wayside"
        / "checks"
        / "unauthenticated_industrial_protocol"
        / "unauthenticated_industrial_protocol.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    subs = [
        n.slice.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
    ]
    assert "kind" not in subs, subs


# --- Zero importu scapy/decode/protocols ------------------------------------


def test_evaluator_module_imports_no_decoding_or_dissector_module():
    module_path = (
        REPO_ROOT
        / "src"
        / "wayside"
        / "checks"
        / "unauthenticated_industrial_protocol"
        / "unauthenticated_industrial_protocol.py"
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


# --- Testy integracyjne ------------------------------------------------------


def _analyze(fixture_relative: str, out_dir: Path) -> dict:
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
    return json.loads((out_dir / "analysis.json").read_text(encoding="utf-8"))


def test_read_only_fixture_yields_one_finding_this_check_and_zero_write_findings(tmp_path):
    """Proof of Pitfall 9: a fixture without a single write operation yields a
    finding of this check and does NOT yield a finding of the write check. A
    check implemented as a filter over the write finding does not pass this
    test."""
    analysis = _analyze(FIXTURE_READ_ONLY, tmp_path)
    findings = analysis["findings"]

    this_check = [f for f in findings if f["check_id"] == CHECK_ID]
    write_check = [f for f in findings if f["check_id"] == WRITE_CHECK_ID]

    assert len(this_check) == 1
    assert write_check == []


def test_modbus_base_fixture_yields_one_finding_each_of_two_checks(tmp_path):
    analysis = _analyze(FIXTURE_MODBUS_BASE, tmp_path)
    findings = analysis["findings"]

    this_check = [f for f in findings if f["check_id"] == CHECK_ID]
    write_check = [f for f in findings if f["check_id"] == WRITE_CHECK_ID]

    assert len(this_check) == 1
    assert len(write_check) == 1


def test_cleartext_fixture_yields_zero_findings_this_check(tmp_path):
    analysis = _analyze(FIXTURE_CLEARTEXT, tmp_path)
    findings = [f for f in analysis["findings"] if f["check_id"] == CHECK_ID]

    assert findings == []


def test_rtu_over_tcp_fixture_yields_zero_findings_this_check(tmp_path):
    """Low-confidence events (Modbus RTU tunnelled over TCP) stand outside
    `analysis["protocol_events"]` - they land in `low_confidence_events`,
    which this evaluator does not see at all."""
    analysis = _analyze(FIXTURE_RTU_OVER_TCP, tmp_path)
    findings = [f for f in analysis["findings"] if f["check_id"] == CHECK_ID]

    assert findings == []


def test_finding_carries_standard_reference_and_configured_severity(tmp_path):
    analysis = _analyze(FIXTURE_READ_ONLY, tmp_path)
    finding = next(f for f in analysis["findings"] if f["check_id"] == CHECK_ID)

    assert finding["severity"] == "high"
    refs = finding["standard_refs"]
    # Since plan 04-05 every finding carries TWO citations: IEC-62443-3-3
    # (first) and CLC/TS 50701 (second), in the order given in the check file.
    assert len(refs) == 2
    assert refs[0]["standard"] == "IEC-62443-3-3"
    assert refs[0]["edition"]
    assert refs[1]["standard"] == "CLC/TS 50701"
    assert refs[1]["edition"] == "2023"


def test_discover_checks_includes_unauthenticated_industrial_protocol():
    ids = sorted(c.spec["id"] for c in engine.discover_checks())
    assert ids == [
        "cleartext-protocol",
        "modbus-unauthenticated-write",
        "unauthenticated-industrial-protocol",
    ]
