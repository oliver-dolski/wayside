"""Bramka findingu za zapis do sterownika i kontraktu dowodu (CHECK-04, CHECK-06).

Wieksza czesc testow jest testem jednostkowym czystej funkcji `evaluate`
nad modelem budowanym recznie w tym pliku, bez zadnego pliku pcap - evaluator
z definicji widzi wylacznie `analysis["protocol_events"]`, nigdy pakietow
(02-RESEARCH.md, Anti-Pattern 1). `_event()` jest wspolna funkcja pomocnicza
budujaca jedno zdarzenie protokolu, zeby kazdy przypadek roznil sie tylko
lista zdarzen, a nie duplikowal ksztalt slownika.

`test_write_operation_finding` jest jedynym testem integracyjnym w tym pliku
i uruchamia CLI w podprocesie, tak samo jak `tests/test_cli_output_snapshot.py`
i `tests/test_analyze_pipeline.py`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from wayside.checks import engine
from wayside.checks.modbus.unauthenticated_write import evaluate
from wayside.model import Evidence

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"


def _event(*, packet_number: int, session_id: int, kind: str = "write", direction: str = "request", **overrides) -> dict:
    """Buduje jedno zdarzenie protokolu w ksztalcie `dataclasses.asdict(ModbusEvent)`.
    Pola nieistotne dla `evaluate` maja wartosci domyslne stale, zeby kazdy
    przypadek testowy roznil sie tylko tym, co faktycznie bada."""
    base = {
        "packet_number": packet_number,
        "session_id": session_id,
        "unit_id": 1,
        "transaction_id": 1,
        "function_code": 6,
        "function_name": "Write Single Register",
        "kind": kind,
        "direction": direction,
        "src_ip": "192.0.2.10",
        "dst_ip": "192.0.2.20",
    }
    base.update(overrides)
    return base


# --- evaluate: zdarzenie zapisu-zadania daje dokladnie jeden finding --------


def test_evaluate_returns_one_finding_for_write_request_event():
    analysis = {"protocol_events": [_event(packet_number=1, session_id=0)]}

    findings = evaluate(analysis)

    assert len(findings) == 1
    assert findings[0]["evidence"] == {"packet_number": 1, "session_id": 0}


# --- evaluate: zdarzenie odczytu nie daje findingu ---------------------------


def test_evaluate_returns_empty_list_for_read_event():
    analysis = {
        "protocol_events": [_event(packet_number=1, session_id=0, kind="read", direction="request")]
    }

    assert evaluate(analysis) == []


# --- evaluate: zdarzenie zapisu w kierunku odpowiedzi nie daje findingu -----


def test_evaluate_returns_empty_list_for_write_response_direction():
    analysis = {
        "protocol_events": [_event(packet_number=1, session_id=0, kind="write", direction="response")]
    }

    assert evaluate(analysis) == []


# --- evaluate: lista zdarzen pusta, bez wyjatku ------------------------------


def test_evaluate_returns_empty_list_for_no_events():
    assert evaluate({"protocol_events": []}) == []


# --- evaluate: brak klucza zdarzen protokolu podnosi KeyError ---------------


def test_evaluate_raises_keyerror_without_protocol_events_key():
    with pytest.raises(KeyError):
        evaluate({})


# --- evaluate: dowod niepusty -------------------------------------------------


def test_evaluate_finding_evidence_fields_are_nonempty():
    analysis = {"protocol_events": [_event(packet_number=3, session_id=2)]}

    finding = evaluate(analysis)[0]
    evidence = finding["evidence"]

    assert evidence["packet_number"] is not None
    assert evidence["session_id"] is not None
    assert evidence["packet_number"] == 3
    assert evidence["session_id"] == 2


# --- evaluate: dwa zdarzenia o tym samym numerze pakietu, dwa findingi ------


def test_evaluate_two_events_with_same_packet_number_yield_two_findings():
    analysis = {
        "protocol_events": [
            _event(packet_number=7, session_id=0, unit_id=1),
            _event(packet_number=7, session_id=0, unit_id=2),
        ]
    }

    findings = evaluate(analysis)

    assert len(findings) == 2
    assert findings[0]["evidence"] == {"packet_number": 7, "session_id": 0}
    assert findings[1]["evidence"] == {"packet_number": 7, "session_id": 0}


# --- run_checks: porzadek sortowania findingow -------------------------------


def test_run_checks_orders_findings_by_check_id_session_id_packet_number():
    checks = engine.discover_checks()
    analysis = {
        "protocol_events": [
            _event(packet_number=5, session_id=1),
            _event(packet_number=2, session_id=0),
            _event(packet_number=1, session_id=0),
        ]
    }

    findings = engine.run_checks(analysis, checks)
    keys = [
        (f["check_id"], f["evidence"]["session_id"], f["evidence"]["packet_number"])
        for f in findings
    ]

    assert keys == sorted(keys)
    assert keys == [
        ("modbus-unauthenticated-write", 0, 1),
        ("modbus-unauthenticated-write", 0, 2),
        ("modbus-unauthenticated-write", 1, 5),
    ]


# --- Evidence: brak pola na surowe bajty ladunku, wlasnosc typu (T-2-06) ----


def test_evidence_rejects_raw_payload_keyword():
    with pytest.raises(TypeError):
        Evidence(packet_number=1, session_id=0, payload=b"\x00\x01")


# --- Test integracyjny: fixture z zapisem daje jeden finding -----------------


def test_write_operation_finding(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    findings = analysis["findings"]
    assert len(findings) == 2

    finding = next(f for f in findings if f["check_id"] == "modbus-unauthenticated-write")
    assert finding["evidence"]["packet_number"] == 1
    assert finding["evidence"]["session_id"] == 0

    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Dowod: pakiet nr 1, sesja nr 0" in report_text
