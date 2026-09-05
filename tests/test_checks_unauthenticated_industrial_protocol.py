"""Bramka findingu za uzycie protokolu przemyslowego bez mechanizmu
uwierzytelnienia i rozdzielenia od findingu za zapis (CHECK-05).

Wieksza czesc testow jest testem jednostkowym czystej funkcji `evaluate` nad
modelem budowanym recznie w tym pliku, bez zadnego pliku pcap - evaluator z
definicji widzi wylacznie `analysis["protocol_events"]`, nigdy pakietow
(02-RESEARCH.md, Anti-Pattern 1). `_event()` jest wspolna funkcja pomocnicza
budujaca jedno zdarzenie protokolu, wzorowana na
`tests/test_checks_cleartext_protocol.py`.

Grupa druga (integracyjna, w podprocesie) jest tu NAJWAZNIEJSZA dla
Pitfall 9 z `04-RESEARCH.md`: przebieg na fixture zlozonym wylacznie z
odczytow daje dokladnie jeden finding tego checka i ZERO findingow checka za
zapis. To jest test, ktorego check zaimplementowany jako filtr na findingu
za zapis NIE przechodzi - dowod, ze CHECK-05 jest wlasnym, niezaleznym
warunkiem, nie deklaracja.
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
    """Buduje jedno zdarzenie protokolu w ksztalcie zwracanym przez
    `run_dissectors` po wzbogaceniu z manifestu przez rejestr. Pola
    nieistotne dla `evaluate` maja wartosci domyslne stale, zeby kazdy
    przypadek testowy roznil sie tylko tym, co faktycznie bada."""
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


# --- evaluate: zdarzenia wylacznie odczytu takze daja finding (brak filtra)


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


# --- evaluate: dowod jest PIERWSZYM zdarzeniem sesji w kolejnosci wejscia ---


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


# --- Evaluator nie odczytuje pola 'kind' ani razu ---------------------------


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
    """Dowod Pitfall 9: fixture bez ani jednej operacji zapisu daje finding
    tego checka i NIE daje findingu checka za zapis. Check zaimplementowany
    jako filtr na findingu za zapis nie przechodzi tego testu."""
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
    """Zdarzenia o pewnosci niskiej (Modbus RTU tunelowany po TCP) stoja
    poza `analysis["protocol_events"]` - trafiaja do `low_confidence_events`,
    ktorej ten evaluator nie widzi w ogole."""
    analysis = _analyze(FIXTURE_RTU_OVER_TCP, tmp_path)
    findings = [f for f in analysis["findings"] if f["check_id"] == CHECK_ID]

    assert findings == []


def test_finding_carries_standard_reference_and_configured_severity(tmp_path):
    analysis = _analyze(FIXTURE_READ_ONLY, tmp_path)
    finding = next(f for f in analysis["findings"] if f["check_id"] == CHECK_ID)

    assert finding["severity"] == "high"
    refs = finding["standard_refs"]
    # Od planu 04-05 kazdy finding niesie DWA powolania: IEC-62443-3-3
    # (pierwsze) i CLC/TS 50701 (drugie), w kolejnosci z pliku checka.
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
