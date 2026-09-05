"""Bramki maszynowe PROTO-01, PROTO-02 i PROTO-04 (plan 02-04).

`test_recognizes_non_standard_port` i `test_rejects_malformed_mbap` dowodza
rozpoznania po ksztalcie naglowka MBAP, nie po numerze portu (02-RESEARCH.md,
Pitfall 2): kazdy z nich ma pare test jednostkowy na `dissect_all` plus test
przez podproces CLI, zeby dowod szedl przez caly potok, nie tylko przez
warstwe protokolu w izolacji (kryterium 3 fazy). `test_function_code_classification`
dowodzi rozdzielenia kodow funkcji na czytajace i zapisujace wobec pelnej
tabeli wpisanej w tym pliku niezaleznie od `FUNCTION_CODE_KIND` - test
porownujacy slownik z samym soba nie dowodzilby niczego.

Sciezki fixture sa wzgledne wobec `REPO_ROOT` w wywolaniach CLI, tak samo
jak w `tests/test_cli_output_snapshot.py` i `tests/test_analyze_pipeline.py`.
"""

from __future__ import annotations

import json
import random
import struct
import subprocess
import sys
from pathlib import Path

from wayside import decode, pcap
from wayside.protocols.modbus_tcp import (
    MIN_ADU_LEN,
    MbapHeader,
    classify_function_code,
    dissect_all,
    validate_mbap,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NON_STANDARD_PORT = "tests/fixtures/pcap/modbus_write_non_standard_port.pcap"
FIXTURE_MALFORMED_MBAP = "tests/fixtures/pcap/modbus_malformed_mbap.pcap"

# Pelna oczekiwana tabela kodow funkcji, wpisana tu NIEZALEZNIE od
# `FUNCTION_CODE_KIND` - zrodlem jest 02-RESEARCH.md Pattern 3, nie kod
# produkcyjny. Dokladnie 19 wpisow.
EXPECTED_FUNCTION_CODE_KIND: dict[int, str] = {
    0x01: "read",
    0x02: "read",
    0x03: "read",
    0x04: "read",
    0x05: "write",
    0x06: "write",
    0x07: "read",
    0x08: "other",
    0x0B: "read",
    0x0C: "read",
    0x0F: "write",
    0x10: "write",
    0x11: "read",
    0x14: "read",
    0x15: "write",
    0x16: "write",
    0x17: "write",
    0x18: "read",
    0x2B: "read",
}


def _build_raw_adu(
    *,
    transaction_id: int = 1,
    protocol_id: int = 0,
    unit_id: int = 1,
    pdu: bytes = b"\x06",
    length_override: int | None = None,
) -> bytes:
    """Sklada surowe bajty ladunku TCP (naglowek MBAP + PDU) przez
    `struct.pack`, z mozliwoscia nadpisania pola dlugosci niezaleznie od
    faktycznej dlugosci `pdu` - bez tego nie da sie zbudowac przypadku
    niespojnej dlugosci, jednego z trzech warunkow walidacji."""
    body = bytes([unit_id]) + pdu
    length = length_override if length_override is not None else len(body)
    return struct.pack(">HHH", transaction_id, protocol_id, length) + body


def _run_analyze(fixture_relative: str, out_dir: Path) -> subprocess.CompletedProcess:
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


# --- validate_mbap: prog dlugosci po obu stronach MIN_ADU_LEN ---------------


def test_validate_mbap_accepts_payload_at_minimum_length():
    raw = _build_raw_adu(pdu=b"\x06")
    assert len(raw) == MIN_ADU_LEN

    header = validate_mbap(raw)

    assert header == MbapHeader(transaction_id=1, protocol_id=0, length=2, unit_id=1)


def test_validate_mbap_rejects_payload_one_byte_below_minimum():
    raw = _build_raw_adu(pdu=b"")
    assert len(raw) == MIN_ADU_LEN - 1

    assert validate_mbap(raw) is None


# --- validate_mbap: precyzja pola dlugosci (T-2-01) -------------------------


def test_validate_mbap_rejects_length_field_max_value_on_short_payload():
    """Pole dlugosci ustawione na wartosc maksymalna dwubajtowa przy krotkim
    ladunku musi zostac odrzucone, nie przyciete do dlugosci faktycznej -
    dowod, ze wartosc z pliku niezaufanego nie jest uzywana jako indeks bez
    kontroli zakresu."""
    raw = _build_raw_adu(pdu=b"\x06", length_override=0xFFFF)
    assert len(raw) == MIN_ADU_LEN

    assert validate_mbap(raw) is None


# --- validate_mbap: pusty ciag bajtow (PROTO-02, edge: empty) ---------------


def test_validate_mbap_rejects_empty_bytes():
    assert validate_mbap(b"") is None


# --- validate_mbap: dlugosc liczona w bajtach, nie w znakach ----------------


def test_validate_mbap_accepts_payload_with_utf8_looking_bytes_and_counts_length_in_bytes():
    """Bajty danych wygladajace na wielobajtowy znak UTF-8 (znak Euro,
    trzy bajty) przechodza walidacje, a dlugosc jest policzona w bajtach -
    dowod, ze nigdzie na tej sciezce nie ma dekodowania bajtow do tekstu."""
    pdu = b"\x06\xe2\x82\xac"
    raw = _build_raw_adu(pdu=pdu)

    header = validate_mbap(raw)

    assert header is not None
    assert header.length == len(raw) - 6


# --- validate_mbap: identyfikator protokolu niezerowy -----------------------


def test_validate_mbap_rejects_nonzero_protocol_id():
    raw = _build_raw_adu(protocol_id=1, pdu=b"\x06")

    assert validate_mbap(raw) is None


# --- classify_function_code: tabela niezalezna od FUNCTION_CODE_KIND -------


def test_function_code_classification():
    for code, expected_kind in EXPECTED_FUNCTION_CODE_KIND.items():
        assert classify_function_code(code) == expected_kind, code

    for code in (0x00, 0x09, 0x0A, 0xFF):
        assert classify_function_code(code) == "unknown"


def test_function_code_0x17_is_write_because_pdu_carries_a_write():
    """Kod 0x17 (Read/Write Multiple Registers) niesie zapis i odczyt w
    jednym PDU - dla potrzeb findingu za zapis liczy sie jako `write`, nigdy
    jako `read` i nigdy jako kategoria mieszana. Ta linia tabeli jest jedyna,
    ktora da sie pomylic w dobrej wierze."""
    assert classify_function_code(0x17) == "write"


def test_classify_function_code_is_order_independent():
    """Sto wywolan w losowej kolejnosci daje wyniki identyczne z wynikami
    wywolan w kolejnosci rosnacej - dowod, ze `FUNCTION_CODE_KIND` jest
    stalym slownikiem literalnym, nie czyms zaleznym od kolejnosci iteracji."""
    codes = list(range(0, 100))
    ascending_results = [classify_function_code(code) for code in codes]

    shuffled = list(codes)
    random.shuffle(shuffled)
    shuffled_results = {code: classify_function_code(code) for code in shuffled}

    assert all(
        shuffled_results[code] == expected
        for code, expected in zip(codes, ascending_results)
    )


# --- PROTO-01: rozpoznanie na porcie niestandardowym ------------------------


def test_recognizes_non_standard_port():
    packets = pcap.read_capture(REPO_ROOT / FIXTURE_NON_STANDARD_PORT)
    segments = decode.decode_segments(packets)

    events = dissect_all(segments)

    assert len(events) == 2
    request, response = events
    assert request.function_code == 6
    assert request.kind == "write"
    assert request.direction == "request"
    assert response.direction == "response"


def test_recognizes_non_standard_port_end_to_end_via_cli(tmp_path):
    result = _run_analyze(FIXTURE_NON_STANDARD_PORT, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    # Od planu 04-04: zapis do sterownika daje finding za zapis oraz finding
    # za uzycie protokolu bez uwierzytelnienia, wiec dwa findingi, nie jeden.
    assert len(analysis["findings"]) == 2
    assert len(analysis["protocol_events"]) == 2


# --- PROTO-02: odrzucenie ramki z niepoprawnym naglowkiem MBAP --------------


def test_rejects_malformed_mbap():
    packets = pcap.read_capture(REPO_ROOT / FIXTURE_MALFORMED_MBAP)
    segments = decode.decode_segments(packets)

    events = dissect_all(segments)

    assert events == []


def test_rejects_malformed_mbap_end_to_end_via_cli(tmp_path):
    result = _run_analyze(FIXTURE_MALFORMED_MBAP, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    assert analysis["findings"] == []
    assert analysis["protocol_events"] == []
