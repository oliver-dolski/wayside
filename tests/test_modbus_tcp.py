"""Machine gates PROTO-01, PROTO-02 and PROTO-04 (plan 02-04).

`test_recognizes_non_standard_port` and `test_rejects_malformed_mbap` prove
recognition by the shape of the MBAP header rather than by the port number
(02-RESEARCH.md, Pitfall 2): each of them comes as a pair, a unit test over
`dissect_all` plus a test through a CLI subprocess, so that the proof runs
through the whole pipeline and not only through the protocol layer in
isolation (criterion 3 of the phase). `test_function_code_classification`
proves the split of function codes into reading and writing ones against the
full table typed into this file independently of `FUNCTION_CODE_KIND` - a test
comparing a dictionary with itself would prove nothing.

The fixture paths are relative to `REPO_ROOT` in the CLI calls, exactly as in
`tests/test_cli_output_snapshot.py` and `tests/test_analyze_pipeline.py`.
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

# The full expected table of function codes, typed here INDEPENDENTLY of
# `FUNCTION_CODE_KIND` - the source is 02-RESEARCH.md Pattern 3, not the
# production code. Exactly 19 entries.
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
    """Assembles the raw bytes of a TCP payload (the MBAP header + the PDU)
    through `struct.pack`, with the option of overriding the length field
    independently of the actual length of `pdu` - without that there is no way
    to build the inconsistent length case, one of the three validation
    conditions."""
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


# --- validate_mbap: the length threshold on both sides of MIN_ADU_LEN ------


def test_validate_mbap_accepts_payload_at_minimum_length():
    raw = _build_raw_adu(pdu=b"\x06")
    assert len(raw) == MIN_ADU_LEN

    header = validate_mbap(raw)

    assert header == MbapHeader(transaction_id=1, protocol_id=0, length=2, unit_id=1)


def test_validate_mbap_rejects_payload_one_byte_below_minimum():
    raw = _build_raw_adu(pdu=b"")
    assert len(raw) == MIN_ADU_LEN - 1

    assert validate_mbap(raw) is None


# --- validate_mbap: precision of the length field (T-2-01) -----------------


def test_validate_mbap_rejects_length_field_max_value_on_short_payload():
    """A length field set to the maximum two-byte value with a short payload
    has to be rejected, not clamped to the actual length - proof that a value
    from an untrusted file is never used as an index without a range check."""
    raw = _build_raw_adu(pdu=b"\x06", length_override=0xFFFF)
    assert len(raw) == MIN_ADU_LEN

    assert validate_mbap(raw) is None


# --- validate_mbap: an empty byte string (PROTO-02, edge: empty) -----------


def test_validate_mbap_rejects_empty_bytes():
    assert validate_mbap(b"") is None


# --- validate_mbap: the length counted in bytes, not in characters ---------


def test_validate_mbap_accepts_payload_with_utf8_looking_bytes_and_counts_length_in_bytes():
    """Data bytes that look like a multi-byte UTF-8 character (the Euro sign,
    three bytes) pass validation, and the length is counted in bytes - proof
    that nowhere on this path are bytes decoded into text."""
    pdu = b"\x06\xe2\x82\xac"
    raw = _build_raw_adu(pdu=pdu)

    header = validate_mbap(raw)

    assert header is not None
    assert header.length == len(raw) - 6


# --- validate_mbap: a non-zero protocol identifier -------------------------


def test_validate_mbap_rejects_nonzero_protocol_id():
    raw = _build_raw_adu(protocol_id=1, pdu=b"\x06")

    assert validate_mbap(raw) is None


# --- classify_function_code: a table independent of FUNCTION_CODE_KIND -----


def test_function_code_classification():
    for code, expected_kind in EXPECTED_FUNCTION_CODE_KIND.items():
        assert classify_function_code(code) == expected_kind, code

    for code in (0x00, 0x09, 0x0A, 0xFF):
        assert classify_function_code(code) == "unknown"


def test_function_code_0x17_is_write_because_pdu_carries_a_write():
    """Code 0x17 (Read/Write Multiple Registers) carries a write and a read in
    one PDU - for the purposes of the write finding it counts as `write`,
    never as `read` and never as a mixed category. This row of the table is
    the only one that can be got wrong in good faith."""
    assert classify_function_code(0x17) == "write"


def test_classify_function_code_is_order_independent():
    """A hundred calls in random order yield results identical to the results
    of calls in ascending order - proof that `FUNCTION_CODE_KIND` is a
    constant literal dictionary, not something dependent on iteration
    order."""
    codes = list(range(0, 100))
    ascending_results = [classify_function_code(code) for code in codes]

    shuffled = list(codes)
    random.shuffle(shuffled)
    shuffled_results = {code: classify_function_code(code) for code in shuffled}

    assert all(
        shuffled_results[code] == expected
        for code, expected in zip(codes, ascending_results)
    )


# --- PROTO-01: recognition on a non-standard port --------------------------


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
    # Since plan 04-04: a write to a controller yields the write finding plus
    # the finding for using a protocol without authentication, so two findings
    # rather than one.
    assert len(analysis["findings"]) == 2
    assert len(analysis["protocol_events"]) == 2


# --- PROTO-02: rejection of a frame with an invalid MBAP header ------------


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
