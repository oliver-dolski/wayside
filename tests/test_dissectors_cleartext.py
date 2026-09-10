"""Machine gate for the three cleartext dissectors (CHECK-03): recognition by
content, rejection of a payload too short without raising, absence of payload
bytes in the event and in the final artifacts.

The pattern is identical to `tests/test_modbus_rtu_tunnel.py`: raw bytes
built in the test, a helper building a `Segment`, a negative case over the
fixtures of another protocol. The constants of the invented user name,
password and resource path are imported from `scripts/gen_fixtures.py` rather
than duplicated - a test for their absence in the artifacts loses its meaning
if it compares against a copy that could itself drift from the fixture.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from wayside import decode, pcap
from wayside.decode import Segment
from wayside.protocols.dissectors.ftp import ftp_dissector
from wayside.protocols.dissectors.http import http_dissector
from wayside.protocols.dissectors.modbus_rtu_tunnel import modbus_rtu_tunnel_dissector
from wayside.protocols.dissectors.modbus_tcp import modbus_tcp_dissector
from wayside.protocols.dissectors.telnet import telnet_dissector

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import gen_fixtures  # noqa: E402

FIXTURE_CLEARTEXT = "tests/fixtures/pcap/cleartext_telnet_ftp_http.pcap"
FIXTURE_MODBUS_WRITE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_MODBUS_NON_STANDARD = "tests/fixtures/pcap/modbus_write_non_standard_port.pcap"
FIXTURE_MODBUS_MALFORMED = "tests/fixtures/pcap/modbus_malformed_mbap.pcap"

# The set of allowed keys of a raw dissector event (before the registry
# injects the protocol/confidence fields) - exactly the fields from the
# <interfaces> block of plan 04-02.
ALLOWED_EVENT_FIELDS = {
    "packet_number",
    "session_id",
    "direction",
    "basis",
    "src_ip",
    "dst_ip",
    "timestamp",
}


def _make_segment(
    payload: bytes,
    *,
    packet_number: int = 1,
    session_id: int = 0,
    src_ip: str = "192.0.2.10",
    src_port: int = 50000,
    dst_ip: str = "192.0.2.20",
    dst_port: int = 23,
) -> Segment:
    return Segment(
        packet_number=packet_number,
        session_id=session_id,
        timestamp=1700000000.0 + packet_number * 0.01,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=payload,
        src_mac="02:00:00:00:00:01",
        dst_mac="02:00:00:00:00:02",
    )


def _fixture_segments(fixture_relative: str) -> list[Segment]:
    packets = pcap.read_capture(REPO_ROOT / fixture_relative)
    return decode.decode_segments(packets)


# --- Telnet: length BEFORE indexing, the negotiation sequence --------------


def test_telnet_dissect_on_empty_and_short_payloads_returns_empty_list():
    for payload in (b"", b"\xff", b"\xff\xfb"):
        segment = _make_segment(payload)
        assert telnet_dissector.dissect([segment]) == []


def test_telnet_dissect_on_three_byte_negotiation_returns_one_event():
    segment = _make_segment(bytes([0xFF, 0xFB, 0x01]))

    events = telnet_dissector.dissect([segment])

    assert len(events) == 1
    assert events[0]["basis"] == telnet_dissector.DETECTION_BASIS


def test_telnet_dissect_on_non_negotiation_command_byte_returns_empty_list():
    segment = _make_segment(bytes([0xFF, 0x01, 0x01]))  # 0x01 outside the command set
    assert telnet_dissector.dissect([segment]) == []


# --- FTP: the command verb, the reply code, the minimum length -------------


def test_ftp_dissect_command_verb_followed_by_space_returns_command_basis():
    segment = _make_segment(b"USER testuser\r\n", dst_port=21)

    events = ftp_dissector.dissect([segment])

    assert len(events) == 1
    assert events[0]["basis"] == ftp_dissector.DETECTION_BASIS_COMMAND


def test_ftp_dissect_reply_code_followed_by_space_returns_reply_basis():
    segment = _make_segment(b"220 Ready\r\n", dst_port=21)

    events = ftp_dissector.dissect([segment])

    assert len(events) == 1
    assert events[0]["basis"] == ftp_dissector.DETECTION_BASIS_REPLY


def test_ftp_dissect_unknown_verb_returns_empty_list():
    segment = _make_segment(b"NOPE test\r\n", dst_port=21)
    assert ftp_dissector.dissect([segment]) == []


def test_ftp_dissect_payload_shorter_than_minimum_returns_empty_list():
    segment = _make_segment(b"PWD", dst_port=21)
    assert len(b"PWD") < ftp_dissector.MIN_COMMAND_LEN
    assert ftp_dissector.dissect([segment]) == []


# --- HTTP: the request line, the status line, a missing version token ------


def test_http_dissect_request_line_with_version_token_returns_request_basis():
    segment = _make_segment(
        b"GET /status.json HTTP/1.1\r\nHost: 192.0.2.20\r\n\r\n", dst_port=8080
    )

    events = http_dissector.dissect([segment])

    assert len(events) == 1
    assert events[0]["basis"] == http_dissector.DETECTION_BASIS_REQUEST


def test_http_dissect_status_line_returns_status_basis():
    segment = _make_segment(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK", dst_port=8080
    )

    events = http_dissector.dissect([segment])

    assert len(events) == 1
    assert events[0]["basis"] == http_dissector.DETECTION_BASIS_STATUS


def test_http_dissect_method_without_version_token_returns_empty_list():
    segment = _make_segment(b"GET /status.json NOTHTTP\r\n\r\n", dst_port=8080)
    assert http_dissector.dissect([segment]) == []


# --- Cross tests: every new dissector over fixtures of a foreign protocol --


def test_new_dissectors_return_empty_list_on_modbus_fixtures():
    for fixture in (
        FIXTURE_MODBUS_WRITE,
        FIXTURE_MODBUS_NON_STANDARD,
        FIXTURE_MODBUS_MALFORMED,
    ):
        segments = _fixture_segments(fixture)
        for dissector in (telnet_dissector, ftp_dissector, http_dissector):
            assert dissector.dissect(segments) == [], (fixture, dissector.__name__)


def test_modbus_dissectors_return_empty_list_on_cleartext_fixture():
    segments = _fixture_segments(FIXTURE_CLEARTEXT)

    assert modbus_tcp_dissector.dissect(segments) == []
    assert modbus_rtu_tunnel_dissector.dissect(segments) == []


# --- Event shape contract: the key set equals the allowed fields -----------


def test_event_shape_matches_allowed_fields_for_all_three_dissectors():
    segments = _fixture_segments(FIXTURE_CLEARTEXT)

    for dissector in (telnet_dissector, ftp_dissector, http_dissector):
        events = dissector.dissect(segments)
        assert events, dissector.__name__
        for event in events:
            assert set(event) == ALLOWED_EVENT_FIELDS, (dissector.__name__, event)


# --- Event direction from the first sender rule, not from the port ---------


def test_direction_follows_first_sender_rule_not_port_number():
    segments = _fixture_segments(FIXTURE_CLEARTEXT)
    telnet_events = telnet_dissector.dissect(segments)

    # Packet 1 (the client, an ephemeral source port) is the first sender in
    # this session, so its event carries the direction "request" regardless of
    # the fact that the destination port (23) is a server port.
    first_by_packet = {event["packet_number"]: event["direction"] for event in telnet_events}
    assert first_by_packet[1] == "request"
    assert first_by_packet[2] == "response"


# --- Integration: the registry recognizes three protocols on the fixture ---


def test_registry_recognizes_three_protocols_on_cleartext_fixture():
    from wayside.protocols import registry as r

    segments = _fixture_segments(FIXTURE_CLEARTEXT)
    protocol_events, low_confidence_events = r.run_dissectors(
        segments, r.discover_dissectors()
    )

    assert sorted({e["protocol"] for e in protocol_events}) == ["ftp", "http", "telnet"]
    assert low_confidence_events == []


# --- No payload bytes in analysis.json and in report.md --------------------


def test_analysis_and_report_carry_no_cleartext_payload_bytes(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_CLEARTEXT,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    analysis_text = (tmp_path / "analysis.json").read_text(encoding="utf-8")
    report_text = (tmp_path / "report.md").read_text(encoding="utf-8")

    forbidden = (
        gen_fixtures.FTP_TEST_USERNAME,
        gen_fixtures.FTP_TEST_PASSWORD,
        gen_fixtures.HTTP_TEST_PATH,
    )
    for needle in forbidden:
        assert needle not in analysis_text, needle
        assert needle not in report_text, needle

    analysis = json.loads(analysis_text)
    protocol_ids = {e["protocol"] for e in analysis["protocol_events"]}
    assert protocol_ids == {"telnet", "ftp", "http"}
