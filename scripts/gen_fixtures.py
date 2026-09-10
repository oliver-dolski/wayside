"""Deterministic generator of synthetic Modbus/TCP pcap captures.

Usage:
    uv run python scripts/gen_fixtures.py            # regenerates the fixtures in place
    uv run python scripts/gen_fixtures.py --check    # regenerates into a temporary
                                                       # directory and compares the sha256
                                                       # sum against the repository files

The addressing comes solely from the RFC 5737 documentation range
(192.0.2.0/24). The MAC addresses are locally administered and invented, they
belong to no real device. The timestamps are constants
(`BASE_TIMESTAMP + i * 0.01`), never the system clock (the `time` function of
the `time` module) - see Pitfall 5 in 01-RESEARCH.md. `wrpcap()` writes the
classic pcap format by default (not pcapng), so the file has no room for
machine metadata.

Every generator is a `gen_*(output_dir: Path) -> Path` function mapped in
`GENERATORS` together with its target file name - `_check()` and `main()`
iterate over that tuple, so adding a new fixture requires no change to either
of those two functions.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import struct
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.contrib.modbus import (  # noqa: E402
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU03ReadHoldingRegistersResponse,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU06WriteSingleRegisterResponse,
)
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

# Documentation addressing, RFC 5737.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
MODBUS_PORT = 502
MODBUS_NON_STANDARD_PORT = 10502
BASE_TIMESTAMP = 1700000000.0

# Destination port of the Modbus RTU over TCP tunnel fixture (plan 03-04),
# following the plan's <interfaces> block - numerically the same as
# MODBUS_NON_STANDARD_PORT, but these are two separate fixture files with
# entirely different payloads (an MBAP header versus a raw RTU frame with no
# header), so the port collision between them does not matter.
RTU_TUNNEL_PORT = 10502

# Ports of the three cleartext protocols (plan 04-02, Task 1).
TELNET_PORT = 23
FTP_CONTROL_PORT = 21
# A non-standard HTTP port: recognition in this project goes by the content
# of the payload, never by the port number (PROTO-01) - port 8080 instead of
# 80 is the same proof `gen_modbus_non_standard_port` has carried since
# Phase 2 (assumption Z-49).
HTTP_PORT = 8080

# Client source ports of the three cleartext sessions, from the ephemeral
# range - constants, not literals repeated in three places.
TELNET_CLIENT_PORT = 49600
FTP_CLIENT_PORT = 49601
HTTP_CLIENT_PORT = 49602

# Openly test values of the cleartext fixture (assumption Z-50): the user
# name and password in the FTP control channel belong to no account and are
# described as test values in the manifest entry.
# `tests/test_dissectors_cleartext.py` imports these same constants instead of
# duplicating their value.
FTP_TEST_USERNAME = "testuser"
FTP_TEST_PASSWORD = "testpass123"
HTTP_TEST_PATH = "/status.json"

# The start address and the holding register value returned by each of the
# three read responses of the read-only session fixture (plan 04-04, Task 1).
# A constant value, never random nor computed - otherwise the byte determinism
# of the generator would be broken.
MODBUS_READ_ONLY_START_ADDR = 0x0000
MODBUS_READ_ONLY_REGISTER_VALUE = 0x00AA

# Global header of a classic pcap, microsecond resolution, little-endian
# (consistent with `PCAP_MAGICS` in `wayside.pcap` after Task 2 of this plan).
PCAP_CLASSIC_MAGIC_LE = 0xA1B2C3D4

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "pcap"

_PCAPNG_SHB_TYPE = 0x0A0D0D0A
_PCAPNG_IDB_TYPE = 0x00000001
_PCAPNG_EPB_TYPE = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC_LE = 0x1A2B3C4D

# Snaplen for the frame truncation fixture: fourteen bytes of the Ethernet
# layer plus twenty bytes of the IP header plus twenty bytes of the TCP header
# yields complete headers and an empty payload - that is a decision
# (assumption Z-07 in 03-02-PLAN.md), not an arbitrary number. A smaller
# snaplen would leave scapy an incomplete TCP header and turn the truncation
# test into a test of the dissector's resilience to garbage.
SNAPLEN_TRUNCATION_LEN = 54

# A Modbus gateway with multiple Unit IDs (Phase 3) - a third address,
# different from the address of the base server, so that the gateway test does
# not pass by accident on the data of another test (assumption Z-10).
GATEWAY_IP = "192.0.2.30"
GATEWAY_MAC = "02:00:00:00:00:03"

__all__ = [
    "GENERATORS",
    "gen_modbus_write_single_register",
    "gen_modbus_non_standard_port",
    "gen_modbus_malformed_mbap",
    "gen_truncated_mid_record",
    "gen_empty_valid_header",
    "gen_modbus_write_pcapng",
    "gen_truncated_mid_block",
    "gen_snaplen_truncated_frames",
    "gen_corrupted_record_length",
    "gen_modbus_poll_cycle_short_window",
    "gen_modbus_poll_cycle_full_window",
    "gen_modbus_gateway_multi_unit_id",
    "gen_modbus_tcp_handshake",
    "gen_modbus_rtu_over_tcp",
    "gen_cleartext_telnet_ftp_http",
    "gen_modbus_read_only_session",
    "main",
]


def gen_modbus_write_single_register(output_dir: Path) -> Path:
    """Generates one Modbus/TCP exchange (a 0x06 request and response) into a pcap file.

    Returns the path of the generated file. Two consecutive calls produce a
    byte identical file (constant addresses, constant timestamps).
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_single_register.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_non_standard_port(output_dir: Path) -> Path:
    """The same 0x06 write exchange as the base fixture, but the server listens
    on `MODBUS_NON_STANDARD_PORT` instead of `MODBUS_PORT`.

    Proof for PROTO-01: protocol recognition goes by the shape of the MBAP
    header, independently of the port number. The fixture is consumed by plan
    02-04.
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_NON_STANDARD_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_NON_STANDARD_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_non_standard_port.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_malformed_mbap(output_dir: Path) -> Path:
    """Two frames, each breaking a different MBAP validation condition of
    `wayside.protocols.modbus_tcp.validate_mbap`.

    scapy does not let one build an invalid MBAP header through the ordinary
    constructor fields of `ModbusADURequest` - one has to build a valid
    packet, take its TCP payload as raw bytes, substitute specific bytes and
    reassemble the packet with a `Raw` layer over TCP.

    First frame (transId=1): the protocol identifier in bytes 2:4 of the
    payload set to a non-zero value (`0x0001`) - it breaks the condition
    `protocol_id == 0`.

    Second frame (transId=2): the length field in bytes 4:6 of the payload set
    to a value inconsistent with the actual number of remaining bytes - it
    breaks the condition `length_field == len(raw) - 6`.
    """
    valid_request_1 = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50001, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    raw_1 = bytearray(bytes(valid_request_1[TCP].payload))
    raw_1[2:4] = struct.pack(">H", 1)  # non-zero protoId - breaks the protoId==0 condition
    frame_bad_proto_id = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50001, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes(raw_1))
    )

    valid_request_2 = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50002, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=2, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    raw_2 = bytearray(bytes(valid_request_2[TCP].payload))
    raw_2[4:6] = struct.pack(">H", 999)  # length inconsistent with the actual bytes
    frame_bad_length = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50002, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes(raw_2))
    )

    packets = [frame_bad_proto_id, frame_bad_length]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_malformed_mbap.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_truncated_mid_record(output_dir: Path) -> Path:
    """A pcap file valid down to the header, cut off in the middle of the last record.

    The source of the content is the same write as the base fixture - built by
    `gen_modbus_write_single_register` into a temporary directory, so that
    there is a single source of bytes. The global magic stays valid, so
    `rdpcap` raises no exception on this file (Pitfall 3, 02-RESEARCH.md):
    this is exactly the shape of input on which Phase 1 gave a silent green
    answer. `wayside.pcap.audit_capture_structure` (Task 2 of this plan) is
    meant to detect this truncation structurally, not by the packet count.
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_single_register(Path(tmp))
        full_bytes = full_path.read_bytes()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "truncated_mid_record.pcap"
    output_path.write_bytes(full_bytes[:-10])
    return output_path


def gen_empty_valid_header(output_dir: Path) -> Path:
    """A file containing the twenty-four byte global header of a classic pcap
    ONLY, zero records.

    It does not rely on `wrpcap` with an empty packet list: the scapy writer
    writes the header only at the first packet, so the result would be a file
    of zero length - a different test case than intended. This file is
    structurally valid and legitimately empty (D-01): `read_capture` on it
    returns zero packets without raising.
    """
    header = struct.pack(
        "<IHHiIII",
        PCAP_CLASSIC_MAGIC_LE,
        2,  # major version
        4,  # minor version
        0,  # time zone
        0,  # timestamp accuracy
        262144,  # snaplen
        1,  # link layer type: Ethernet
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "empty_valid_header.pcap"
    output_path.write_bytes(header)
    return output_path


def _pcapng_section_header_block() -> bytes:
    """A minimal Section Header Block (28 bytes, no options), little-endian."""
    total_length = 28
    return struct.pack(
        "<IIIHHqI",
        _PCAPNG_SHB_TYPE,
        total_length,
        _PCAPNG_BYTE_ORDER_MAGIC_LE,
        1,  # major version
        0,  # minor version
        -1,  # section length unknown
        total_length,
    )


def _pcapng_interface_description_block() -> bytes:
    """A minimal Interface Description Block (20 bytes, no options)."""
    total_length = 20
    return struct.pack(
        "<IIHHII",
        _PCAPNG_IDB_TYPE,
        total_length,
        1,  # link layer type: Ethernet (LINKTYPE_ETHERNET)
        0,  # reserved
        65535,  # snaplen
        total_length,
    )


def _pcapng_enhanced_packet_block(data: bytes, timestamp_s: float) -> bytes:
    """Enhanced Packet Block: length = 32 + data padded to a multiple of 4."""
    pad_len = (-len(data)) % 4
    padded_data = data + b"\x00" * pad_len
    total_length = 32 + len(padded_data)

    timestamp_us = round(timestamp_s * 1_000_000)
    timestamp_high = (timestamp_us >> 32) & 0xFFFFFFFF
    timestamp_low = timestamp_us & 0xFFFFFFFF

    header = struct.pack(
        "<IIIIIII",
        _PCAPNG_EPB_TYPE,
        total_length,
        0,  # interface identifier
        timestamp_high,
        timestamp_low,
        len(data),  # captured length
        len(data),  # original length
    )
    return header + padded_data + struct.pack("<I", total_length)


def gen_modbus_write_pcapng(output_dir: Path) -> Path:
    """The same 0x06 write exchange as the classic fixture, written as pcapng
    instead of a classic pcap.

    The bytes are built explicitly by `struct.pack` in little-endian order,
    consistent with the byte-order magic of the Section Header Block - `scapy`
    is not used to write the pcapng format (a route not guaranteed in this
    version), but the bytes of every packet (`bytes(pkt)`) come from the same
    scapy objects as the classic fixture (D-04): there is a single source of
    content.
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    blocks = [_pcapng_section_header_block(), _pcapng_interface_description_block()]
    for i, pkt in enumerate([request, response]):
        timestamp = BASE_TIMESTAMP + i * 0.01
        blocks.append(_pcapng_enhanced_packet_block(bytes(pkt), timestamp))

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_write_single_register.pcapng"
    output_path.write_bytes(b"".join(blocks))
    return output_path


def gen_truncated_mid_block(output_dir: Path) -> Path:
    """The bytes of a valid pcapng, written without the last ten bytes, so that
    the file ends in the middle of the last Enhanced Packet Block.

    The counterpart of `gen_truncated_mid_record` for the pcapng format -
    proof that the structural audit (Task 2 of this plan) detects the
    truncation in that format too, not only in a classic pcap.
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_pcapng(Path(tmp))
        full_bytes = full_path.read_bytes()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "truncated_mid_block.pcapng"
    output_path.write_bytes(full_bytes[:-10])
    return output_path


# --- Phase 3: fixtures built from byte structure (Task 1, 03-02-PLAN.md) ---


def gen_snaplen_truncated_frames(output_dir: Path) -> Path:
    """Two records cut off by a snaplen equal to `SNAPLEN_TRUNCATION_LEN`.

    The same 0x06 write exchange as the base fixture, built byte by byte
    instead of through `wrpcap`: the scapy writer writes the complete frame
    and cannot produce a record in which the captured length is smaller than
    the original length. The global header carries a snaplen equal to
    `SNAPLEN_TRUNCATION_LEN` instead of the default one; every record carries
    a captured length equal to the length of the truncated frame and an
    original length equal to the full length of the frame before truncation.

    Truncation by snaplen is a LEGITIMATE case - recognized in
    `wayside.pcap._audit_pcap_classic` by the condition captured length
    smaller than original length - and not the same thing as a corrupted
    length field, recognized by the condition captured length greater than the
    snaplen (see `gen_corrupted_record_length` below).
    `audit_capture_structure` raises no exception on this file (INGEST-03).
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    global_header = struct.pack(
        "<IHHiIII",
        PCAP_CLASSIC_MAGIC_LE,
        2,  # major version
        4,  # minor version
        0,  # time zone
        0,  # timestamp accuracy
        SNAPLEN_TRUNCATION_LEN,  # snaplen
        1,  # link layer type: Ethernet
    )

    records = bytearray()
    for i, pkt in enumerate([request, response]):
        # The timestamp derived from BASE_TIMESTAMP, never from the system
        # clock - exactly like the rest of the generators in this file.
        timestamp = BASE_TIMESTAMP + i * 0.01
        ts_sec = int(timestamp)
        ts_usec = round((timestamp - ts_sec) * 1_000_000)

        full_frame = bytes(pkt)
        truncated_frame = full_frame[:SNAPLEN_TRUNCATION_LEN]
        records += struct.pack(
            "<IIII", ts_sec, ts_usec, len(truncated_frame), len(full_frame)
        )
        records += truncated_frame

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "snaplen_truncated_frames.pcap"
    output_path.write_bytes(bytes(global_header) + bytes(records))
    return output_path


def gen_corrupted_record_length(output_dir: Path) -> Path:
    """A file corrupted structurally at a full, consistent file length -
    different from a truncated file.

    Built from the same bytes as the base fixture
    (`gen_modbus_write_single_register`, written into a temporary directory
    the way `gen_truncated_mid_record` does it), with one change IN PLACE: the
    captured length field in the header of the FIRST record is substituted
    with the value 300000, greater than the snaplen from the global header.
    The global header is twenty-four bytes, the record header sixteen, so the
    captured length field of the first record lies at an offset of 32 to 36
    bytes from the start of the file (a layout confirmed by reading
    `wayside.pcap._audit_pcap_classic`). The length of the written file stays
    identical to the length of the source file - that is the entire content of
    this fixture: the structure is inconsistent, but the file is NOT
    truncated.

    This file forces entry into the `incl_len > snaplen` range check block in
    `wayside.pcap`, which has existed since Phase 2 but until now was called
    by no fixture and no test (INGEST-05).
    """
    with tempfile.TemporaryDirectory() as tmp:
        full_path = gen_modbus_write_single_register(Path(tmp))
        full_bytes = bytearray(full_path.read_bytes())

    global_header_len = 24  # magic+versions+zone+accuracy+snaplen+network
    incl_len_offset = global_header_len + 8  # ts_sec(4) + ts_usec(4)
    full_bytes[incl_len_offset : incl_len_offset + 4] = struct.pack("<I", 300000)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "corrupted_record_length.pcap"
    output_path.write_bytes(bytes(full_bytes))
    return output_path


# --- Phase 3: fixtures built by scapy (Task 2, 03-02-PLAN.md) --------------


def gen_modbus_poll_cycle_short_window(output_dir: Path) -> Path:
    """Four packets, two Modbus requests five seconds apart in a capture window
    shorter than ten seconds.

    The first request at `BASE_TIMESTAMP`, the first response at
    `BASE_TIMESTAMP + 0.01`, the second request at `BASE_TIMESTAMP + 5.0`, the
    second response at `BASE_TIMESTAMP + 5.01`. The longest interval between
    requests is five seconds, the capture window 5.01 seconds - the window is
    therefore shorter than two full intervals and shorter than three full
    intervals, so this file trips the warning condition regardless of which
    threshold multiplier from the range of two to three is chosen in plan
    03-03 (assumption Z-08).
    """
    packets = []
    for i, (offset, trans_id) in enumerate([(0.0, 1), (5.0, 2)]):
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50200, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50200, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + offset
        response.time = BASE_TIMESTAMP + offset + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_poll_cycle_short_window.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_poll_cycle_full_window(output_dir: Path) -> Path:
    """Twelve packets, six Modbus requests one second apart, in a capture window
    covering many repetitions of the polling cycle.

    Six requests at `BASE_TIMESTAMP + n` for n from zero to five, every
    response at the time of its request plus `0.01`. The longest interval
    between requests is one second, the capture window 5.01 seconds, so the
    window covers five full intervals - this file does NOT trip the warning
    condition for any threshold multiplier from the range of two to five, that
    is, it is a negative case robust against the outcome of the checkpoint of
    plan 03-03.
    """
    packets = []
    for n in range(6):
        trans_id = n + 1
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50201, dport=MODBUS_PORT, seq=2 * n + 1, ack=2 * n, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50201, seq=2 * n + 1, ack=2 * n + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + n
        response.time = BASE_TIMESTAMP + n + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_poll_cycle_full_window.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_gateway_multi_unit_id(output_dir: Path) -> Path:
    """Six packets, three Modbus exchanges to one server address with three
    different Unit ID values - a gateway exposing three logical addresses.

    A session between `CLIENT_IP`/`CLIENT_MAC` and `GATEWAY_IP`/`GATEWAY_MAC`.
    Three requests with `unitId` equal to 1, 2 and 3 in turn, each with a
    rising `transId`, three responses with the same `unitId`/`transId` values.

    This file represents one network host exposing three logical addresses
    behind it, NOT three hosts - that is exactly the shape of data on which a
    naive inventory produces three entries instead of one with sub-addresses
    (ASSET-05).
    """
    packets = []
    for i, unit_id in enumerate([1, 2, 3]):
        trans_id = unit_id
        request = (
            Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
            / IP(src=CLIENT_IP, dst=GATEWAY_IP, id=1)
            / TCP(sport=50300, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=unit_id)
            / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
        )
        response = (
            Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
            / IP(src=GATEWAY_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50300, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=unit_id)
            / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
        )
        request.time = BASE_TIMESTAMP + i * 0.01
        response.time = BASE_TIMESTAMP + i * 0.01 + 0.005
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_gateway_multi_unit_id.pcap"
    wrpcap(str(output_path), packets)
    return output_path


def gen_modbus_tcp_handshake(output_dir: Path) -> Path:
    """Five packets: a three-way TCP handshake explicitly before the Modbus
    exchange, the only passive proof of which side initiated the session.

    The order: a packet with `TCP(flags="S")` from the client to the server; a
    packet with `TCP(flags="SA")` from the server to the client; a packet with
    `TCP(flags="A")` from the client to the server; a Modbus request with
    `flags="PA"` from the client; a Modbus response with `flags="PA"` from the
    server. The first three packets carry no layer above TCP, so their payload
    is empty - `decode_segments` today rejects every segment without a
    payload, so those three packets are invisible to the rest of the pipeline,
    but a packet with the SYN flag and without the ACK flag remains the only
    passive proof of the initiator (FLOW-02). The Phase 2 fixtures contain no
    connection handshake at all, so until this file the project has no
    material for the positive FLOW-02 case (assumption Z-09).
    """
    syn = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src=CLIENT_IP, dst=SERVER_IP, id=1
    ) / TCP(sport=50400, dport=MODBUS_PORT, seq=0, ack=0, flags="S")
    syn_ack = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src=SERVER_IP, dst=CLIENT_IP, id=1
    ) / TCP(sport=MODBUS_PORT, dport=50400, seq=0, ack=1, flags="SA")
    ack = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src=CLIENT_IP, dst=SERVER_IP, id=1
    ) / TCP(sport=50400, dport=MODBUS_PORT, seq=1, ack=1, flags="A")
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50400, dport=MODBUS_PORT, seq=1, ack=1, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50400, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [syn, syn_ack, ack, request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_tcp_handshake.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Phase 3: the Modbus RTU over TCP tunnel fixture (plan 03-04, Task 2) --


def _rtu_crc16(data: bytes) -> int:
    """A LOCAL implementation of the CRC16/Modbus checksum, INDEPENDENT of
    `wayside.protocols.modbus_rtu_tunnel.modbus_crc16` (assumption Z-16).

    An import from `wayside` would pull the whole import graph of the reading
    layer (scapy.layers.*, cache isolation) into this script, together with
    its own import side effects, which this script performs differently today.
    Besides, two independent implementations that have to agree on every test
    vector of `tests/test_modbus_rtu_tunnel.py` are stronger proof of
    correctness than one shared implementation, whose bug would agree with
    itself. The parameters of the algorithm (initial register `0xFFFF`,
    reversed polynomial `0xA001`) come from the same source as in the
    production module - "MODBUS over Serial Line Specification and
    Implementation Guide V1.02", section 6.2.2, see the docstring of
    `wayside/protocols/modbus_rtu_tunnel.py`.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def gen_modbus_rtu_over_tcp(output_dir: Path) -> Path:
    """A serial-to-network converter that passes a raw Modbus RTU frame from
    the bus straight into a TCP socket, without reconstructing an MBAP header.

    Two packets in one TCP session: a client request and a server response,
    both with an identical eight-byte payload - Write Single Register echoes
    the same content back unchanged for this function code. The frame body:
    the address byte `0x01`, the function code byte `0x06`, the register
    address `0x0001` and the register value `0x002A` in most significant byte
    first order (four bytes), the `_rtu_crc16` checksum over those six bytes,
    written in least significant byte first order. The destination port is
    non-standard (`RTU_TUNNEL_PORT`) on purpose: recognition in this project
    does not depend on the port number (PROTO-01, Phase 2), and a number other
    than 502 removes the temptation to write a test that passes because of the
    port rather than because of the shape of the frame.
    """
    body = struct.pack(">BBHH", 0x01, 0x06, 0x0001, 0x002A)
    frame = body + struct.pack("<H", _rtu_crc16(body))

    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50500, dport=RTU_TUNNEL_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=frame)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=RTU_TUNNEL_PORT, dport=50500, seq=1, ack=1, flags="PA")
        / Raw(load=frame)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_rtu_over_tcp.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Phase 4: the Telnet/FTP/HTTP cleartext fixture (plan 04-02, Task 1) ---


def gen_cleartext_telnet_ftp_http(output_dir: Path) -> Path:
    """Three cleartext TCP sessions: Telnet, the FTP control channel, HTTP on a
    non-standard port (CHECK-03, the evidence for criterion 1 of the phase).

    Every session carries traffic recognizable by the shape of the first bytes
    of the payload, never by the port number nor by a full decoding of the
    protocol - HTTP listens on a non-standard `HTTP_PORT` precisely so that
    recognition by content is the only explanation of the result (PROTO-01 as
    the pattern, assumption Z-49). The user name and password in the FTP
    control channel are openly invented test values (assumption Z-50) -
    `tests/test_dissectors_cleartext.py` imports these same constants instead
    of duplicating their value, in order to check for their absence in the
    artifacts.
    """
    # The Telnet session, two packets: each carries a three-byte option
    # negotiation sequence. Byte 0: IAC (0xFF, interpret the command as a
    # command rather than as data). Byte 1: the negotiation command (client:
    # WILL / 0xFB, server: DO / 0xFD - an answer with a different command,
    # the way a real Telnet negotiation goes). Byte 2: the option number
    # (0x01 = echo) - an arbitrary value, the dissector does not check it (a
    # decision, not an oversight).
    telnet_client = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=TELNET_CLIENT_PORT, dport=TELNET_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=bytes([0xFF, 0xFB, 0x01]))
    )
    telnet_server = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=TELNET_PORT, dport=TELNET_CLIENT_PORT, seq=1, ack=1, flags="PA")
        / Raw(load=bytes([0xFF, 0xFD, 0x01]))
    )

    # The FTP session, control channel, three packets: the server welcome
    # response (the numeric code 220, a space, our own invented text), then
    # the client command carrying the user name, then the client command
    # carrying the password.
    ftp_welcome = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=FTP_CONTROL_PORT, dport=FTP_CLIENT_PORT, seq=1, ack=0, flags="PA")
        / Raw(load=b"220 Test FTP service ready\r\n")
    )
    ftp_user = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=FTP_CLIENT_PORT, dport=FTP_CONTROL_PORT, seq=1, ack=1, flags="PA")
        / Raw(load=f"USER {FTP_TEST_USERNAME}\r\n".encode("ascii"))
    )
    ftp_pass = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=FTP_CLIENT_PORT, dport=FTP_CONTROL_PORT, seq=2, ack=1, flags="PA")
        / Raw(load=f"PASS {FTP_TEST_PASSWORD}\r\n".encode("ascii"))
    )

    # The HTTP session, two packets: the request line (method, path,
    # version) with the host name header, then the response status line with
    # the content type header and a short body.
    http_request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=HTTP_CLIENT_PORT, dport=HTTP_PORT, seq=1, ack=0, flags="PA")
        / Raw(
            load=(
                f"GET {HTTP_TEST_PATH} HTTP/1.1\r\n"
                f"Host: {SERVER_IP}\r\n\r\n"
            ).encode("ascii")
        )
    )
    http_response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=HTTP_PORT, dport=HTTP_CLIENT_PORT, seq=1, ack=1, flags="PA")
        / Raw(
            load=(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n\r\nOK"
            ).encode("ascii")
        )
    )

    packets = [
        telnet_client,
        telnet_server,
        ftp_welcome,
        ftp_user,
        ftp_pass,
        http_request,
        http_response,
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "cleartext_telnet_ftp_http.pcap"
    wrpcap(str(output_path), packets)
    return output_path


# --- Phase 4: the read-only Modbus session fixture (plan 04-04, Task 1) ----


def gen_modbus_read_only_session(output_dir: Path) -> Path:
    """One Modbus/TCP session, three request-response exchanges, every request
    carrying the read holding registers function code (0x03).

    The case that separates CHECK-05 from CHECK-04 (assumption Z-62,
    04-RESEARCH.md Pitfall 9): the fixture yields a finding for the use of an
    industrial protocol without an authentication mechanism and does NOT yield
    a finding for a write to a controller, because it contains not one write
    operation - a check implemented as a filter over the write finding would
    come apart exactly here.

    The transaction identifier rises with every exchange (1, 2, 3), the unit
    identifier is constant. The interval between consecutive requests is short
    (0.02 s), so that the capture window (0.05 s) is longer than twice the
    measured interval between requests (0.04 s) - otherwise the fixture would
    trip the warning about a capture window too short against the measured
    polling cycle, which would be noise unrelated to CHECK-05.
    """
    packets = []
    for i in range(3):
        trans_id = i + 1
        offset = i * 0.02
        request = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
            / TCP(sport=50300, dport=MODBUS_PORT, seq=2 * i + 1, ack=2 * i, flags="PA")
            / ModbusADURequest(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU03ReadHoldingRegistersRequest(
                startAddr=MODBUS_READ_ONLY_START_ADDR, quantity=1
            )
        )
        response = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
            / TCP(sport=MODBUS_PORT, dport=50300, seq=2 * i + 1, ack=2 * i + 2, flags="PA")
            / ModbusADUResponse(transId=trans_id, protoId=0, unitId=1)
            / ModbusPDU03ReadHoldingRegistersResponse(
                registerVal=[MODBUS_READ_ONLY_REGISTER_VALUE]
            )
        )
        request.time = BASE_TIMESTAMP + offset
        response.time = BASE_TIMESTAMP + offset + 0.01
        packets.extend([request, response])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "modbus_read_only_session.pcap"
    wrpcap(str(output_path), packets)
    return output_path


GENERATORS: tuple[tuple[str, Callable[[Path], Path]], ...] = (
    ("modbus_write_single_register.pcap", gen_modbus_write_single_register),
    ("modbus_write_non_standard_port.pcap", gen_modbus_non_standard_port),
    ("modbus_malformed_mbap.pcap", gen_modbus_malformed_mbap),
    ("truncated_mid_record.pcap", gen_truncated_mid_record),
    ("empty_valid_header.pcap", gen_empty_valid_header),
    ("modbus_write_single_register.pcapng", gen_modbus_write_pcapng),
    ("truncated_mid_block.pcapng", gen_truncated_mid_block),
    ("snaplen_truncated_frames.pcap", gen_snaplen_truncated_frames),
    ("corrupted_record_length.pcap", gen_corrupted_record_length),
    ("modbus_poll_cycle_short_window.pcap", gen_modbus_poll_cycle_short_window),
    ("modbus_poll_cycle_full_window.pcap", gen_modbus_poll_cycle_full_window),
    ("modbus_gateway_multi_unit_id.pcap", gen_modbus_gateway_multi_unit_id),
    ("modbus_tcp_handshake.pcap", gen_modbus_tcp_handshake),
    ("modbus_rtu_over_tcp.pcap", gen_modbus_rtu_over_tcp),
    ("cleartext_telnet_ftp_http.pcap", gen_cleartext_telnet_ftp_http),
    ("modbus_read_only_session.pcap", gen_modbus_read_only_session),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check() -> int:
    ok = True
    for name, generator in GENERATORS:
        repo_file = FIXTURE_DIR / name
        if not repo_file.exists():
            print(f"No fixture file in the repository: {repo_file}", file=sys.stderr)
            ok = False
            continue

        with tempfile.TemporaryDirectory() as tmp:
            generated = generator(Path(tmp))
            repo_hash = _sha256(repo_file)
            generated_hash = _sha256(generated)
            if repo_hash != generated_hash:
                print(
                    f"sha256 sum mismatch for {name}: "
                    f"repo={repo_hash} generated={generated_hash}",
                    file=sys.stderr,
                )
                ok = False

    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Regenerate into a temporary directory and compare the sha256 sum against the repository.",
    )
    args = parser.parse_args()

    if args.check:
        return _check()

    for name, generator in GENERATORS:
        output_path = generator(FIXTURE_DIR)
        print(f"Generated: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
