"""Machine gate INGEST-02 at the level of the structural audit: the snaplen
read from the header of a classic pcap and from the Interface Description
Block of a pcapng (plan 03-01, Task 3), alongside the integration test in
`tests/test_analyze_pipeline.py`.

`audit_capture_structure` is called directly, without a subprocess and without
the CLI - a pure function over a file. The pcapng files with a non-standard
number of IDB blocks are built in this file by `struct.pack`, copying the
layout from `scripts/gen_fixtures.py`, and written ONLY into `tmp_path` - the
`tests/fixtures/pcap/` directory is guarded by
`tests/test_fixture_manifest.py` and a file without a manifest entry fails the
whole suite.
"""

from __future__ import annotations

import struct
from pathlib import Path

from wayside.pcap import CaptureCorruptError, CaptureTruncatedError, audit_capture_structure

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"

FIXTURE_WRITE_CLASSIC = FIXTURE_DIR / "modbus_write_single_register.pcap"
FIXTURE_WRITE_PCAPNG = FIXTURE_DIR / "modbus_write_single_register.pcapng"
FIXTURE_EMPTY_HEADER = FIXTURE_DIR / "empty_valid_header.pcap"
FIXTURE_TRUNCATED_RECORD = FIXTURE_DIR / "truncated_mid_record.pcap"
FIXTURE_TRUNCATED_BLOCK = FIXTURE_DIR / "truncated_mid_block.pcapng"

# The byte layout is identical to `scripts/gen_fixtures.py` - little-endian,
# the same field order in every block.
_PCAPNG_SHB_TYPE = 0x0A0D0D0A
_PCAPNG_IDB_TYPE = 0x00000001
_PCAPNG_EPB_TYPE = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC_LE = 0x1A2B3C4D


def _section_header_block() -> bytes:
    total_length = 28
    return struct.pack(
        "<IIIHHqI",
        _PCAPNG_SHB_TYPE,
        total_length,
        _PCAPNG_BYTE_ORDER_MAGIC_LE,
        1,
        0,
        -1,
        total_length,
    )


def _interface_description_block(snaplen: int) -> bytes:
    total_length = 20
    return struct.pack(
        "<IIHHII",
        _PCAPNG_IDB_TYPE,
        total_length,
        1,  # LINKTYPE_ETHERNET
        0,
        snaplen,
        total_length,
    )


def _enhanced_packet_block(data: bytes) -> bytes:
    pad_len = (-len(data)) % 4
    padded_data = data + b"\x00" * pad_len
    total_length = 32 + len(padded_data)
    header = struct.pack(
        "<IIIIIII",
        _PCAPNG_EPB_TYPE,
        total_length,
        0,
        0,
        0,
        len(data),
        len(data),
    )
    return header + padded_data + struct.pack("<I", total_length)


def _pcapng_bytes(idb_snaplens: list[int], *, include_epb: bool = True) -> bytes:
    blocks = [_section_header_block()]
    for snaplen in idb_snaplens:
        blocks.append(_interface_description_block(snaplen))
    if include_epb:
        blocks.append(_enhanced_packet_block(b"\x00\x01\x02\x03"))
    return b"".join(blocks)


# --- The requirement-to-test contract: the name from 03-VALIDATION.md, unchanged ---


def test_snaplen_reported_from_global_header():
    structure = audit_capture_structure(FIXTURE_WRITE_CLASSIC)

    with open(FIXTURE_WRITE_CLASSIC, "rb") as handle:
        global_header = handle.read(24)
    (expected_snaplen,) = struct.unpack("<I", global_header[16:20])

    assert structure.snaplen == expected_snaplen
    assert structure.snaplen_note is None


# --- Classic pcap: an empty capture carries the snaplen of the global header ---


def test_empty_valid_header_reports_snaplen_and_is_structurally_empty():
    structure = audit_capture_structure(FIXTURE_EMPTY_HEADER)

    assert structure.snaplen == 262144
    assert structure.is_structurally_empty is True


# --- pcapng: the base fixture carries the snaplen of its single IDB block --


def test_pcapng_fixture_reports_snaplen_from_single_interface_description_block():
    structure = audit_capture_structure(FIXTURE_WRITE_PCAPNG)

    assert structure.snaplen == 65535
    assert structure.snaplen_note is None


# --- pcapng built in the test: many IDB blocks, differing snaplen ---------


def test_pcapng_with_two_idb_blocks_of_different_snaplen_gives_none_and_note(tmp_path):
    path = tmp_path / "two_idb_different.pcapng"
    path.write_bytes(_pcapng_bytes([65535, 262144]))

    structure = audit_capture_structure(path)

    assert structure.snaplen is None
    assert structure.snaplen_note
    assert "2" in structure.snaplen_note  # the number of distinct snaplen values


# --- pcapng built in the test: many IDB blocks, the same snaplen ----------


def test_pcapng_with_two_idb_blocks_of_same_snaplen_gives_that_value_and_no_note(tmp_path):
    path = tmp_path / "two_idb_same.pcapng"
    path.write_bytes(_pcapng_bytes([65535, 65535]))

    structure = audit_capture_structure(path)

    assert structure.snaplen == 65535
    assert structure.snaplen_note is None


# --- pcapng built in the test: no IDB block at all ------------------------


def test_pcapng_without_any_idb_block_gives_none_and_note(tmp_path):
    path = tmp_path / "no_idb.pcapng"
    path.write_bytes(_pcapng_bytes([]))

    structure = audit_capture_structure(path)

    assert structure.snaplen is None
    assert structure.snaplen_note


# --- Regression: the Phase 2 error paths untouched by the new IDB branch --


def test_truncated_mid_record_pcap_still_raises_truncated_with_offset_in_message():
    try:
        audit_capture_structure(FIXTURE_TRUNCATED_RECORD)
        raise AssertionError("CaptureTruncatedError was not raised")
    except CaptureTruncatedError as exc:
        message = str(exc)
        assert "bytes" in message


def test_truncated_mid_block_pcapng_still_raises_truncated():
    try:
        audit_capture_structure(FIXTURE_TRUNCATED_BLOCK)
        raise AssertionError("CaptureTruncatedError was not raised")
    except CaptureTruncatedError:
        pass


# --- Regression: an IDB block too short for the snaplen field ends as truncation ---


def test_idb_block_shorter_than_snaplen_field_raises_truncated_without_block_content(
    tmp_path,
):
    # A block of length 16 bytes: it passes the general block range check
    # (>=12, a multiple of four, a matching trailing length), but it is shorter
    # than the twenty bytes needed for the snaplen field at the offset from 12
    # to 16 - the IDB branch has its own check BEFORE the read.
    total_length = 16
    short_idb = (
        struct.pack("<II", _PCAPNG_IDB_TYPE, total_length)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", total_length)
    )
    path = tmp_path / "short_idb.pcapng"
    path.write_bytes(_section_header_block() + short_idb)

    try:
        audit_capture_structure(path)
        raise AssertionError("CaptureTruncatedError was not raised")
    except CaptureTruncatedError as exc:
        assert "snaplen" in str(exc)


# --- Phase 3: snaplen truncation and structural corruption (plan 03-03, Task 1) ---

FIXTURE_SNAPLEN_TRUNCATED = FIXTURE_DIR / "snaplen_truncated_frames.pcap"
FIXTURE_CORRUPTED_RECORD_LENGTH = FIXTURE_DIR / "corrupted_record_length.pcap"


def test_snaplen_truncated_frames_reports_both_packet_numbers():
    structure = audit_capture_structure(FIXTURE_SNAPLEN_TRUNCATED)

    assert structure.snaplen_truncated_packet_numbers == (1, 2)


def test_classic_fixture_without_snaplen_truncation_reports_empty_tuple():
    structure = audit_capture_structure(FIXTURE_WRITE_CLASSIC)

    assert structure.snaplen_truncated_packet_numbers == ()


def test_pcapng_fixture_without_snaplen_truncation_reports_empty_tuple():
    structure = audit_capture_structure(FIXTURE_WRITE_PCAPNG)

    assert structure.snaplen_truncated_packet_numbers == ()


def test_capture_corrupt_error_is_subclass_of_capture_truncated_error():
    assert issubclass(CaptureCorruptError, CaptureTruncatedError)


def test_corrupted_record_length_not_truncation():
    # The gate checks two things at once: without the second half the test
    # passes even when both error paths have collapsed into one (Z-11).
    try:
        audit_capture_structure(FIXTURE_CORRUPTED_RECORD_LENGTH)
        raise AssertionError("CaptureCorruptError was not raised")
    except CaptureCorruptError:
        pass

    try:
        audit_capture_structure(FIXTURE_TRUNCATED_RECORD)
        raise AssertionError("CaptureTruncatedError was not raised")
    except CaptureCorruptError:
        raise AssertionError(
            "A truncated capture was misclassified as structurally corrupted"
        )
    except CaptureTruncatedError:
        pass
