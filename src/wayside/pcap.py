"""Reading a pcap file and summarising a capture with no dependency on
libpcap/Npcap.

This module imports `rdpcap`/`wrpcap` EXCLUSIVELY from `scapy.utils`, never
from `scapy.all` and never from `scapy.layers.*` modules (e.g. `Ether`,
`IP`). The second restriction is not cosmetic: `scapy.layers.l2` imports
`scapy.arch`, which on Windows unconditionally initialises
`scapy.arch.libpcap` (see Pitfall 3 in 01-RESEARCH.md) - verified
empirically in this phase that `from scapy.utils import rdpcap` alone does
NOT pull in that import, while `from scapy.layers.l2 import Ether` already
does. The consequence for later phases: protocol decoding
(Ether/IP/TCP/Modbus) will have to either accept a dependency on
`scapy.arch.libpcap` at import time, or find another decoding path without
the `scapy.layers.*` layers. Reading and writing pcap files are in
themselves purely file operations and need no libpcap/Npcap - that is the
boundary this module guards.

`PcapReader` without a registered `Ether` class (because importing it is
forbidden here) does not recognise the link type and prints an "unknown LL
type - Using Raw packets" warning on `stderr` through the `scapy.runtime`
logger. That warning is harmless for this module (the packet count and
timestamps come from the frame, not from decoded content), so it is
silenced in line with the recommendation in Pitfall 3.
"""

from __future__ import annotations

import logging
import os
import struct
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# At import time scapy builds a cache of data dictionaries
# (`services.pickle` and relatives) in a directory computed once, in
# `scapy.main`, from `XDG_CACHE_HOME` or from `~/.cache`. scapy handles
# writing to that cache gracefully, but the `cachepath.exists()` check in
# `scapy.data.scapy_data_cache` is NOT guarded - and `pathlib.Path.exists()`
# on a directory whose ACL forbids even traversal raises `PermissionError`
# instead of returning `False`. One `~/.cache/scapy` with a restrictive ACL
# (typically left behind by an earlier scapy run with elevated privileges)
# is enough to make every import of this module end in an exception.
#
# FOUND-02 promises a test suite that passes on a fresh clone, not on a
# machine whose home directory happens to be in the right state, so the
# scapy cache gets a deterministic location in a temporary directory. The
# cache is purely a start-up time optimisation - losing it does not change
# the result of a read.
#
# The override applies ONLY for the duration of the scapy import:
# `XDG_CACHE_HOME` is a process variable and scapy reads it once, so after
# the import we restore the previous value and do not redirect the cache of
# other libraries. An explicitly set `XDG_CACHE_HOME` (e.g. in CI) takes
# precedence and is left alone. The condition holds as long as this module
# is the only place in the package importing scapy - see
# `tests/test_no_external_dissector.py`.
_SCAPY_CACHE_FALLBACK = str(Path(tempfile.gettempdir()) / "wayside-scapy-cache")
_XDG_CACHE_HOME_BEFORE_IMPORT = os.environ.get("XDG_CACHE_HOME")

if _XDG_CACHE_HOME_BEFORE_IMPORT is None:
    os.environ["XDG_CACHE_HOME"] = _SCAPY_CACHE_FALLBACK

try:
    # At module import `scapy.route` executes `conf.route = Route()`, and
    # `Route.__init__` with `conf.route_autoload` true queries the system for
    # the routing table. On Windows that goes through `GetIpForwardTable2` in
    # `scapy.arch.windows._read_routes_c` and ends NON-DETERMINISTICALLY in a
    # memory access violation (exit code 0xC0000005) inside `_extract_ip`,
    # which reads the structures returned by that call. Symptom: roughly
    # every third full run of the test suite had one `wayside.cli analyze`
    # subprocess killed with no output at all, in a different test each time.
    # Diagnosed from a `PYTHONFAULTHANDLER=1` trace.
    #
    # This path is needed for nothing here: the tool is passive and sends not
    # a single packet, so the routing table would never be used anyway.
    # `scapy.route` arrives transitively together with `scapy.layers.l2`
    # (through `scapy.ansmachine` and `scapy.sendrecv`), so the flags have to
    # be set HERE, before the first import of any layer - this is the only
    # place in the package that imports scapy first.
    from scapy.config import conf as _scapy_conf  # noqa: E402

    _scapy_conf.route_autoload = False
    _scapy_conf.route6_autoload = False

    from scapy.utils import rdpcap  # noqa: E402
finally:
    if _XDG_CACHE_HOME_BEFORE_IMPORT is None:
        os.environ.pop("XDG_CACHE_HOME", None)
    else:
        os.environ["XDG_CACHE_HOME"] = _XDG_CACHE_HOME_BEFORE_IMPORT

__all__ = [
    "CaptureSummary",
    "read_capture",
    "summarize",
    "PCAP_GLOBAL_HEADER_LEN",
    "PCAP_RECORD_HEADER_LEN",
    "PCAPNG_BLOCK_HEADER_LEN",
    "PCAP_MAGICS",
    "PCAPNG_MAGIC",
    "CaptureTruncatedError",
    "CaptureCorruptError",
    "CaptureFormatError",
    "CaptureStructure",
    "audit_capture_structure",
]


@dataclass(frozen=True)
class CaptureSummary:
    """A summary of one pcap capture."""

    path: Path
    packet_count: int
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    duration_s: float


def read_capture(path: Path):
    """Reads a pcap capture from the given path.

    Raises `FileNotFoundError` when the file is absent - it never returns a
    silent empty list for a missing file.
    """
    if not Path(path).exists():
        raise FileNotFoundError(f"The capture file does not exist: {path}")
    return rdpcap(str(path))


def summarize(path: Path) -> CaptureSummary:
    """Returns a `CaptureSummary` for the capture at the given path."""
    packets = read_capture(path)
    packet_count = len(packets)

    if packet_count == 0:
        return CaptureSummary(
            path=Path(path),
            packet_count=0,
            first_timestamp=None,
            last_timestamp=None,
            duration_s=0.0,
        )

    timestamps = sorted(float(pkt.time) for pkt in packets)
    first_timestamp = datetime.fromtimestamp(timestamps[0], tz=timezone.utc)
    last_timestamp = datetime.fromtimestamp(timestamps[-1], tz=timezone.utc)
    duration_s = timestamps[-1] - timestamps[0]

    return CaptureSummary(
        path=Path(path),
        packet_count=packet_count,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        duration_s=duration_s,
    )


# --- Structural audit (D-01) -------------------------------------------------
#
# Everything below stands on the standard library alone (struct, pathlib) -
# the structural audit pulls in no scapy layer (D-04). `rdpcap` reads the file
# header correctly and simply stops reading records when the stream ends in
# the middle of a record - it does not treat that as a format error (Pitfall
# 3, 02-RESEARCH.md). This audit detects exactly that case, by comparing the
# length fields against the number of bytes actually left in the file, BEFORE
# `read_capture`/`rdpcap` gets the file at all (the gate in `pipeline.py`).

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16
PCAPNG_BLOCK_HEADER_LEN = 8  # block type (4) + total length (4)

# Magic bytes of classic pcap (4 variants: microsecond/nanosecond, each in
# little/big-endian order) -> (format, byte order). The values were verified
# with `struct.pack` in that session, not recalled from memory.
PCAP_MAGICS: dict[bytes, tuple[str, str]] = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "little"),  # microsecond, little-endian
    b"\xa1\xb2\xc3\xd4": ("pcap", "big"),  # microsecond, big-endian
    b"\x4d\x3c\xb2\xa1": ("pcap", "little"),  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d": ("pcap", "big"),  # nanosecond, big-endian
}

# The pcapng Section Header Block type - a byte palindrome, hence the same
# sequence regardless of the file's byte order (RFC 9-tcpdump/libpcap
# "pcapng"). This is the only way to recognise the format BEFORE establishing
# the byte order, which pcapng carries in the following field (byte order
# magic).
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_PCAPNG_BYTE_ORDER_MAGIC: dict[bytes, str] = {
    b"\x4d\x3c\x2b\x1a": "little",
    b"\x1a\x2b\x3c\x4d": "big",
}

_PCAPNG_EPB_TYPE = 0x00000006  # Enhanced Packet Block - a record with a packet
_PCAPNG_IDB_TYPE = 0x00000001  # Interface Description Block - carries snaplen
_PCAPNG_IDB_MIN_LEN = 20  # header(8) + linktype(2) + reserved(2) + snaplen(4) + trailer(4)


class CaptureTruncatedError(Exception):
    """The capture has a valid format magic, but the stream ends in the
    middle of a record/block - truncation detected structurally (D-01), not
    through the packet count returned by `rdpcap`."""


class CaptureCorruptError(CaptureTruncatedError):
    """The capture structure is inconsistent with itself at a full and
    consistent file length - distinct from `CaptureTruncatedError`, which
    means a stream ending prematurely in the middle of a record or block
    (Z-11). A subclass of the existing exception, so that every `except
    CaptureTruncatedError` block from Phases 1-2 still catches this
    case."""


class CaptureFormatError(Exception):
    """The file has a magic not recognised by any supported format (classic
    pcap or pcapng)."""


@dataclass(frozen=True)
class CaptureStructure:
    """The result of a structural capture audit, with no interpretation of
    packet content."""

    capture_format: str  # "pcap" | "pcapng"
    endianness: str  # "little" | "big"
    record_count: int  # pcap records or pcapng EPB blocks
    is_structurally_empty: bool  # valid header, zero records with a packet
    snaplen: int | None  # None when ambiguous (see snaplen_note)
    snaplen_note: str | None  # non-empty ONLY when snaplen is None
    snaplen_truncated_packet_numbers: tuple[int, ...]  # 1-based, a legal case


def _audit_pcap_classic(path: Path, total_size: int, endianness: str) -> CaptureStructure:
    order = "<" if endianness == "little" else ">"
    with open(path, "rb") as handle:
        global_header = handle.read(PCAP_GLOBAL_HEADER_LEN)
        if len(global_header) < PCAP_GLOBAL_HEADER_LEN:
            raise CaptureTruncatedError(
                f"{path}: pcap global header truncated at {len(global_header)} bytes"
            )
        (_magic, _ver_major, _ver_minor, _thiszone, _sigfigs, snaplen, _network) = (
            struct.unpack(order + "IHHiIII", global_header)
        )

        pos = PCAP_GLOBAL_HEADER_LEN
        record_count = 0
        snaplen_truncated_packet_numbers: list[int] = []
        while pos < total_size:
            remaining = total_size - pos
            if remaining < PCAP_RECORD_HEADER_LEN:
                raise CaptureTruncatedError(
                    f"{path}: record header truncated at offset {pos} bytes "
                    f"({remaining} of {PCAP_RECORD_HEADER_LEN} bytes available)"
                )
            handle.seek(pos)
            record_header = handle.read(PCAP_RECORD_HEADER_LEN)
            (_ts_sec, _ts_frac, incl_len, _orig_len) = struct.unpack(
                order + "IIII", record_header
            )

            # A value from an untrusted file is not an index until it passes
            # a range check (T-2-02) - snaplen BEFORE the seek. A captured
            # length greater than the snaplen is a structural inconsistency of
            # the length field, not a truncated stream (Z-11) - the file has a
            # full, consistent length but contradicts itself.
            if incl_len > snaplen:
                raise CaptureCorruptError(
                    f"{path}: captured length {incl_len} at offset {pos} bytes "
                    f"exceeds the snaplen {snaplen} from the global header"
                )

            pos += PCAP_RECORD_HEADER_LEN
            data_remaining = total_size - pos
            if incl_len > data_remaining:
                raise CaptureTruncatedError(
                    f"{path}: record data truncated at offset {pos} bytes "
                    f"(expected {incl_len}, available {data_remaining})"
                )

            # Truncation by snaplen is a LEGAL case (Z-14), distinct from the
            # condition above: a record whose captured length is smaller than
            # its original length was cut by the snaplen during capture, not
            # damaged. The numbering is 1-based, consistent with the
            # `packet_number` convention in `decode.py` - `record_count`
            # before the increment is the 0-based index of the current
            # record.
            if incl_len < _orig_len:
                snaplen_truncated_packet_numbers.append(record_count + 1)

            pos += incl_len
            record_count += 1

        return CaptureStructure(
            capture_format="pcap",
            endianness=endianness,
            record_count=record_count,
            is_structurally_empty=record_count == 0,
            snaplen=snaplen,
            snaplen_note=None,
            snaplen_truncated_packet_numbers=tuple(snaplen_truncated_packet_numbers),
        )


def _audit_pcapng(path: Path, total_size: int) -> CaptureStructure:
    with open(path, "rb") as handle:
        first_block_probe = handle.read(12)
        if len(first_block_probe) < 12:
            raise CaptureTruncatedError(
                f"{path}: Section Header Block truncated at {len(first_block_probe)} bytes"
            )

        byte_order_magic = first_block_probe[8:12]
        endianness = _PCAPNG_BYTE_ORDER_MAGIC.get(byte_order_magic)
        if endianness is None:
            raise CaptureFormatError(
                f"{path}: unrecognised byte order magic {byte_order_magic!r} in "
                "the Section Header Block"
            )
        order = "<" if endianness == "little" else ">"

        pos = 0
        record_count = 0
        idb_snaplens: list[int] = []
        snaplen_truncated_packet_numbers: list[int] = []
        while pos < total_size:
            remaining = total_size - pos
            if remaining < PCAPNG_BLOCK_HEADER_LEN:
                raise CaptureTruncatedError(
                    f"{path}: pcapng block header truncated at offset {pos} "
                    f"bytes ({remaining} of {PCAPNG_BLOCK_HEADER_LEN} bytes available)"
                )
            handle.seek(pos)
            block_header = handle.read(PCAPNG_BLOCK_HEADER_LEN)
            block_type, total_length = struct.unpack(order + "II", block_header)

            # A block length inconsistent with itself (too short or not a
            # multiple of four) is structural corruption, not a truncated
            # stream (Z-11) - the file may have a full, consistent length and
            # still carry this violation.
            if total_length < 12 or total_length % 4 != 0:
                raise CaptureCorruptError(
                    f"{path}: block length {total_length} at offset {pos} "
                    "bytes is not a multiple of four or is smaller than 12"
                )
            if total_length > remaining:
                raise CaptureTruncatedError(
                    f"{path}: the block at offset {pos} bytes (length "
                    f"{total_length}) extends past the end of the file "
                    f"({remaining} bytes available)"
                )

            handle.seek(pos + total_length - 4)
            trailing_raw = handle.read(4)
            (trailing_length,) = struct.unpack(order + "I", trailing_raw)
            if trailing_length != total_length:
                raise CaptureCorruptError(
                    f"{path}: block length mismatch at offset {pos} bytes "
                    f"(start {total_length}, end {trailing_length})"
                )

            if block_type == _PCAPNG_EPB_TYPE:
                # A range check BEFORE the read (T-3-09): a block shorter
                # than 32 bytes has no room for the captured length field
                # (offset 20:24) and the original length field (offset 24:28)
                # plus header and trailer - an invalid block of this type,
                # structural corruption, not truncation.
                if total_length < 32:
                    raise CaptureCorruptError(
                        f"{path}: the Enhanced Packet Block at offset {pos} "
                        f"bytes (length {total_length}) is too short to "
                        "contain the packet length fields"
                    )
                handle.seek(pos + 20)
                (captured_len, orig_len) = struct.unpack(order + "II", handle.read(8))
                # Truncation by snaplen is a LEGAL case (Z-14), the same
                # condition as in the classic pcap branch. The numbering
                # counts EPB blocks ONLY, consistent with today's
                # `record_count` - interface description blocks do not shift
                # the numbering.
                if captured_len < orig_len:
                    snaplen_truncated_packet_numbers.append(record_count + 1)
                record_count += 1
            elif block_type == _PCAPNG_IDB_TYPE:
                # A range check BEFORE the read (T-3-01): a block shorter
                # than twenty bytes has no room for the snaplen field at
                # offset 12 to 16, so it ends here rather than at an attempt
                # to read past the block. The message carries the byte offset
                # only, never the block's content.
                if total_length < _PCAPNG_IDB_MIN_LEN:
                    raise CaptureTruncatedError(
                        f"{path}: the Interface Description Block at offset "
                        f"{pos} bytes (length {total_length}) is too short to "
                        "contain the snaplen field"
                    )
                handle.seek(pos + 12)
                (idb_snaplen,) = struct.unpack(order + "I", handle.read(4))
                idb_snaplens.append(idb_snaplen)
            pos += total_length

        if not idb_snaplens:
            snaplen: int | None = None
            snaplen_note: str | None = (
                f"{path}: no Interface Description Block in the pcapng file "
                "- the snaplen was not established"
            )
        else:
            unique_snaplens = set(idb_snaplens)
            if len(unique_snaplens) == 1:
                snaplen = idb_snaplens[0]
                snaplen_note = None
            else:
                snaplen = None
                snaplen_note = (
                    f"{path}: {len(unique_snaplens)} Interface Description "
                    "Blocks carry different snaplens - the value is not "
                    "unambiguous"
                )

        return CaptureStructure(
            capture_format="pcapng",
            endianness=endianness,
            record_count=record_count,
            is_structurally_empty=record_count == 0,
            snaplen=snaplen,
            snaplen_note=snaplen_note,
            snaplen_truncated_packet_numbers=tuple(snaplen_truncated_packet_numbers),
        )


def audit_capture_structure(path: Path) -> CaptureStructure:
    """Audits the structure of a capture with no interpretation of packet
    content.

    The order: a missing file gives `FileNotFoundError` with the same message
    as `read_capture`; a file shorter than the format magic (4 bytes) gives
    `CaptureTruncatedError`; a magic not recognised by any supported format
    gives `CaptureFormatError`; a recognised magic but a truncated header or
    any truncated record/block gives `CaptureTruncatedError`.

    No exception message carries raw file bytes or payload content - only the
    path, the byte offset and the name of the violated condition (T-2-10),
    analogously to `Violation` without a text field in
    `scripts/confidentiality_guard.py`.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"The capture file does not exist: {path}")

    total_size = path.stat().st_size
    with open(path, "rb") as handle:
        magic_probe = handle.read(4)

    if len(magic_probe) < 4:
        raise CaptureTruncatedError(
            f"{path}: the file is shorter than the format magic number "
            f"(4 bytes, found {len(magic_probe)})"
        )

    if magic_probe == PCAPNG_MAGIC:
        return _audit_pcapng(path, total_size)

    if magic_probe in PCAP_MAGICS:
        _capture_format, endianness = PCAP_MAGICS[magic_probe]
        return _audit_pcap_classic(path, total_size, endianness)

    raise CaptureFormatError(
        f"{path}: the magic {magic_probe!r} matches no supported format "
        "(neither classic pcap nor pcapng)"
    )
