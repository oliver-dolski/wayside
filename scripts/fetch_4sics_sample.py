"""Download of a slice of the public 4SICS capture set (REPORT-05, decision record `0005`).

Usage:
    uv run python scripts/fetch_4sics_sample.py
        Downloads `DATASET_FILE_URL` over the network, verifies its sha256
        sum against `DATASET_SHA256` BEFORE any further use of the file,
        builds the deterministic slice `SLICE_FILENAME` and verifies its sum
        against `SLICE_SHA256`. Both files land in `DATASET_DIR`, a directory
        ignored by git.

    uv run python scripts/fetch_4sics_sample.py --source path/to/file.pcap
        Builds the slice from a file already sitting on disk - zero network
        connections. The fallback route for a machine cut off from the
        network (`04-RESEARCH.md`, section "Environment Availability").

    uv run python scripts/fetch_4sics_sample.py --skip-download
        Skips the download and uses the source file already sitting in
        `DATASET_DIR` (from a previous run of this script).

    uv run python scripts/fetch_4sics_sample.py --output-dir output/path
        Overrides the output directory - useful when building the slice into
        a temporary directory for a test.

This script is a DEVELOPER operation, run by hand. `wayside analyze` never
calls it and never reaches for the network - the downloaded source file and
the slice file do NOT enter the repository (decision record `0005`): both
land in `DATASET_DIR`, listed in `.gitignore` with the reason given. The
checksum of the downloaded file is verified BEFORE it is used to build the
slice - a silent substitution of the capture set at the source is a named
residual risk of decision record `0005` (threat T-4-28), so this script never
uses a file whose sum does not match the constant.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

import wayside.pcap  # noqa: F401 - scapy cache isolation BEFORE importing the layers

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.utils import PcapWriter, RawPcapReader  # noqa: E402

__all__ = [
    "DATASET_NAME",
    "DATASET_PAGE_URL",
    "DATASET_FILE_URL",
    "DATASET_FILENAME",
    "DATASET_SHA256",
    "SLICE_FILENAME",
    "SLICE_SKIP_PACKETS",
    "SLICE_PACKET_COUNT",
    "SLICE_SHA256",
    "DATASET_DIR",
    "DatasetIntegrityError",
    "fetch_dataset",
    "build_slice",
    "main",
]

# The name of the capture set together with the institution the attribution
# is owed to (decision record `0005`) - the traffic comes from the lab of the
# 4SICS industrial conference, published by Netresec with the consent of
# CS3Sthlm (the successor of 4SICS).
DATASET_NAME = "4SICS 2015 Geek Lounge (CS3Sthlm, published by Netresec)"

# Address of the capture set page the attribution points at [CITED: WebFetch 2026-09-05].
DATASET_PAGE_URL = "https://www.netresec.com/?page=PCAP4SICS"

# Download address of one capture file - the third of the three files listed
# on the capture set page (200 MB). The address is a token signed at the
# source (`share.netresec.com`), so the phase research gives it a validity of
# seven days - if it stops working, the new address has to be read off the
# `DATASET_PAGE_URL` page (assumption Z-75).
DATASET_FILE_URL = (
    "https://share.netresec.com/s/gw6Y2QzJHqDD5pr/download/"
    "4SICS-GeekLounge-151022.pcap"
)

# The file name at the source - confirmed by downloading it, not guessed.
DATASET_FILENAME = "4SICS-GeekLounge-151022.pcap"

# Checksum of the source file, established at the first download
# (2026-09-05, 209,236,002 bytes). A silent substitution of the file at the
# source is a residual risk named outright in decision record `0005` - this
# constant is the only defence against it (threat T-4-28).
DATASET_SHA256 = "82529c23906416dc73d7f1926a0d38b82527f1f2a7ff8c6f755ce3208feb9643"

SLICE_FILENAME = "4sics-slice.pcap"

# The number of packets of the source file skipped BEFORE the slice is cut.
# The original intent (assumption Z-69) counted the slice from the first
# packet with `SLICE_PACKET_COUNT = 2000` - Task 2 of this plan measured that
# the first 2000 packets of this source file yield ZERO findings: the first
# packet carrying traffic recognizable by the dissectors of this repository
# (Modbus/TCP) falls at position 292179 (1-based), because the capture is
# traffic from the network of an industrial conference, where most of the
# earlier traffic is S7comm (port 102) and general internet traffic of the
# attendees. A slice counted from the first packet would therefore have to
# span more than 290,000 packets, and reading that many packets through this
# project's decoding layer (scapy) costs on the order of 30-50 seconds -
# that alone exceeds the time budget of the gate from Task 3 (acceptance
# criterion "uv run pytest -q under 120 seconds"; measured empirically
# 2026-09-05, documented in 04-06-SUMMARY.md as a deviation from assumption
# Z-69). `SLICE_SKIP_PACKETS` moves the START of the cut to the first packet
# carrying recognizable traffic (29 packets before the first Modbus/TCP
# event, so that the slice covers the preceding TCP handshake as well) - the
# slice stays fully deterministic (the same source file always yields the
# same skip position), the only thing that changes is that the start of the
# cut is not packet number one.
SLICE_SKIP_PACKETS = 292150

# The number of packets in the slice, counted from `SLICE_SKIP_PACKETS`.
# Forty packets cover five independent Modbus/TCP sessions (one host polling
# five different servers) - material that reads well in the example report
# rather than flooding it with hundreds of nearly identical entries (the same
# capture with a larger `SLICE_PACKET_COUNT` produced several hundred
# findings of the same check - measured 2026-09-05).
SLICE_PACKET_COUNT = 40

# Checksum of the slice file, built from `DATASET_FILENAME` with the
# `SLICE_SKIP_PACKETS`/`SLICE_PACKET_COUNT` above (2026-09-05).
SLICE_SHA256 = "7e2f9bbbb38a2d8a5344370781a6c706ae0abac95af13659575814a34a1fbf97"

# The download directory, derived from the location of the script - not from
# the directory the process was started in. Ignored by git (`.gitignore`,
# decision record `0005`): an external capture set weighing hundreds of
# megabytes does not enter the repository.
DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "4sics"

_CHUNK_SIZE = 1024 * 1024


class DatasetIntegrityError(Exception):
    """Raised in three cases: the checksum constant is empty (bootstrap - the
    first download, before anybody typed the value into this module), the sum
    of the source file does not match the constant, or the sum of the slice
    file does not match the constant. None of these cases ends in a silent use
    of the file - that is the entire reason this class exists."""


def _verify_checksum(path: Path, expected: str, *, what: str, constant_name: str) -> None:
    """Computes the sha256 sum of `path` in a stream and compares it with
    `expected`.

    `expected` empty: the bootstrap path (assumption Z-75) - it ends in a
    `DatasetIntegrityError` carrying the computed sum, so that it can be typed
    in as the value of the constant `constant_name`. `expected` different from
    the computed sum: a `DatasetIntegrityError` carrying both hashes (threat
    T-4-28)."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()

    if not expected:
        raise DatasetIntegrityError(
            f"The constant {constant_name} is empty - this is the first use of "
            f"this file. The sha256 sum of the {what} ({path}): {actual}. Type "
            f"that value in as {constant_name} in this module, so that every "
            "further run checks it normally."
        )
    if actual != expected:
        raise DatasetIntegrityError(
            f"Checksum of the {what} does not match: expected {expected}, got "
            f"{actual}. The file ({path}) may have been silently substituted at "
            "the source - that is exactly the residual risk named in decision "
            "record `0005`."
        )


def fetch_dataset(
    *,
    url: str = DATASET_FILE_URL,
    source_path: Path | None = None,
    output_dir: Path = DATASET_DIR,
) -> Path:
    """Returns the path of the capture set source file under `output_dir`.

    `source_path` given: copies the file from disk in a stream, does not touch
    the network - the fallback route for a disconnected machine, the same
    pattern `scripts/gen_oui_db.py` carries for the vendor registry.
    `source_path` omitted: downloads `url` in a stream through the standard
    library, over the encrypted protocol only, with no redirect onto an
    unencrypted one. In both cases: a write to a temporary file inside
    `output_dir` and an atomic swap (`os.replace`) once finished - a download
    interrupted halfway leaves no file that looks complete. The sha256 sum is
    verified BEFORE the path is returned to the caller (threat T-4-28).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    target_path = output_dir / DATASET_FILENAME

    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(output_dir), prefix=f".{DATASET_FILENAME}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            if source_path is not None:
                with Path(source_path).open("rb") as source_handle:
                    while True:
                        chunk = source_handle.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        handle.write(chunk)
            else:
                if not url.startswith("https://"):
                    raise ValueError(
                        f"The download address {url!r} does not use the "
                        "encrypted protocol (https)."
                    )
                request = urllib.request.Request(
                    url, headers={"User-Agent": "wayside-fetch-4sics-sample/1.0"}
                )
                with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
                    while True:
                        chunk = response.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        handle.write(chunk)
        os.replace(tmp_path_str, target_path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise

    _verify_checksum(
        target_path, DATASET_SHA256, what="source file", constant_name="DATASET_SHA256"
    )
    return target_path


def build_slice(source: Path, output_dir: Path = DATASET_DIR) -> Path:
    """Builds the slice file under `output_dir` out of the packets of `source`.

    Reads `source` AS A STREAM (`RawPcapReader`, without decoding the layers) -
    reading a whole file on the order of hundreds of megabytes through this
    project's reading layer (`wayside.pcap`/scapy) would take minutes and
    gigabytes of memory (assumption Z-69). It skips the first
    `SLICE_SKIP_PACKETS` packets (see the comment next to that constant), then
    writes the following `SLICE_PACKET_COUNT` packets into the slice file,
    preserving the original timestamps and the original layer two type
    (`reader.linktype`) - the slice is meant to carry real traffic with real
    timestamps, because that is its entire value. The sha256 sum of the slice
    file is verified BEFORE the path is returned to the caller.
    """
    source = Path(source)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    target_path = output_dir / SLICE_FILENAME

    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(output_dir), prefix=f".{SLICE_FILENAME}.", suffix=".tmp"
    )
    os.close(fd)
    try:
        skipped = 0
        written = 0
        with RawPcapReader(str(source)) as reader, PcapWriter(
            tmp_path_str, linktype=reader.linktype
        ) as writer:
            writer.write_header(None)
            for raw_bytes, metadata in reader:
                if skipped < SLICE_SKIP_PACKETS:
                    skipped += 1
                    continue
                if written >= SLICE_PACKET_COUNT:
                    break
                writer.write_packet(
                    raw_bytes,
                    sec=metadata.sec,
                    usec=metadata.usec,
                    caplen=metadata.caplen,
                    wirelen=metadata.wirelen,
                )
                written += 1
        os.replace(tmp_path_str, target_path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise

    _verify_checksum(
        target_path, SLICE_SHA256, what="slice file", constant_name="SLICE_SHA256"
    )
    return target_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help=(
            "Path to a source file already sitting on disk. Given: zero "
            "network connections. Omitted: a download from "
            f"{DATASET_FILE_URL}."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DATASET_DIR,
        help=f"Output directory (default {DATASET_DIR}).",
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help=(
            "Skips the download and uses the source file already sitting in "
            "the output directory from a previous run."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir)

    try:
        if args.skip_download:
            source_path = output_dir / DATASET_FILENAME
            if not source_path.is_file():
                print(
                    f"--skip-download was given, but {source_path} does not exist - "
                    "run without that flag first.",
                    file=sys.stderr,
                )
                return 1
            _verify_checksum(
                source_path,
                DATASET_SHA256,
                what="source file",
                constant_name="DATASET_SHA256",
            )
        else:
            source_path = fetch_dataset(source_path=args.source, output_dir=output_dir)
        slice_path = build_slice(source_path, output_dir=output_dir)
    except DatasetIntegrityError as exc:
        print(f"Capture set integrity error: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"Could not download or process the capture set: {exc}", file=sys.stderr)
        return 1

    print(f"Written source file: {source_path}")
    print(f"Written slice: {slice_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
