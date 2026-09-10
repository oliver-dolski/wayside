"""Decoding Ether/IP/TCP frames and reconstructing TCP sessions in file
order.

This module imports `wayside.pcap` FIRST, before any `scapy.layers.*`
import - `wayside.pcap` performs scapy cache isolation through
`XDG_CACHE_HOME` at import time (see `wayside/pcap.py`), and `scapy.main`
computes the cache directory only once. Duplicating that logic in a second
place would defeat its purpose.

Importing `Ether` from `scapy.layers.l2` registers the DLT_EN10MB -> Ether
mapping in `conf.l2types` as a side effect of the module itself
(`scapy.layers.l2` calls `conf.l2types.register(...)` at import) - without
it `rdpcap` does not recognise the Ethernet layer and returns raw `Raw`
packets, even when IP/TCP are imported elsewhere too. SINCE PHASE 3
`decode_segments` refers to the `Ether` class directly
(`pkt.haslayer(Ether)`, `pkt[Ether]`) to pull the layer two address for the
inventory (ASSET-01) - the import has to be here regardless of that use,
before any code on this read path calls `rdpcap`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import wayside.pcap  # noqa: F401  - imported FIRST, see the module docstring

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.l2 import Ether  # noqa: E402,F401
from scapy.layers.inet import IP, TCP  # noqa: E402

__all__ = [
    "SESSION_KEY_SEPARATOR",
    "Segment",
    "SessionInitiator",
    "decode_segments",
    "find_session_initiators",
]

SESSION_KEY_SEPARATOR = "<->"


@dataclass(frozen=True)
class Segment:
    """One TCP segment with a non-empty payload, in pcap file order."""

    packet_number: int
    session_id: int
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes
    src_mac: str | None
    dst_mac: str | None


@dataclass(frozen=True)
class SessionInitiator:
    """The party that opened the TCP session, established from the
    connection handshake packet observed in this capture.

    What this type does NOT mean: the PRESENCE of an entry is an observation
    of the connection-opening packet (the SYN flag without the ACK flag),
    and its ABSENCE means an UNDETERMINED initiator, not a guessed one. A
    capture starting in the middle of an ongoing session does not carry this
    information at all, and the first sender of payload is not a substitute
    for it - that is the separate `direction` field with the
    `inferred:first-observed-sender` marker (assumption Z-30).
    """

    session_id: int
    ip: str
    port: int


def _canonical_session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """Builds a session key independent of traffic direction.

    Both endpoints are canonicalised as `(ip, port)` sorted
    lexicographically, so that both directions of the same TCP conversation
    get the same key.
    """
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    low, high = sorted((endpoint_a, endpoint_b))
    return f"{low[0]}:{low[1]}{SESSION_KEY_SEPARATOR}{high[0]}:{high[1]}"


def decode_segments(packets) -> list[Segment]:
    """Decodes a list of scapy packets into a list of `Segment`.

    It skips frames without an IP or TCP layer and frames with an empty TCP
    payload. `packet_number` is a 1-based index into `packets` (the
    "frame.number" field convention familiar from popular traffic
    analysers), regardless of how many segments were skipped. `session_id`
    is assigned sequentially, in file order, on first encountering a
    canonical 4-tuple - held in a `dict`, never in a `set`, because
    insertion order is the guarantee of determinism here (02-RESEARCH.md,
    Pitfall 5).
    """
    segments: list[Segment] = []
    session_ids: dict[str, int] = {}
    next_session_id = 0

    for packet_number, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        tcp_layer = pkt[TCP]
        payload = bytes(tcp_layer.payload)
        if not payload:
            continue

        ip_layer = pkt[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)

        if pkt.haslayer(Ether):
            src_mac = str(pkt[Ether].src)
            dst_mac = str(pkt[Ether].dst)
        else:
            src_mac = None
            dst_mac = None

        session_key = _canonical_session_key(src_ip, src_port, dst_ip, dst_port)
        if session_key not in session_ids:
            session_ids[session_key] = next_session_id
            next_session_id += 1

        segments.append(
            Segment(
                packet_number=packet_number,
                session_id=session_ids[session_key],
                timestamp=float(pkt.time),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                payload=payload,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )
        )

    return segments


def find_session_initiators(packets, segments: list[Segment]) -> dict[int, SessionInitiator]:
    """Returns a mapping from session identifier to the party that opened
    it.

    It stands NEXT TO `decode_segments`, not inside it: a packet with the
    SYN flag carries no payload by definition of the protocol, so the empty
    payload filter in `decode_segments` rejects it. Breaking that filter
    would change the number of segments seen by `dissect_all`, that is a
    contract from Phase 2, with no consumer for the change.

    The session key comes from `_canonical_session_key`, the only source of
    keys in this module - the new function does not build its own, parallel
    key, because the numbering would drift from `decode_segments` at the
    first change of canonicalisation.

    A session without a single segment carrying payload gets NO entry
    (assumption Z-31): it appears in no other section of the model, so an
    entry here would split the identifier space between sections.
    """
    session_ids: dict[str, int] = {}
    for segment in segments:
        key = _canonical_session_key(
            segment.src_ip, segment.src_port, segment.dst_ip, segment.dst_port
        )
        session_ids.setdefault(key, segment.session_id)

    initiators: dict[int, SessionInitiator] = {}
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        tcp_layer = pkt[TCP]
        # The TCP layer `flags` field in scapy is a flag field with the
        # letters `FSRPAUECN`, so a letter test reads more clearly here than
        # a bit mask. The packet OPENING a connection has the SYN flag and
        # does NOT have the ACK flag - the server's reply (SYN together with
        # ACK) is not an opening.
        if "S" not in tcp_layer.flags or "A" in tcp_layer.flags:
            continue

        ip_layer = pkt[IP]
        key = _canonical_session_key(
            str(ip_layer.src), int(tcp_layer.sport), str(ip_layer.dst), int(tcp_layer.dport)
        )
        session_id = session_ids.get(key)
        if session_id is None:
            continue

        # The first packet in file order wins; later ones do not overwrite.
        initiators.setdefault(
            session_id,
            SessionInitiator(
                session_id=session_id,
                ip=str(ip_layer.src),
                port=int(tcp_layer.sport),
            ),
        )

    return initiators
