"""Communication matrix: who talks to whom, in which direction, over which
protocol and how much of it there was (FLOW-01, FLOW-02, FLOW-03).

What this matrix shows: TCP sessions that reached the capture point and
carried at least one segment with payload (assumption Z-31). Sessions made
up exclusively of packets without payload are COUNTED and named in the
report's limitations section rather than added here: session identifiers
come from `decode.decode_segments` and are shared by `conversations`,
`protocol_events` and this matrix, so a row outside that numbering would
split the identifier space between model sections.

What this matrix does NOT show: a picture of the network. The absence of a
conversation from this table is not proof that the conversation did not
happen - it is proof that it did not reach this listening point. The
sentences in `VANTAGE_POINT_LIMITATIONS` stand in the report so the reader
does not have to work that out alone.

A session whose protocol was not recognised DOES have a row, labelled `tcp`.
Dropping such a row would be a lie by omission, and this is the part of the
report where that lie costs the most: the reader builds their picture of the
network out of it.

Protocol identifiers now live in the `manifest.yaml` files of the dissector
registry (`wayside.protocols.registry`) and are the single source of truth -
this module carries no closed tuple of label constants, because that would
be a second, drifting copy of the same list (PROTO-05). A row label comes
straight from the event's `protocol` field. Resolution order is NOT
commutative: high confidence precedes low confidence, and with several
high-confidence protocols in the same session the label is compound (sorted
identifiers joined by a plus sign, assumption Z-43) - picking one of several
would be an arbitrary choice, and dropping any of them a lie by omission.
"""

from __future__ import annotations

import dataclasses

import wayside.pcap  # noqa: F401  - scapy cache isolation BEFORE layer imports

from scapy.layers.inet import IP, TCP  # noqa: E402

from wayside.decode import (  # noqa: E402
    Segment,
    SessionInitiator,
    _canonical_session_key,
)
from wayside.model import inferred, not_derivable, observed  # noqa: E402

__all__ = [
    "PROTOCOL_UNRECOGNIZED",
    "COMPLETENESS_CLAIM_TERMS",
    "VANTAGE_POINT_LIMITATIONS",
    "build_comm_matrix",
    "vantage_point_limitations",
]

PROTOCOL_UNRECOGNIZED = "tcp"

PROVENANCE_METHOD_PAYLOAD_SHAPE = "payload-shape"
PROVENANCE_METHOD_FIRST_SENDER = "first-observed-sender"

# Strings suggesting a complete picture of the network - TEST DATA for the
# FLOW-03 machine gate, in the same style as `FORBIDDEN_ROLE_LABELS` in
# `assets/inventory.py`. They live in production code so that the gate and
# the report text have one source of truth.
COMPLETENESS_CLAIM_TERMS: tuple[str, ...] = (
    "complete list",
    "complete inventory",
    "complete picture",
    "full list",
    "full inventory",
    "full picture",
    "all devices",
    "all hosts",
    "the whole network",
    "entire network",
)

# Deliberately NOT on the list above: "every device" and "every host". Both
# read as a completeness claim in isolation, but both also open an ordinary
# requirement sentence ("every device connecting to the control system is
# uniquely identified"), and the standards catalogue paraphrases carry
# exactly that construction. A gate that fires on the paraphrase of a clause
# rather than on a claim about the inventory teaches its reader to ignore
# it.

# Fixed sentences naming the blind spot of passive observation. They are
# constants rather than text assembled in the rendering layer, because this
# is content that must read identically in every report and that must not be
# lost while editing a template.
VANTAGE_POINT_LIMITATIONS: tuple[str, ...] = (
    "This report describes only traffic that reached the capture point. A "
    "device absent from the result is not a device absent from the network - "
    "it is a device whose traffic did not pass this point.",
    "A device sitting behind a protocol gateway is visible only under the "
    "address of that gateway. A network address in this report may therefore "
    "correspond to more than one physical device.",
    "Multiple hosts hidden behind a single address after address translation "
    "are indistinguishable from this point. One inventory row may correspond "
    "to more than one device.",
)


def _endpoint(ip: str, port: int) -> str:
    return f"{ip}:{port}"


def _observed_endpoint(value: str):
    return observed(value)


def _inferred_endpoint(value: str):
    return inferred(value, PROVENANCE_METHOD_FIRST_SENDER)


def _wire_length(pkt) -> int:
    """Packet length on the wire (assumption Z-34).

    `wirelen` is set by the scapy reader when the capture is read. When the
    attribute is absent (e.g. a packet built in memory rather than read from
    a file) the byte length of the packet stands in - an explicit fallback,
    not a silent zero. Zero would give a zero volume for the whole session,
    that is a CONFIDENT, WRONG number in the report, and that is the worst
    failure mode in this project.
    """
    wirelen = getattr(pkt, "wirelen", None)
    if wirelen is None:
        return len(bytes(pkt))
    return int(wirelen)


def build_comm_matrix(
    *,
    packets,
    segments: list[Segment],
    events: list[dict],
    low_confidence_events: list[dict],
    initiators: dict[int, SessionInitiator],
) -> list[dict]:
    """Builds the communication matrix, one row per session with payload.

    Row order is the order in which sessions are first encountered in the
    file - a `dict` plus a separate `order` list, never a `set` on the path
    to serialisation (`03-PATTERNS.md`, Shared Patterns).

    EVERY field of a row goes through `dataclasses.asdict` on an
    `ObservedField`, the session identifier included. Uniformity is worth one
    extra wrapper here: the provenance gate then walks the whole section with
    no exceptions, and an exception is the thing that gets forgotten.
    """
    rows: dict[int, dict[str, object]] = {}
    order: list[int] = []
    first_sender: dict[int, tuple[str, str]] = {}
    session_by_key: dict[str, int] = {}
    packet_counts: dict[int, int] = {}
    volume_bytes: dict[int, int] = {}

    # First pass: sessions and the first sender of payload.
    for segment in segments:
        key = _canonical_session_key(
            segment.src_ip, segment.src_port, segment.dst_ip, segment.dst_port
        )
        session_by_key.setdefault(key, segment.session_id)
        if segment.session_id in first_sender:
            continue
        order.append(segment.session_id)
        first_sender[segment.session_id] = (
            _endpoint(segment.src_ip, segment.src_port),
            _endpoint(segment.dst_ip, segment.dst_port),
        )
        packet_counts[segment.session_id] = 0
        volume_bytes[segment.session_id] = 0

    # Second pass: packet count and wire volume, over ALL packets of the
    # session, not only the segments carrying payload (assumption Z-33). A
    # packet whose key is absent from the mapping belongs to a session
    # without payload, counted separately in the limitations section.
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        key = _canonical_session_key(
            str(ip_layer.src), int(tcp_layer.sport), str(ip_layer.dst), int(tcp_layer.dport)
        )
        session_id = session_by_key.get(key)
        if session_id is None:
            continue
        packet_counts[session_id] += 1
        volume_bytes[session_id] += _wire_length(pkt)

    # PROTO-05: a session -> tuple of sorted protocol identifiers mapping,
    # built straight from the event's `protocol` field - zero closed sets of
    # constants in this file. Indexing `event["protocol"]` without a default
    # is DELIBERATE: the dissector registry injects this field into every
    # event, so its absence is a model shape error and `KeyError` is meant to
    # report it outright.
    high_confidence_protocols: dict[int, set[str]] = {}
    for event in events:
        high_confidence_protocols.setdefault(event["session_id"], set()).add(
            event["protocol"]
        )
    low_confidence_protocols: dict[int, set[str]] = {}
    for event in low_confidence_events:
        low_confidence_protocols.setdefault(event["session_id"], set()).add(
            event["protocol"]
        )

    for session_id in order:
        source_value, target_value = first_sender[session_id]
        initiator = initiators.get(session_id)
        if initiator is not None:
            initiator_endpoint = _endpoint(initiator.ip, initiator.port)
            # The initiating party is known, so the row's source and target
            # are an OBSERVATION rather than an inference from who sent
            # payload first.
            other = target_value if source_value == initiator_endpoint else source_value
            source_value, target_value = initiator_endpoint, other
            initiator_field = observed(initiator_endpoint)
            endpoint_field = _observed_endpoint
        else:
            # Assumption Z-30: the initiator is NOT DETERMINED, and the
            # direction is an inference marked as an inference. The first
            # sender of payload is not a substitute for the initiating party.
            initiator_field = not_derivable()
            endpoint_field = _inferred_endpoint

        if session_id in high_confidence_protocols:
            # Assumption Z-43: several high-confidence protocols in the same
            # session give a compound label, sorted identifiers joined by a
            # plus sign - picking one of them would be arbitrary, and
            # dropping any a lie by omission.
            label = "+".join(sorted(high_confidence_protocols[session_id]))
            protocol_field = inferred(label, PROVENANCE_METHOD_PAYLOAD_SHAPE)
        elif session_id in low_confidence_protocols:
            label = "+".join(sorted(low_confidence_protocols[session_id]))
            protocol_field = inferred(label, PROVENANCE_METHOD_PAYLOAD_SHAPE)
        else:
            # Having seen TCP is an observation - failing to recognise the
            # application protocol does not turn it into an inference.
            protocol_field = observed(PROTOCOL_UNRECOGNIZED)

        rows[session_id] = {
            "session_id": observed(session_id),
            "source": endpoint_field(source_value),
            "target": endpoint_field(target_value),
            "direction": endpoint_field(f"{source_value} -> {target_value}"),
            "initiator": initiator_field,
            "protocol": protocol_field,
            "volume_bytes": observed(volume_bytes[session_id]),
            "packet_count": observed(packet_counts[session_id]),
        }

    return [
        {name: dataclasses.asdict(field) for name, field in rows[session_id].items()}
        for session_id in order
    ]


def vantage_point_limitations(
    *,
    host_count: int,
    session_count: int,
    payloadless_session_count: int,
    window_duration_s: float | None,
) -> list[str]:
    """Sentences about the blind spot: the constants plus one sentence with
    the numbers of THIS run.

    A general formula on its own is cheap and therefore worthless - the
    reader reads it as a legal disclaimer and skips it. A sentence stating
    how many addresses, how many sessions and how long a window were actually
    seen ties the limitation to this specific capture (FLOW-03).
    """
    if window_duration_s is None:
        window_sentence = "the capture time window was not established"
    else:
        window_sentence = f"the capture time window is {window_duration_s} s long"

    # The sentence with numbers stands FIRST, ahead of the fixed sentences: a
    # general formula read first is taken for a legal disclaimer and skipped,
    # while the numbers from this run tie the limitation to this capture.
    lines = [
        f"Scope of this run: addresses observed {host_count}, sessions with "
        f"payload {session_count}, sessions without a single segment carrying "
        f"payload {payloadless_session_count}, {window_sentence}."
    ]
    lines.extend(VANTAGE_POINT_LIMITATIONS)

    if payloadless_session_count:
        lines.append(
            f"TCP sessions made up exclusively of packets without payload: "
            f"{payloadless_session_count}. They have no row in the "
            "communication matrix, because they carry no segment to "
            "recognise - they are counted here so they do not vanish without "
            "a trace."
        )

    return lines
