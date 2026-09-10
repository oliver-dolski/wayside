"""Telnet dissector: recognition by the option negotiation sequence
(CHECK-03).

Recognition goes by the shape of the first payload bytes, never by port
number (assumption Z-46, the PROTO-01 pattern) - the goal is to detect the
PRESENCE of the Telnet protocol in the traffic, not to decode it fully. The
payload length is checked BEFORE every indexed access (threat T-4-06): the
recognising function `_recognize` raises on no input, because the payload
comes from an untrusted file. The event returned by `dissect` carries not a
single payload byte - only shape metadata and a fixed name for the
recognition basis (assumption Z-45, threat T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "IAC",
    "NEGOTIATION_COMMANDS",
    "MIN_NEGOTIATION_LEN",
    "DETECTION_BASIS",
    "dissect",
]

IAC = 0xFF

# Telnet negotiation commands: WILL (0xFB), WONT (0xFC), DO (0xFD),
# DONT (0xFE), SB - the start of subnegotiation (0xFA). An immutable set.
NEGOTIATION_COMMANDS: frozenset[int] = frozenset({0xFA, 0xFB, 0xFC, 0xFD, 0xFE})

MIN_NEGOTIATION_LEN = 3

DETECTION_BASIS = "telnet-iac-negotiation"


def _recognize(payload: bytes) -> str | None:
    """Checks whether `payload` starts with a Telnet negotiation sequence.
    Returns `DETECTION_BASIS` or `None`, and never raises - the length is
    checked before any indexed access (threat T-4-06)."""
    if len(payload) < MIN_NEGOTIATION_LEN:
        return None
    if payload[0] != IAC:
        return None
    if payload[1] not in NEGOTIATION_COMMANDS:
        return None
    # The third byte (the option number) takes any value - that is a ruling,
    # not an omission: the option number does not narrow the set of
    # recognised sequences.
    return DETECTION_BASIS


def dissect(segments: list[Segment]) -> list[dict]:
    """Iterates the FULL `segments` list in file order, skipping every
    segment that does not start with a Telnet negotiation sequence - with no
    assumption about whether another dissector has already processed that
    segment. The direction follows the first-payload-sender rule for a given
    session, copied from `wayside.protocols.modbus_tcp.dissect_all`: the
    party that first sent, in that session, a payload passing recognition is
    the client."""
    events: list[dict] = []
    session_clients: dict[int, tuple[str, int]] = {}

    for segment in segments:
        basis = _recognize(segment.payload)
        if basis is None:
            continue

        client_endpoint = session_clients.get(segment.session_id)
        if client_endpoint is None:
            client_endpoint = (segment.src_ip, segment.src_port)
            session_clients[segment.session_id] = client_endpoint

        direction = (
            "request"
            if (segment.src_ip, segment.src_port) == client_endpoint
            else "response"
        )

        events.append(
            {
                "packet_number": segment.packet_number,
                "session_id": segment.session_id,
                "direction": direction,
                "basis": basis,
                "src_ip": segment.src_ip,
                "dst_ip": segment.dst_ip,
                "timestamp": segment.timestamp,
            }
        )

    return events
