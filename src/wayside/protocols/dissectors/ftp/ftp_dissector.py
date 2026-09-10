"""FTP dissector: recognising the control channel by a command verb or by
a reply code (CHECK-03).

Recognition goes by the shape of the first payload bytes, never by port
number (assumption Z-46, the PROTO-01 pattern) - the goal is to detect the
PRESENCE of FTP traffic, not to decode it fully. The payload length is
checked BEFORE every indexed access (threat T-4-06): the recognising
function `_recognize` raises on no input, because the payload comes from an
untrusted file. The event returned by `dissect` carries not a single
payload byte - only shape metadata and a fixed name for the recognition
basis (assumption Z-45, threat T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "CONTROL_VERBS",
    "MIN_COMMAND_LEN",
    "DETECTION_BASIS_COMMAND",
    "DETECTION_BASIS_REPLY",
    "dissect",
]

# FTP control channel command verbs: supplying a user name (USER),
# supplying a password (PASS), retrieving a file (RETR), storing a file
# (STOR), listing (LIST), ending the session (QUIT), the current directory
# (PWD), changing directory (CWD), the transfer type (TYPE), active mode
# (PORT), passive mode (PASV). An immutable set, compared without case
# folding - the protocol exchanges them in upper case.
CONTROL_VERBS: frozenset[bytes] = frozenset(
    {
        b"USER",
        b"PASS",
        b"RETR",
        b"STOR",
        b"LIST",
        b"QUIT",
        b"PWD",
        b"CWD",
        b"TYPE",
        b"PORT",
        b"PASV",
    }
)

# The length of the shortest verb (PWD/CWD, three bytes) plus one delimiter
# byte - the same minimum length works for the reply code branch (three
# digits plus one delimiter byte).
MIN_COMMAND_LEN = 4

DETECTION_BASIS_COMMAND = "ftp-control-verb"
DETECTION_BASIS_REPLY = "ftp-reply-code"

_COMMAND_DELIMITERS = (0x20, 0x0D)  # space or carriage return
_REPLY_DELIMITERS = (0x20, 0x2D)  # space or hyphen


def _recognize(payload: bytes) -> str | None:
    """Checks the two FTP recognition branches over `payload`. Returns the
    recognition basis or `None`, and never raises - the length is checked
    before any indexed access (threat T-4-06)."""
    if len(payload) < MIN_COMMAND_LEN:
        return None

    for verb in CONTROL_VERBS:
        if not payload.startswith(verb):
            continue
        next_index = len(verb)
        if next_index < len(payload) and payload[next_index] in _COMMAND_DELIMITERS:
            return DETECTION_BASIS_COMMAND

    first_three = payload[:3]
    if first_three.isdigit() and payload[3] in _REPLY_DELIMITERS:
        return DETECTION_BASIS_REPLY

    return None


def dissect(segments: list[Segment]) -> list[dict]:
    """Iterates the FULL `segments` list in file order, skipping every
    segment that does not start with an FTP command verb or reply code -
    with no assumption about whether another dissector has already processed
    that segment. The direction follows the first-payload-sender rule for a
    given session, copied from
    `wayside.protocols.modbus_tcp.dissect_all`: the party that first sent, in
    that session, a payload passing recognition is the client."""
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
