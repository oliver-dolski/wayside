"""HTTP dissector: recognition by the request line or by the response
status line (CHECK-03).

Recognition goes by the shape of the first payload bytes, never by port
number (assumption Z-46, the PROTO-01 pattern) - this phase's fixture sends
HTTP on a non-standard port precisely so that content-based recognition is
the only explanation for the result. The goal is to detect the PRESENCE of
HTTP traffic, not to decode it fully. The payload length is checked BEFORE
every indexed access (threat T-4-06): the recognising function `_recognize`
raises on no input, because the payload comes from an untrusted file. The
event returned by `dissect` carries not a single payload byte - only shape
metadata and a fixed name for the recognition basis (assumption Z-45,
threat T-4-07).
"""

from __future__ import annotations

from wayside.decode import Segment

__all__ = [
    "REQUEST_METHODS",
    "VERSION_TOKENS",
    "MIN_REQUEST_LEN",
    "DETECTION_BASIS_REQUEST",
    "DETECTION_BASIS_STATUS",
    "dissect",
]

REQUEST_METHODS: frozenset[bytes] = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS"}
)

VERSION_TOKENS: frozenset[bytes] = frozenset({b"HTTP/1.0", b"HTTP/1.1"})

# The length of the shortest possible request line: "GET / HTTP/1.1".
MIN_REQUEST_LEN = len(b"GET / HTTP/1.1")

DETECTION_BASIS_REQUEST = "http-request-line"
DETECTION_BASIS_STATUS = "http-status-line"

# A search limit for the first line - without it a payload without a single
# newline character would turn the search for the version token into a scan
# of the whole payload (threat T-4-06).
_MAX_FIRST_LINE_SCAN_LEN = 256


def _first_line(payload: bytes) -> bytes:
    """The bytes up to the first newline character, truncated to
    `_MAX_FIRST_LINE_SCAN_LEN`."""
    limit = min(len(payload), _MAX_FIRST_LINE_SCAN_LEN)
    newline_index = payload.find(b"\n", 0, limit)
    if newline_index == -1:
        return payload[:limit]
    return payload[:newline_index]


def _recognize(payload: bytes) -> str | None:
    """Checks the two HTTP recognition branches over `payload`. Returns the
    recognition basis or `None`, and never raises - the length is checked
    before any indexed access (threat T-4-06)."""
    if len(payload) < MIN_REQUEST_LEN:
        return None

    first_line = _first_line(payload)

    for method in REQUEST_METHODS:
        prefix = method + b" "
        if payload.startswith(prefix) and any(
            token in first_line for token in VERSION_TOKENS
        ):
            return DETECTION_BASIS_REQUEST

    for token in VERSION_TOKENS:
        prefix = token + b" "
        if payload.startswith(prefix):
            status_code = payload[len(prefix) : len(prefix) + 3]
            if len(status_code) == 3 and status_code.isdigit():
                return DETECTION_BASIS_STATUS

    return None


def dissect(segments: list[Segment]) -> list[dict]:
    """Iterates the FULL `segments` list in file order, skipping every
    segment that does not start with an HTTP request line or status line -
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
