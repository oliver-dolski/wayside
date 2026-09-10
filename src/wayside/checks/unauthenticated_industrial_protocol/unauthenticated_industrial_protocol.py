"""Evaluator of the `unauthenticated-industrial-protocol` check
(CHECK-05).

Four things this module does outright:

1. It reads ONLY the serialised model (`analysis["protocol_events"]`),
   never packets, no decoding module and no dissector module - checks see
   the model only, never the internal details of decoding (02-RESEARCH.md,
   Anti-Pattern 1).
2. It emits one finding per SESSION, not per event (assumption Z-57): a
   session with one write and ten reads would give eleven identical
   findings, that is the noise the phase research names outright in its
   Anti-Patterns section.
3. It does NOT filter by event classification (`kind`) - the condition is
   the mere PRESENCE of traffic of a protocol from the
   `UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS` list, not the kind of operation.
   That is the whole difference against the write check
   (`modbus-unauthenticated-write`): that check fires on a write operation,
   this check fires on the use of the protocol itself, regardless of whether
   a write occurred in the session (04-RESEARCH.md, Pitfall 9).
4. The set of protocols covered by the check lives HERE, not in the
   dissector manifest (assumption Z-60) - recognising a protocol and
   judging its properties are two responsibilities.
"""

from __future__ import annotations

__all__ = ["evaluate", "UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS"]

# The membership criterion: an industrial protocol whose specification
# carries no mechanism for authenticating the sender. That is what a future
# protocol has to meet to enter here - without recording the criterion the
# constant becomes a list with no rule.
UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS: frozenset[str] = frozenset({"modbus-tcp"})


def evaluate(analysis: dict) -> list[dict]:
    """For every session carrying at least one protocol event from
    `UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS` it remembers the FIRST event of
    that session in input order (assumption Z-58) and returns for it one
    finding with the evidence (packet number, session identifier) of that
    first event.

    Indexing `analysis["protocol_events"]` is DELIBERATELY demanding: a
    model without that key is a model of invalid shape, and `KeyError`
    signals it outright instead of quietly returning an empty list, which
    would look like a legal absence of events.

    A dictionary plus a separate order list, never a set on the path to
    serialisation (the shared pattern of this repository since Phase 3) -
    result order goes into the artifact, and a set does not have it."""
    first_seen: dict[int, dict] = {}
    order: list[int] = []

    for event in analysis["protocol_events"]:
        protocol = event.get("protocol")
        if protocol not in UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS:
            continue
        session_id = event["session_id"]
        if session_id in first_seen:
            continue
        first_seen[session_id] = event
        order.append(session_id)

    results: list[dict] = []
    for session_id in order:
        event = first_seen[session_id]
        results.append(
            {
                "evidence": {
                    "packet_number": event["packet_number"],
                    "session_id": event["session_id"],
                }
            }
        )
    return results
