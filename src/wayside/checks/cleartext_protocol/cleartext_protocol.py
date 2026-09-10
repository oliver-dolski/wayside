"""Evaluator of the `cleartext-protocol` check (CHECK-03).

It reads ONLY `analysis["protocol_events"]`, never packets, no decoding
module and no dissector module - checks see the model only, never the
internal details of decoding (02-RESEARCH.md, Anti-Pattern 1). A pure
function, zero I/O, zero state shared between calls.

It emits one finding per (session identifier, cleartext protocol
identifier) pair (assumption Z-47), never one finding per event: a single
HTTP session carries dozens of events of the same protocol, and a finding
for each of them would be noise instead of signal.
"""

from __future__ import annotations

__all__ = ["evaluate", "CLEARTEXT_PROTOCOLS"]

CLEARTEXT_PROTOCOLS = frozenset({"telnet", "ftp", "http"})


def evaluate(analysis: dict) -> list[dict]:
    """For every (session identifier, cleartext protocol identifier) pair
    it remembers the FIRST event encountered in input order and returns one
    finding for that pair, with the evidence (packet number, session
    identifier) of that first event.

    Indexing `analysis["protocol_events"]` is DELIBERATELY demanding: a
    model without that key is a model of invalid shape, and `KeyError`
    signals it outright instead of quietly returning an empty list, which
    would look like a legal absence of events.

    A dictionary plus a separate order list, never a set on the path to
    serialisation (the shared pattern of this repository since Phase 3) -
    result order goes into the artifact, and a set does not have it."""
    first_seen: dict[tuple[int, str], dict] = {}
    order: list[tuple[int, str]] = []

    for event in analysis["protocol_events"]:
        protocol = event.get("protocol")
        if protocol not in CLEARTEXT_PROTOCOLS:
            continue
        key = (event["session_id"], protocol)
        if key in first_seen:
            continue
        first_seen[key] = event
        order.append(key)

    results: list[dict] = []
    for key in order:
        event = first_seen[key]
        results.append(
            {
                "evidence": {
                    "packet_number": event["packet_number"],
                    "session_id": event["session_id"],
                }
            }
        )
    return results
