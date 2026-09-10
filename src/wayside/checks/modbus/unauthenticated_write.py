"""Evaluator of the `modbus-unauthenticated-write` check (CHECK-04).

It reads ONLY `analysis["protocol_events"]`, never packets and never the
pcap file - checks see the model only, never the internal details of
decoding (02-RESEARCH.md, Anti-Pattern 1). A pure function, zero I/O.
"""

from __future__ import annotations

__all__ = ["evaluate"]


def evaluate(analysis: dict) -> list[dict]:
    """Selects write-request events and returns for each a finding with
    the evidence (packet number, session identifier). The check metadata
    (title, severity, rationale, standard citation, remediation) is attached
    by the engine from the YAML file, not duplicated here.

    Indexing `analysis["protocol_events"]` is DELIBERATELY demanding: a
    model without that key is a model of invalid shape, and `KeyError`
    signals it outright instead of quietly returning an empty list, which
    would look like a legal absence of events."""
    results: list[dict] = []
    for event in analysis["protocol_events"]:
        if event.get("kind") == "write" and event.get("direction") == "request":
            results.append(
                {
                    "evidence": {
                        "packet_number": event["packet_number"],
                        "session_id": event["session_id"],
                    }
                }
            )
    return results
