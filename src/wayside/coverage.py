"""Assessment of capture window coverage against the measured Modbus
polling interval (INGEST-04): a pure function with no state and no I/O, in
the same style as `src/wayside/risk.py`.

Criterion 1 of phase 3 in `ROADMAP.md` speaks literally of a capture
"shorter than the observed polling cycle". Taken literally that is a
condition which is never true: the capture window by definition spans every
interval measured inside it, so it is never shorter than one. A literal
implementation would give a dead condition and a test that never fires on
any data.

The operationalisation adopted in this module: the warning fires when the
capture window is shorter than `POLL_CYCLE_WINDOW_MULTIPLIER` times the
longest measured interval between consecutive requests in the same session.
The multiplier value was chosen at the Task 2 decision checkpoint of
03-03-PLAN.md (2026-09-04, human ruling: option `multiplier-2`, value 2.0) -
two repetitions are the smallest observation that tells a cycle from a
coincidence, and a lower threshold fires the warning less often on captures
that genuinely suffice.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

__all__ = [
    "POLL_CYCLE_WINDOW_MULTIPLIER",
    "MIN_REQUESTS_FOR_CYCLE",
    "PollingCycle",
    "measure_polling_cycles",
    "coverage_warnings",
    "build_coverage_section",
]

# Operational threshold chosen at the Task 2 decision checkpoint,
# 03-03-PLAN.md.
POLL_CYCLE_WINDOW_MULTIPLIER: float = 2.0

# One point does not define an interval.
MIN_REQUESTS_FOR_CYCLE: int = 2


@dataclass(frozen=True)
class PollingCycle:
    """A measured interval between consecutive Modbus requests in one
    session.

    `measured_cycle_s` is an OBSERVATION from this capture, not a declared
    polling period of the device - a single measured interval is never
    presented as a confirmed polling cycle.
    """

    session_id: int
    measured_cycle_s: float
    request_count: int


def measure_polling_cycles(events: list[dict]) -> list[PollingCycle]:
    """Measures the longest interval between consecutive requests in each
    session.

    Takes `events` in the shape of `analysis["protocol_events"]`. Events with
    a direction other than `request` are ignored. Grouping goes by
    `session_id` in a `dict`, never in a `set` - determinism of file order is
    a contract inherited from Phase 2 here. Sessions with fewer than
    `MIN_REQUESTS_FOR_CYCLE` requests are skipped with no entry: one point
    does not define an interval, and guessing one from a single event would
    be an invented number. The returned list is ordered ascending by session
    identifier.
    """
    sessions: dict[int, list[float]] = {}
    for event in events:
        if event.get("direction") != "request":
            continue
        session_id = event["session_id"]
        sessions.setdefault(session_id, []).append(event["timestamp"])

    cycles: list[PollingCycle] = []
    for session_id in sorted(sessions):
        timestamps = sessions[session_id]
        if len(timestamps) < MIN_REQUESTS_FOR_CYCLE:
            continue
        # Intervals between consecutive timestamps IN FILE ORDER (not sorted
        # values) - the longest of them is the most conservative value
        # (assumption Z-15 from 03-03-PLAN.md).
        longest = max(
            second - first for first, second in zip(timestamps, timestamps[1:])
        )
        cycles.append(
            PollingCycle(
                session_id=session_id,
                measured_cycle_s=round(longest, 6),
                request_count=len(timestamps),
            )
        )
    return cycles


def coverage_warnings(
    *, cycles: list[PollingCycle], window_duration_s: float | None
) -> list[str]:
    """Builds warnings about a capture window too short against the measured
    polling interval.

    A window equal to `None` (a capture with no packets) gives an empty list
    - there is nothing to measure. A measured interval equal to zero gives an
    empty list for that session: the threshold condition at zero is trivially
    false, and putting a division there would be a division by zero. For
    every remaining session the condition is STRICT - the warning is raised
    when the window is SMALLER than `POLL_CYCLE_WINDOW_MULTIPLIER` times the
    measured interval; equality does not fire it.
    """
    if window_duration_s is None:
        return []

    warnings: list[str] = []
    for cycle in cycles:
        if cycle.measured_cycle_s == 0:
            continue
        threshold = POLL_CYCLE_WINDOW_MULTIPLIER * cycle.measured_cycle_s
        if window_duration_s >= threshold:
            continue
        warnings.append(
            f"The capture window lasts {window_duration_s} seconds, session "
            f"{cycle.session_id} carries a longest measured interval between "
            f"consecutive requests of {cycle.measured_cycle_s} seconds "
            f"against the adopted threshold (multiplier "
            f"{POLL_CYCLE_WINDOW_MULTIPLIER}). The observed value is a single "
            "interval between requests in this session, not a confirmed "
            "polling cycle."
        )
    return warnings


def build_coverage_section(
    *, cycles: list[PollingCycle], window_duration_s: float | None
) -> dict:
    """Assembles the `coverage` section of the `analysis.json` dictionary."""
    return {
        "window_duration_s": (
            round(window_duration_s, 6) if window_duration_s is not None else None
        ),
        "window_multiplier_threshold": POLL_CYCLE_WINDOW_MULTIPLIER,
        "polling_cycles": [dataclasses.asdict(cycle) for cycle in cycles],
    }
