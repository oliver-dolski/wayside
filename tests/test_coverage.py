"""Machine gate INGEST-04: the window threshold against the measured Modbus
polling interval, a positive and a negative case.

Entirely a unit test, without a subprocess and without a pcap file - the
events are built as dictionaries in the same shape as
`analysis["protocol_events"]`, by the helper at the top of the file, the same
pattern of brevity as `tests/test_risk_rubric.py` over a pure function.
"""

from __future__ import annotations

from wayside.coverage import (
    MIN_REQUESTS_FOR_CYCLE,
    POLL_CYCLE_WINDOW_MULTIPLIER,
    PollingCycle,
    build_coverage_section,
    coverage_warnings,
    measure_polling_cycles,
)


def _event(*, session_id: int, timestamp: float, direction: str = "request") -> dict:
    """Builds one event in the shape of `analysis["protocol_events"]`, limited
    to the fields `measure_polling_cycles` actually reads."""
    return {
        "session_id": session_id,
        "timestamp": timestamp,
        "direction": direction,
    }


# --- measure_polling_cycles: the empty and single-element input edge cases ---


def test_measure_polling_cycles_on_empty_list_returns_empty_list():
    assert measure_polling_cycles([]) == []


def test_measure_polling_cycles_on_single_request_returns_empty_list():
    events = [_event(session_id=0, timestamp=100.0)]
    assert measure_polling_cycles(events) == []


# --- measure_polling_cycles: two requests in one session ---


def test_measure_polling_cycles_on_two_requests_returns_one_entry_with_measured_gap():
    events = [
        _event(session_id=0, timestamp=100.0),
        _event(session_id=0, timestamp=103.5),
    ]
    cycles = measure_polling_cycles(events)
    assert cycles == [
        PollingCycle(session_id=0, measured_cycle_s=3.5, request_count=2)
    ]


def test_measure_polling_cycles_ignores_response_events():
    events = [
        _event(session_id=0, timestamp=100.0),
        _event(session_id=0, timestamp=100.01, direction="response"),
        _event(session_id=0, timestamp=103.5),
        _event(session_id=0, timestamp=103.51, direction="response"),
    ]
    cycles = measure_polling_cycles(events)
    assert cycles == [
        PollingCycle(session_id=0, measured_cycle_s=3.5, request_count=2)
    ]


def test_measure_polling_cycles_returns_longest_gap_for_unequal_intervals():
    # Intervals: 1.0, 5.0, 2.0 - the longest is 5.0, neither the last nor the mean.
    events = [
        _event(session_id=0, timestamp=0.0),
        _event(session_id=0, timestamp=1.0),
        _event(session_id=0, timestamp=6.0),
        _event(session_id=0, timestamp=8.0),
    ]
    cycles = measure_polling_cycles(events)
    assert cycles == [
        PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=4)
    ]


def test_measure_polling_cycles_on_two_sessions_returns_two_entries_ordered_by_session_id():
    events = [
        _event(session_id=1, timestamp=0.0),
        _event(session_id=0, timestamp=0.0),
        _event(session_id=1, timestamp=2.0),
        _event(session_id=0, timestamp=10.0),
    ]
    cycles = measure_polling_cycles(events)
    assert [c.session_id for c in cycles] == [0, 1]
    assert cycles[0].measured_cycle_s == 10.0
    assert cycles[1].measured_cycle_s == 2.0


def test_min_requests_for_cycle_is_two():
    assert MIN_REQUESTS_FOR_CYCLE == 2


# --- coverage_warnings: a strict threshold, both numbers in the text ---


def test_coverage_warnings_below_threshold_returns_one_warning_with_both_numbers():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    warnings = coverage_warnings(cycles=cycles, window_duration_s=5.01)
    assert len(warnings) == 1
    assert "5.01" in warnings[0]
    assert "5.0" in warnings[0]


def test_coverage_warnings_above_threshold_returns_empty_list():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=1.0, request_count=6)]
    warnings = coverage_warnings(cycles=cycles, window_duration_s=5.01)
    assert warnings == []


def test_coverage_warnings_exactly_at_threshold_returns_empty_list():
    # The condition is STRICT: a window equal to exactly multiplier*interval
    # trips no warning - equality is not "shorter than".
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    window_at_threshold = POLL_CYCLE_WINDOW_MULTIPLIER * 5.0
    warnings = coverage_warnings(cycles=cycles, window_duration_s=window_at_threshold)
    assert warnings == []


# --- coverage_warnings: the None and zero edge cases, without raising ---


def test_coverage_warnings_with_window_none_returns_empty_list_and_no_exception():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    assert coverage_warnings(cycles=cycles, window_duration_s=None) == []


def test_coverage_warnings_with_zero_measured_cycle_returns_empty_list_no_division_by_zero():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=0.0, request_count=2)]
    assert coverage_warnings(cycles=cycles, window_duration_s=0.5) == []


def test_coverage_warnings_on_empty_cycles_returns_empty_list():
    assert coverage_warnings(cycles=[], window_duration_s=5.01) == []


# --- build_coverage_section: the form of the analysis["coverage"] section ---


def test_build_coverage_section_carries_threshold_and_cycles_as_dicts():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    section = build_coverage_section(cycles=cycles, window_duration_s=5.01)
    assert section == {
        "window_duration_s": 5.01,
        "window_multiplier_threshold": POLL_CYCLE_WINDOW_MULTIPLIER,
        "polling_cycles": [
            {"session_id": 0, "measured_cycle_s": 5.0, "request_count": 2}
        ],
    }


def test_build_coverage_section_with_window_none_carries_none_and_empty_cycles():
    section = build_coverage_section(cycles=[], window_duration_s=None)
    assert section["window_duration_s"] is None
    assert section["polling_cycles"] == []


# --- the threshold tied to the fixtures of the Task 2 checkpoint (03-03-PLAN.md) ---


def test_threshold_fires_warning_on_short_window_fixture_numbers_and_not_on_full_window():
    # `modbus_poll_cycle_short_window.pcap`: a 5.01 s window, a 5.0 s interval -
    # it trips the warning for the multiplier chosen at the checkpoint (2x).
    short_window_cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    assert coverage_warnings(cycles=short_window_cycles, window_duration_s=5.01) != []

    # `modbus_poll_cycle_full_window.pcap`: a 5.01 s window, a 1.0 s interval -
    # it trips no warning. This half of the test is the one without which an
    # always-true condition would go unnoticed.
    full_window_cycles = [PollingCycle(session_id=0, measured_cycle_s=1.0, request_count=6)]
    assert coverage_warnings(cycles=full_window_cycles, window_duration_s=5.01) == []
