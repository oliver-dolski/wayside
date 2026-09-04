"""Bramka maszynowa INGEST-04: prog okna wobec zmierzonego odstepu odpytywania
Modbus, przypadek pozytywny i negatywny.

W calosci jednostkowa, bez subprocessu i bez pliku pcap - zdarzenia sa
budowane jako slowniki w tym samym ksztalcie co `analysis["protocol_events"]`,
przez funkcje pomocnicza na gorze pliku, ten sam wzorzec zwiezlosci co
`tests/test_risk_rubric.py` nad czysta funkcja.
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
    """Buduje jeden zdarzenie w ksztalcie `analysis["protocol_events"]`,
    ograniczone do pol, ktore `measure_polling_cycles` faktycznie czyta."""
    return {
        "session_id": session_id,
        "timestamp": timestamp,
        "direction": direction,
    }


# --- measure_polling_cycles: przypadki brzegowe pustego i jednoelementowego wejscia ---


def test_measure_polling_cycles_on_empty_list_returns_empty_list():
    assert measure_polling_cycles([]) == []


def test_measure_polling_cycles_on_single_request_returns_empty_list():
    events = [_event(session_id=0, timestamp=100.0)]
    assert measure_polling_cycles(events) == []


# --- measure_polling_cycles: dwa zadania w jednej sesji ---


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
    # Odstepy: 1.0, 5.0, 2.0 - najdluzszy jest 5.0, nie ostatni ani sredni.
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


# --- coverage_warnings: prog ostry, obie liczby w tresci ---


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
    # Warunek jest OSTRY: okno rowne dokladnie mnoznik*odstep nie zapala
    # ostrzezenia - rownosc nie jest "krotszy niz".
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    window_at_threshold = POLL_CYCLE_WINDOW_MULTIPLIER * 5.0
    warnings = coverage_warnings(cycles=cycles, window_duration_s=window_at_threshold)
    assert warnings == []


# --- coverage_warnings: przypadki brzegowe None i zero, bez wyjatku ---


def test_coverage_warnings_with_window_none_returns_empty_list_and_no_exception():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    assert coverage_warnings(cycles=cycles, window_duration_s=None) == []


def test_coverage_warnings_with_zero_measured_cycle_returns_empty_list_no_division_by_zero():
    cycles = [PollingCycle(session_id=0, measured_cycle_s=0.0, request_count=2)]
    assert coverage_warnings(cycles=cycles, window_duration_s=0.5) == []


def test_coverage_warnings_on_empty_cycles_returns_empty_list():
    assert coverage_warnings(cycles=[], window_duration_s=5.01) == []


# --- build_coverage_section: forma sekcji analysis["coverage"] ---


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


# --- prog wiazany z fixture'ami z checkpointu w Task 2 (03-03-PLAN.md) ------


def test_threshold_fires_warning_on_short_window_fixture_numbers_and_not_on_full_window():
    # `modbus_poll_cycle_short_window.pcap`: okno 5.01 s, odstep 5.0 s -
    # zapala ostrzezenie dla mnoznika wybranego w checkpoincie (mnoznik-2).
    short_window_cycles = [PollingCycle(session_id=0, measured_cycle_s=5.0, request_count=2)]
    assert coverage_warnings(cycles=short_window_cycles, window_duration_s=5.01) != []

    # `modbus_poll_cycle_full_window.pcap`: okno 5.01 s, odstep 1.0 s - nie
    # zapala ostrzezenia. Ta polowa testu jest ta, bez ktorej warunek zawsze
    # prawdziwy przeszedlby niezauwazony.
    full_window_cycles = [PollingCycle(session_id=0, measured_cycle_s=1.0, request_count=6)]
    assert coverage_warnings(cycles=full_window_cycles, window_duration_s=5.01) == []
