"""Bramka RISK-03: waga z zapisanych kryteriow, identyczna przy powtorzeniu.

`severity_to_risk` jest czysta funkcja bez stanu: sto wywolan w dowolnej
kolejnosci dla tego samego wejscia daje ten sam wynik, a waga poza
`ALLOWED_SEVERITIES` konczy sie `ValueError`, nigdy waga domyslna. Zaden
test tutaj nie sprawdza wartosci liczbowej ryzyka - slownik ryzyka jest
zamknietym zbiorem etykiet nieliczbowych (prohibicja tego planu).
"""

from __future__ import annotations

import pytest

from wayside.risk import ALLOWED_SEVERITIES, RUBRIC_CRITERIA, SEVERITY_TO_RISK, severity_to_risk


# --- Kompletnosc rubryki wobec ALLOWED_SEVERITIES ---------------------------


def test_rubric_criteria_has_nonempty_entry_for_every_allowed_severity():
    for severity in ALLOWED_SEVERITIES:
        assert RUBRIC_CRITERIA.get(severity), f"Brak kryterium rubryki dla wagi {severity!r}"


def test_severity_to_risk_maps_every_allowed_severity_to_nonempty_label():
    for severity in ALLOWED_SEVERITIES:
        risk = severity_to_risk(severity)
        assert risk, f"Puste ryzyko dla wagi {severity!r}"


# --- ValueError na wadze nieznanej, nigdy waga domyslna ---------------------


def test_severity_to_risk_raises_value_error_for_unknown_severity():
    with pytest.raises(ValueError):
        severity_to_risk("nieistniejaca")


def test_severity_to_risk_raises_value_error_for_empty_severity():
    with pytest.raises(ValueError):
        severity_to_risk("")


# --- Determinizm: sto wywolan, identyczny wynik dla tego samego wejscia ----


def test_severity_to_risk_is_deterministic_across_repeated_calls():
    results = {severity_to_risk("high") for _ in range(100)}
    assert results == {severity_to_risk("high")}
    assert len(results) == 1


def test_two_findings_with_identical_severity_get_identical_risk():
    risk_a = severity_to_risk("medium")
    risk_b = severity_to_risk("medium")
    assert risk_a == risk_b


# --- Prohibicja: brak wskaznika liczbowego (MUST NOT zbiorczy Security Level) ---


def test_no_risk_label_can_be_converted_to_a_float():
    for label in SEVERITY_TO_RISK.values():
        with pytest.raises(ValueError):
            float(label)


def test_severity_to_risk_return_values_are_not_numeric():
    for severity in ALLOWED_SEVERITIES:
        risk = severity_to_risk(severity)
        with pytest.raises(ValueError):
            float(risk)
