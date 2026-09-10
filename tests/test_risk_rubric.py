"""Gate RISK-03: a severity from recorded criteria, identical on repetition.

`severity_to_risk` is a pure function without state: a hundred calls in any
order for the same input yield the same result, and a severity outside
`ALLOWED_SEVERITIES` ends in a `ValueError`, never in a default severity. No
test here checks a numeric risk value - the risk vocabulary is a closed set
of non-numeric labels (a prohibition of this plan).
"""

from __future__ import annotations

import pytest

from wayside.risk import ALLOWED_SEVERITIES, RUBRIC_CRITERIA, SEVERITY_TO_RISK, severity_to_risk


# --- Completeness of the rubric against ALLOWED_SEVERITIES -----------------


def test_rubric_criteria_has_nonempty_entry_for_every_allowed_severity():
    for severity in ALLOWED_SEVERITIES:
        assert RUBRIC_CRITERIA.get(severity), f"No rubric criterion for severity {severity!r}"


def test_severity_to_risk_maps_every_allowed_severity_to_nonempty_label():
    for severity in ALLOWED_SEVERITIES:
        risk = severity_to_risk(severity)
        assert risk, f"Empty risk for severity {severity!r}"


# --- ValueError on an unknown severity, never a default one -----------------


def test_severity_to_risk_raises_value_error_for_unknown_severity():
    with pytest.raises(ValueError):
        severity_to_risk("nonexistent")


def test_severity_to_risk_raises_value_error_for_empty_severity():
    with pytest.raises(ValueError):
        severity_to_risk("")


# --- Determinism: a hundred calls, identical result for the same input -----


def test_severity_to_risk_is_deterministic_across_repeated_calls():
    results = {severity_to_risk("high") for _ in range(100)}
    assert results == {severity_to_risk("high")}
    assert len(results) == 1


def test_two_findings_with_identical_severity_get_identical_risk():
    risk_a = severity_to_risk("medium")
    risk_b = severity_to_risk("medium")
    assert risk_a == risk_b


# --- Prohibition: no numeric indicator (MUST NOT: an aggregate Security Level) ---


def test_no_risk_label_can_be_converted_to_a_float():
    for label in SEVERITY_TO_RISK.values():
        with pytest.raises(ValueError):
            float(label)


def test_severity_to_risk_return_values_are_not_numeric():
    for severity in ALLOWED_SEVERITIES:
        risk = severity_to_risk(severity)
        with pytest.raises(ValueError):
            float(risk)
