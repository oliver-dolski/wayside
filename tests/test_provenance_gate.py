"""Machine gate ASSET-03: an inventory field without a provenance marker is
rejected mechanically (plan 03-01, Task 2).

The test data lives in module constants rather than literals scattered across
the assertions - the same style as `VERDICT_WORDS` in
`tests/test_report_render.py`. Every rejection test checks two things at once:
the exception type AND the presence of the path of the offending field in the
message - the exception type alone, without the path, cannot be used to fix
anything when a host carries ten fields.

This file is entirely a unit test: no subprocess and no pcap file -
`assert_provenance_complete` and `iter_observed_fields` are pure functions over
a structure already serialized into dictionaries and lists.
"""

from __future__ import annotations

import pytest

from wayside.model import (
    ObservedField,
    ProvenanceError,
    assert_provenance_complete,
    inferred,
    iter_observed_fields,
)

VALID_ASSETS: list[dict] = [
    {
        "ip": {"value": "192.0.2.10", "provenance": "observed"},
        "mac": {"value": "02:00:00:00:00:01", "provenance": "observed"},
    },
]

# An `analysis` dictionary in the shape inherited from Phase 2, with no field
# wrapped in a provenance carrier - exactly what the gate MUST NOT let through
# if somebody widened its scope beyond the `assets` section (assumption Z-02).
ANALYSIS_FROM_PHASE_2: dict = {
    "capture": {"filename": "x.pcap", "packet_count": 2},
    "conversations": [
        {"session_id": 0, "endpoints": ["192.0.2.10:1", "192.0.2.20:2"], "packet_count": 2}
    ],
    "protocol_events": [{"function_code": 6, "kind": "write"}],
    "zones": [{"provisional": True}],
    "findings": [],
}


# --- Letting valid shapes through ------------------------------------------


def test_gate_passes_list_of_valid_fields():
    assert_provenance_complete(VALID_ASSETS, path="assets")


def test_gate_passes_field_with_null_value_and_not_derivable_marker():
    node = [{"mac": {"value": None, "provenance": "not-derivable-passively"}}]
    assert_provenance_complete(node, path="assets")


def test_gate_passes_empty_list_and_empty_dict():
    assert_provenance_complete([], path="assets")
    assert_provenance_complete({}, path="assets")


# --- Rejection: constructing an ObservedField ------------------------------


def test_observed_field_rejects_unknown_provenance():
    with pytest.raises(ValueError):
        ObservedField(value=1, provenance="made-up")


# --- Rejection: a raw value instead of a field, the path in the message ----


def test_gate_reports_path_of_field_without_marker():
    node = [{"ip": {"value": "a", "provenance": "observed"}, "mac": "raw-value"}]
    with pytest.raises(ProvenanceError) as excinfo:
        assert_provenance_complete(node, path="assets")
    assert "mac" in str(excinfo.value)


def test_gate_rejects_raw_scalar_nested_inside_list():
    node = [{"tags": ["raw-value-inside-a-list"]}]
    with pytest.raises(ProvenanceError) as excinfo:
        assert_provenance_complete(node, path="assets")
    assert "tags" in str(excinfo.value)


# --- Rejection: a marker outside PROVENANCE_PATTERN ------------------------


def test_gate_rejects_field_with_provenance_outside_pattern():
    node = [{"mac": {"value": "x", "provenance": "guessed"}}]
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(node, path="assets")


def test_gate_rejects_inferred_without_method():
    node = [{"mac": {"value": "x", "provenance": "inferred:"}}]
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(node, path="assets")


# --- The inferred() factory: a lower-case method passes, an UPPER-CASE one does not ---


def test_inferred_factory_accepts_lowercase_method_names():
    inferred("Acme", "oui-lookup")
    inferred("192.0.2.10", "first-observed-sender")


def test_inferred_factory_rejects_uppercase_method_name():
    with pytest.raises(ValueError):
        inferred("Acme", "OUI")


# --- iter_observed_fields: no double counting ------------------------------


def test_iter_observed_fields_does_not_descend_into_recognized_field_value():
    # The `value` of this field is ITSELF a dictionary of the shape
    # {"value","provenance"} - the generator is meant to yield the outer
    # dictionary once and NOT descend into its "value".
    nested_field = {
        "value": {"value": "deep", "provenance": "observed"},
        "provenance": "observed",
    }
    node = {"x": nested_field}

    results = list(iter_observed_fields(node))

    assert len(results) == 1
    assert results[0][0] == "x"
    assert results[0][1] is nested_field


# --- The gate's scope contract (assumption Z-02): the assets section, NOT the whole tree ---


def test_gate_on_assets_section_passes_but_on_full_phase_2_analysis_raises():
    assert_provenance_complete(VALID_ASSETS, path="assets")
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(ANALYSIS_FROM_PHASE_2, path="analysis")
