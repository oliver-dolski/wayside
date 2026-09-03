"""Bramka STD-06: model strefy jest wypelniony przed powolaniem na wymaganie
systemowe.

`resolve` z modelem o pustej liscie stref podnosi `StandardsError`, a model
wypelniony zwraca powolanie - to jest cale maszynowe znaczenie STD-06: model
strefy istnieje wypelniony PRZED powolaniem, bo bez niego powolanie w ogole
nie powstaje.
"""

from __future__ import annotations

import pytest

from wayside.standards import mapper
from wayside.zones import DEFAULT_CONDUIT_ID, DEFAULT_ZONE_ID, build_zone_model


# --- build_zone_model: jedna strefa, jeden kanal, oba provisional -----------


def test_build_zone_model_returns_exactly_one_zone_and_one_conduit():
    model = build_zone_model(
        observed_ips=["192.0.2.10", "192.0.2.20"], observed_protocols=["modbus-tcp"]
    )

    assert len(model["zones"]) == 1
    assert len(model["conduits"]) == 1
    assert model["zones"][0]["id"] == DEFAULT_ZONE_ID
    assert model["conduits"][0]["id"] == DEFAULT_CONDUIT_ID


def test_build_zone_model_marks_zone_and_conduit_provisional_with_nonempty_note():
    model = build_zone_model(observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp"])

    zone = model["zones"][0]
    conduit = model["conduits"][0]
    assert zone["provisional"] is True
    assert conduit["provisional"] is True
    assert zone["note"]
    assert conduit["note"]


def test_build_zone_model_sorts_zone_members_regardless_of_input_order():
    model_a = build_zone_model(
        observed_ips=["192.0.2.20", "192.0.2.10", "192.0.2.30"],
        observed_protocols=["modbus-tcp"],
    )
    model_b = build_zone_model(
        observed_ips=["192.0.2.10", "192.0.2.30", "192.0.2.20"],
        observed_protocols=["modbus-tcp"],
    )

    expected = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
    assert model_a["zones"][0]["members"] == expected
    assert model_b["zones"][0]["members"] == expected


def test_build_zone_model_conduit_carries_observed_protocols_sorted():
    model = build_zone_model(
        observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp", "ethernet-ip"]
    )

    assert model["conduits"][0]["protocols"] == ["ethernet-ip", "modbus-tcp"]
    assert model["conduits"][0]["zones"] == [DEFAULT_ZONE_ID]


def test_build_zone_model_on_no_observed_traffic_still_returns_provisional_placeholder():
    model = build_zone_model(observed_ips=[], observed_protocols=[])

    assert model["zones"][0]["members"] == []
    assert model["conduits"][0]["protocols"] == []
    assert model["zones"][0]["provisional"] is True


# --- resolve: model strefy wymagany PRZED powolaniem (STD-06) ---------------


def test_resolve_with_empty_zones_list_raises_standards_error():
    with pytest.raises(mapper.StandardsError):
        mapper.resolve("IEC-62443-3-3", "SR 1.1", zone_model={"zones": [], "conduits": []})


def test_resolve_with_populated_zone_model_returns_standard_ref():
    zone_model = build_zone_model(observed_ips=["192.0.2.10"], observed_protocols=["modbus-tcp"])

    ref = mapper.resolve("IEC-62443-3-3", "SR 1.1", zone_model=zone_model)

    assert ref.standard == "IEC-62443-3-3"
    assert ref.clause == "SR 1.1"
    assert ref.clause_title
    assert ref.paraphrase
    assert ref.verified is False
