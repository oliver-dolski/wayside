"""Building the host inventory from segments: IP address and MAC address,
every field with its own provenance marker (ASSET-01, ASSET-03).

This list is NOT a list of devices visible on the network - it is a list of
IP addresses that appeared in traffic captured at this listening point. A
capture shows only the traffic that reached the probe (the inventory is
never to be presented as a complete list of devices on the network).

Assumption Z-03: one IP address carries at most one MAC address - the first
observed in file order. A second, different MAC address for the same IP
switches the `mac` field to `not-derivable-passively` instead of picking one
of the two: a capture point behind a router sees the router's layer two
address, not the host's, so presenting one of the two as `observed` would
mean presenting someone else's address as the host's.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from wayside.assets.oui import PROVENANCE_METHOD_OUI
from wayside.decode import Segment
from wayside.model import (
    PROVENANCE_NOT_DERIVABLE,
    ObservedField,
    inferred,
    not_derivable,
    observed,
)

__all__ = [
    "ROLE_MODBUS_CLIENT",
    "ROLE_MODBUS_SERVER",
    "ROLE_MODBUS_BOTH",
    "ROLE_UNDETERMINED",
    "ROLE_LABELS",
    "FORBIDDEN_ROLE_LABELS",
    "CONFIDENCE_LEVELS",
    "MIN_EVENTS_FOR_MEDIUM_CONFIDENCE",
    "build_assets",
]

ROLE_MODBUS_CLIENT = "Modbus client"
ROLE_MODBUS_SERVER = "Modbus server"
ROLE_MODBUS_BOTH = "Modbus client and server"
ROLE_UNDETERMINED = "undetermined"

# A closed set of role labels, modelled on `ALLOWED_SEVERITIES` in
# `risk.py` (assumption Z-26). All four values are BEHAVIOURAL: they say
# what an address did in the observed traffic, not what a device is in the
# process. An organisational label requires knowledge a passive capture does
# not carry, and a closed set turns that discipline from the author's
# convention into a property of the code.
ROLE_LABELS: tuple[str, ...] = (
    ROLE_MODBUS_CLIENT,
    ROLE_MODBUS_SERVER,
    ROLE_MODBUS_BOTH,
    ROLE_UNDETERMINED,
)

# Organisational labels, that is TEST DATA for the machine gate from plan
# 03-06 Task 3 - in the same style as `EXTERNAL_DISSECTOR_PATTERNS` in
# `tests/test_no_external_dissector.py`. They live in production code so
# that the gate and the implementation have one source of truth instead of
# two lists that drift at the first change. Each of them would assert
# something about a device's function in the process - and that cannot be
# established from traffic direction in a single window (03-RESEARCH.md,
# Pitfall 4).
FORBIDDEN_ROLE_LABELS: tuple[str, ...] = (
    "historian",
    "HMI",
    "engineering workstation",
    "operator workstation",
    "SCADA",
    "PLC",
    "RTU",
    "IED",
)

# A closed set of role confidence levels (assumption Z-27). There is no
# `high` value and there will not be one: the limitation is not the sample
# size but the fact that the observed window may not cover the opposite
# behaviour - an engineer's laptop that only read for fifteen minutes looks
# the same at ten events as at a thousand. A third level in the set would be
# an invitation to use it.
CONFIDENCE_LEVELS: tuple[str, ...] = ("low", "medium")

# The medium confidence threshold (assumption Z-28). Three events is the
# smallest number at which a direction stops being a single exchange. The
# number is arbitrary to exactly the same degree as any other, which is why
# it stands as a named constant rather than as a number inside a
# condition.
MIN_EVENTS_FOR_MEDIUM_CONFIDENCE = 3

PROVENANCE_METHOD_ROLE = "modbus-traffic-direction"
PROVENANCE_METHOD_ROLE_CONFIDENCE = "event-count-and-direction"


def build_assets(
    *,
    segments: list[Segment],
    events: list[dict] | None = None,
    vendor_lookup: Callable[[str], str | None] | None = None,
) -> list[dict]:
    """Builds the host list in the order each IP address is first observed
    in the file. Every entry has the keys `ip`, `mac`, `oui_vendor`,
    `unit_ids` and `gateway`, and every value is a dictionary of the shape
    `{"value": ..., "provenance": ...}` (the result of
    `dataclasses.asdict` on an `ObservedField`).

    `events` is a list of dictionaries in the shape of
    `analysis["protocol_events"]`, that is the result of
    `dataclasses.asdict` on a `ModbusEvent`. A value of `None` means the
    same as an empty list - every caller predating this argument keeps
    working unchanged.

    The rule for the `unit_ids` and `gateway` fields (ASSET-04, ASSET-05):
    Unit ID values are collected ONLY under the destination address of
    events with the `request` direction, because a Unit ID addresses a
    logical device on the server side. An address without a single such
    value gives `not_derivable()` in both fields. An address with values
    gives `observed(list sorted ascending)`.

    `vendor_lookup` is a function taking a MAC address and returning a
    vendor name or `None` (assumption Z-20). This module does NOT import
    `wayside.assets.oui.lookup_vendor` or `load_oui_table` - the caller
    (`wayside.pipeline.analyze`) injects a ready function closed over the
    loaded table, so this file and its tests stay entirely independent of
    whether the data file sits in the repository tree.

    The rule for the `oui_vendor` field, in this order: an undetermined host
    MAC address (no Ethernet layer, or a mismatch under Z-03) gives
    `not_derivable()` WITHOUT calling `vendor_lookup`; a `vendor_lookup`
    equal to `None` gives `not_derivable()`; a `vendor_lookup` result equal
    to `None` gives `not_derivable()`; a non-empty result gives
    `inferred(name, PROVENANCE_METHOD_OUI)` - the vendor is an INFERENCE
    from the table, never an observation from the traffic (assumption
    Z-23).

    It uses a `dict` plus a separate `order` list for insertion order -
    never a `set` on the path to the result, because
    `model.dump_deterministic` sorts dictionary keys only, so list order is
    the obligation of the data producer (the pattern is identical to
    `pipeline._build_conversations`).
    """
    hosts: dict[str, dict[str, object]] = {}
    order: list[str] = []
    first_mac: dict[str, str | None] = {}

    # A `set` is allowed here ONLY as a working structure inside the
    # function - what enters the result is a sorted list, never the iteration
    # order of a set.
    unit_ids_by_server: dict[str, set[int]] = {}
    # ONLY events with the `request` direction are counted: a response
    # mirrors a request, so counting both would double the same
    # observation.
    requests_sent: dict[str, int] = {}
    requests_received: dict[str, int] = {}
    for event in events or []:
        if event.get("direction") != "request":
            continue
        # `unit_id` is a Modbus-specific field: since Phase 4 (PROTO-05)
        # `events` also carries cleartext protocol events, which do not have
        # it - `"unit_id" in event`, never an unconditional
        # `event["unit_id"]`, so that an event without the field does not
        # raise KeyError.
        if "unit_id" in event:
            unit_ids_by_server.setdefault(event["dst_ip"], set()).add(event["unit_id"])
        requests_sent[event["src_ip"]] = requests_sent.get(event["src_ip"], 0) + 1
        requests_received[event["dst_ip"]] = requests_received.get(event["dst_ip"], 0) + 1

    def _oui_vendor_field(mac: str | None) -> object:
        if mac is None or vendor_lookup is None:
            return not_derivable()
        vendor_name = vendor_lookup(mac)
        if vendor_name is None:
            return not_derivable()
        return inferred(vendor_name, PROVENANCE_METHOD_OUI)

    def _unit_ids_field(ip: str) -> object:
        seen = unit_ids_by_server.get(ip)
        if not seen:
            return not_derivable()
        return observed(sorted(seen))

    def _gateway_field(ip: str) -> object:
        seen = unit_ids_by_server.get(ip)
        if seen is not None and len(seen) > 1:
            return inferred(True, "multiple-unit-ids")
        # There is no branch returning `False` here and there will not be
        # one (assumption Z-25): a single Unit ID under an address is an
        # absence of evidence for a gateway, not evidence of its absence - a
        # gateway with one device attached looks identical in a capture to a
        # device with no gateway.
        return not_derivable()

    def _role_field(sent: int, received: int) -> object:
        if sent > 0 and received > 0:
            return inferred(ROLE_MODBUS_BOTH, PROVENANCE_METHOD_ROLE)
        if sent > 0:
            return inferred(ROLE_MODBUS_CLIENT, PROVENANCE_METHOD_ROLE)
        if received > 0:
            return inferred(ROLE_MODBUS_SERVER, PROVENANCE_METHOD_ROLE)
        # ASSET-07: the only inventory field where an absence of knowledge
        # has a VALUE rather than `null`. An undetermined role is meant to be
        # a visible row in the report, because a host omitted from the
        # inventory looks like a host that does not exist, and a host with an
        # empty cell looks like a rendering fault. The provenance marker
        # carries the same message as everywhere else.
        return ObservedField(value=ROLE_UNDETERMINED, provenance=PROVENANCE_NOT_DERIVABLE)

    def _role_evidence_field(sent: int, received: int) -> object:
        if sent == 0 and received == 0:
            # Zero observed events is an OBSERVATION, not an absence of
            # observation - hence the `observed` marker here too.
            return observed(
                "Zero Modbus events associated with this address in this "
                "capture (requests sent: 0, requests received: 0)."
            )
        return observed(
            f"Modbus requests sent by this address: {sent}; "
            f"Modbus requests received by this address: {received}."
        )

    def _role_confidence_field(sent: int, received: int) -> object:
        total = sent + received
        directions_seen = (1 if sent > 0 else 0) + (1 if received > 0 else 0)
        if total >= MIN_EVENTS_FOR_MEDIUM_CONFIDENCE and directions_seen == 1:
            return inferred("medium", PROVENANCE_METHOD_ROLE_CONFIDENCE)
        return inferred("low", PROVENANCE_METHOD_ROLE_CONFIDENCE)

    def _visit(ip: str, mac: str | None) -> None:
        if ip not in hosts:
            order.append(ip)
            first_mac[ip] = mac
            hosts[ip] = {
                "ip": observed(ip),
                "mac": observed(mac) if mac is not None else not_derivable(),
                "oui_vendor": _oui_vendor_field(mac),
                "unit_ids": _unit_ids_field(ip),
                "gateway": _gateway_field(ip),
                "role": _role_field(requests_sent.get(ip, 0), requests_received.get(ip, 0)),
                "role_evidence": _role_evidence_field(
                    requests_sent.get(ip, 0), requests_received.get(ip, 0)
                ),
                "role_confidence": _role_confidence_field(
                    requests_sent.get(ip, 0), requests_received.get(ip, 0)
                ),
            }
            return

        # A second, different MAC address for the same IP (Z-03): switch the
        # field to not_derivable() and leave it there - a second mismatch
        # changes nothing any more. A MAC address absent at the first
        # encounter stays not_derivable() permanently, even if a later
        # segment carries one - an absence of knowledge at the start does not
        # turn into certainty later. The oui_vendor field is NOT recomputed
        # here - it is established only at the first encounter with the IP
        # address, consistently with the mac field it concerns at that
        # moment.
        if first_mac[ip] is not None and mac is not None and mac != first_mac[ip]:
            hosts[ip]["mac"] = not_derivable()

    for segment in segments:
        _visit(segment.src_ip, segment.src_mac)
        _visit(segment.dst_ip, segment.dst_mac)

    return [
        {field_name: dataclasses.asdict(field_value) for field_name, field_value in hosts[ip].items()}
        for ip in order
    ]
