# 0001: Decoding engine v1

## Context

The design research (technology layer) (design research from 2026-09-01, the
"Core Technologies" section) recommends `tshark` (the Wireshark CLI, called as a
subprocess) as the main decoding engine for the seven industrial protocols
targeted for v2+: Modbus, S7comm, DNP3, EtherNet/IP+CIP, PROFINET, OPC UA and
IEC 60870-5-104/101. That recommendation is justified outright in that
research: scapy covers only 2 of the 7 protocols natively, while Wireshark has
dissectors for all seven.

The governing and later documents - `ROADMAP.md`, `01-01-SUMMARY.md` and
`REQUIREMENTS.md` - settle it more narrowly: the scope of v1 is Modbus/TCP
only, decoded by `scapy` natively, with no dependency on Wireshark or tshark.
`FOUND-01` says so outright: "The tool runs on a clean Windows 11 with one
command, without installing Wireshark or tshark".

This is a collision between two pieces of design research with different time
horizons and ambitions, described as Pitfall 9 in `01-RESEARCH.md`: `STACK.md`
measured the wider scenario (seven protocols, v2+) before the decision to
narrow v1 to a single protocol was taken.

## Decision

The narrower ruling holds. An external dissector (Wireshark/tshark, and
`pyshark` as its PyPI wrapper) is excluded from v1 - not only as a required
dependency but also as an optional one. An optional dependency shows up in the
installation instructions and in the documentation anyway, and `FOUND-01`
speaks of a clean machine: no additional networking installation, not merely no
installation by default.

This decision is enforced by machine through
`tests/test_no_external_dissector.py`, which scans `src/`, `scripts/`,
`pyproject.toml`, `uv.lock` and `.github/workflows/` for binary names
(`tshark`, `wireshark`) and for the wrapper package name (`pyshark`), and
separately guards against a regression on Assumption A1 (no import of
`scapy.all`, which on Windows transitively loads `scapy.arch.libpcap` and
breaks the declared absence of dependencies).

## Consequences

Further industrial protocols in v1 (beyond Modbus/TCP) require their own
parser, written by hand from public protocol documentation, rather than
delegation to a ready Wireshark dissector. `ROADMAP.md` (Phase 2) names that
outright as an asset, not a cost: parsing a protocol by hand shows knowledge of
the protocol, not knowledge of a library, and that is the advantage this
project stands on (see `PROJECT.md`, the "Context" section).

The scope of the gate is expensive to change in the other direction: every
further phase grows underneath it, so widening the scan later (for example to a
new dependency carrier, such as the configuration file of a developer tool)
requires reviewing everything built under it up to that point.

## Reversibility

`one-way` within the bounds of v1. As long as v1 lasts, no phase introduces a
dependency on an external packet decoder, not even an optional one. Reversing
this decision during v1 would break `FOUND-01` outright.

## Revision path

`V2-03` (the project requirements register, the "v2 Requirements" section)
explicitly admits an external decoder (tshark) for further industrial protocols
(S7comm, DNP3, IEC 60870-5-104) as a documented precondition. Revising this
decision belongs to v2 and requires changing the requirement in
`REQUIREMENTS.md`, not merely changing the code -
`tests/test_no_external_dissector.py` has to be deliberately narrowed or
removed together with that requirement change, otherwise the gate and the
requirement start contradicting each other.

While working on Phase 2 it is worth adding a note to the design research
(technology layer) that the tshark recommendation there covers a wider scope
(seven protocols, v2+) than the delivered scope of v1 (one protocol, Modbus/TCP
through scapy) - so that a future reading of that document does not take the
recommendation as still current for v1.
