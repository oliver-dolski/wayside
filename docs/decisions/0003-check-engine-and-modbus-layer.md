# 0003: The check engine and the Modbus/TCP layer

## Context

Three rulings from Phase 2, each for the same reason: the design research
(architecture) was written before the first line of code in this project and
before the `LOCK-01` decision from Phase 1
(`docs/decisions/0001-decoding-engine-v1.md`), so it aimed at a wider scope than
the delivered v1. That is the same class of drift as Pitfall 9 from
`01-RESEARCH.md` (the `tshark` recommendation in `STACK.md` for the seven
protocols of v2+, before the decision to narrow v1 to a single protocol through
scapy) - the project-level research measured the wider scenario, and the Phase 2
code settled it more narrowly. Without a record outside the planning directory
every further phase would rediscover these three rulings its own way.

## Decision

### D-05: report rendering without a template engine

**Context of the decision:** `ARCHITECTURE.md` recommended Jinja2 as early as
the first vertical slice (visible in the component responsibility table and in
the build order). The "Context" section of `PROJECT.md` puts simplicity above
completeness, and the report of this phase has six sections with names fixed in
advance - a fixed skeleton does not need a template engine to be rendered.

**Ruling:** `src/wayside/report.py` renders markdown with plain Python functions
(joining a list of lines), with no dependency on Jinja2 or any other template
engine. The reconsideration point: Phase 4, when the PDF export will know the
number of report variants and the decision will have material to judge by that
it lacks today.

**Machine gate:** no `jinja2` entry in the `pyproject.toml` dependencies, plus
`tests/test_report_render.py::test_six_sections_present` (completeness of the
six sections with no template engine involved).

### D-06: checks discovered by a directory scan at runtime

**Context of the decision:** The extensibility criterion of this phase speaks
outright of a new check without changing any file in the engine directory. Entry
points from `pyproject.toml` would require an entry in that file and a
reinstall of the package for every new check. A decorator-based registry would
require a central import that grows with every new check - in both cases adding
a check touches a file OUTSIDE its own directory.

**Ruling:** `src/wayside/checks/engine.py` discovers checks through a directory
scan (`sorted(rglob("*.yaml"))`) and loads the evaluator as a sibling file
through `importlib.util.spec_from_file_location`. Neither entry points nor a
decorator registry. A new check is a new YAML file plus a new `.py` file in a new
subdirectory - `engine.py` and `pyproject.toml` stay untouched.

**Machine gate:**
`tests/test_check_engine.py::test_new_check_discovered_without_engine_change` -
it adds a check at runtime and compares the sha256 digest of `engine.py` and
`pyproject.toml` before and after, instead of guessing from the run result
alone.

### D-07: protocol recognition and MBAP header validation as own code over the library's PDU classes

**Context of the decision:** Reading the source of the `scapy.contrib.modbus`
package confirmed that its coverage of Modbus Application Protocol function
codes is complete - an own function code parser is not needed. That same reading
showed two gaps: the library binds Modbus rigidly to a single port number
through `bind_layers`, and it performs no MBAP header validation at all - a
header with an invalid protocol identifier passes without objection, and empty
bytes yield a phantom valid packet. The criterion of port-independent
recognition cannot be met by layer binding alone.

**Ruling:** `src/wayside/protocols/modbus_tcp.py` recognises Modbus/TCP by the
shape of the MBAP header on any TCP port, not by port number. Own MBAP
validation (`validate_mbap`) stands BEFORE functional classification as a gate
rejecting an invalid frame entirely, not as a warning attached to the result.
Function code classification stays based on the library's table - the fallback
path from the requirements map (an own function code parser) is not taken,
because the library's coverage turned out to be complete.

**Machine gate:** a fixture on a non-standard port and a fixture with a damaged
MBAP header, each with a pair of a unit test and a test through the CLI -
`tests/test_modbus_tcp.py::test_recognizes_non_standard_port` /
`::test_recognizes_non_standard_port_end_to_end_via_cli` and
`::test_rejects_malformed_mbap` / `::test_rejects_malformed_mbap_end_to_end_via_cli`.

## Consequences

None of the three choices closes a path of development - each is recorded with
its own reconsideration condition or with a fallback path that was deliberately
NOT taken (D-07). A later phase wanting to introduce a template engine, a
decorator registry or an own Modbus function code parser does so as a deliberate
revision of this record, not as a first encounter with the problem.

## Reversibility

D-05 and D-06 are `two-way`: changing the report rendering implementation or the
check discovery mechanism touches neither the `analysis.json` schema nor the CLI
contract, so the cost of revision is local to one module. D-07 is `one-way`
within the bounds of v1: giving up own MBAP validation in favour of bare
reliance on the library would mean the return of two closed gaps (a phantom
packet from empty bytes, no check of the protocol identifier) that this record
exists to close.

## Revision path

A note was added to the design research (architecture) next to the
recommendations of a second packet decoder and a template engine, pointing at
this file and at `docs/decisions/0001-decoding-engine-v1.md` - the research
itself stays untouched as a record of the state of knowledge before the code,
and the note is a pointer for a future reading.
