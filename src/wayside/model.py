"""The canonical model: `analysis.json` as the single source, the finding
dataclasses and atomic writing.

`Evidence` has EXACTLY the fields listed below and no field for raw bytes
or payload content - that is a property of the type (threat T-2-06),
modelled on `Violation` in `scripts/confidentiality_guard.py`, which
likewise does not carry the matched text.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Evidence",
    "StandardRef",
    "Finding",
    "build_analysis",
    "dump_deterministic",
    "write_atomic",
    "write_atomic_bytes",
    "PROVENANCE_OBSERVED",
    "PROVENANCE_NOT_DERIVABLE",
    "PROVENANCE_PATTERN",
    "ObservedField",
    "ProvenanceError",
    "observed",
    "inferred",
    "not_derivable",
    "iter_observed_fields",
    "assert_provenance_complete",
    "collect_not_derivable_fields",
]

# The carrier of field provenance (assumption Z-01): every inventory field
# carries not only a value but also the way that value came about. Three
# families of markers: `observed` (read straight from the frame),
# `inferred:<method>` (computed, with a named inference method) and
# `not-derivable-passively` (cannot be established from a passive capture -
# such a field is never to be omitted).
PROVENANCE_OBSERVED = "observed"
PROVENANCE_NOT_DERIVABLE = "not-derivable-passively"
PROVENANCE_PATTERN = re.compile(r"^(observed|inferred:[a-z0-9_-]+|not-derivable-passively)$")


@dataclass(frozen=True)
class ObservedField:
    """A value together with the marker of its provenance. `__post_init__`
    rejects a marker outside `PROVENANCE_PATTERN` at construction time - the
    same style as `severity_to_risk` in `risk.py`, which raises on a value
    outside the list instead of returning a default."""

    value: object
    provenance: str

    def __post_init__(self) -> None:
        if not PROVENANCE_PATTERN.match(self.provenance):
            raise ValueError(
                f"Provenance marker outside the allowed pattern: {self.provenance!r}"
            )


class ProvenanceError(Exception):
    """An inventory field without a provenance marker, or with a marker
    outside `PROVENANCE_PATTERN`, detected by
    `assert_provenance_complete`."""


def observed(value: object) -> ObservedField:
    """A field read straight from the frame."""
    return ObservedField(value=value, provenance=PROVENANCE_OBSERVED)


def inferred(value: object, method: str) -> ObservedField:
    """A field computed by the method `method` (without the `inferred:`
    prefix - it is added here)."""
    return ObservedField(value=value, provenance=f"inferred:{method}")


def not_derivable() -> ObservedField:
    """A field that cannot be established from a passive capture. `value`
    is always `None` - an absent field never stands in for this marker."""
    return ObservedField(value=None, provenance=PROVENANCE_NOT_DERIVABLE)


def iter_observed_fields(node: object, path: str = "") -> Iterator[tuple[str, dict]]:
    """A generator walking recursively over a structure already serialised
    into dictionaries and lists (the result of `dataclasses.asdict`).

    A dictionary whose key set is exactly `{"value", "provenance"}` IS a
    provenance field: the generator yields the `(path, node)` pair and does
    NOT descend into `value` - a value that happens to be a dictionary of the
    same shape is not counted twice. Every other dictionary is a container
    and the generator descends into its values. A list is a container and the
    generator descends into its items."""
    if isinstance(node, dict):
        if set(node.keys()) == {"value", "provenance"}:
            yield path, node
            return
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_observed_fields(value, child_path)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            yield from iter_observed_fields(item, f"{path}[{index}]")


def collect_not_derivable_fields(
    analysis: dict, sections: tuple[str, ...] = ("assets", "comm_matrix")
) -> list[dict]:
    """Lists the fields not derivable passively, aggregated by field name.

    It uses `iter_observed_fields`, that is the same walk that drives the
    `assert_provenance_complete` gate. One walk, two uses: the gate CHECKS,
    this function LISTS. A second, parallel traversal of the model would
    drift from the gate at the first new field shape.

    Aggregation is by field name, not by entry (assumption Z-32): a per-host
    list grows linearly with the number of hosts and, on a real capture,
    turns the limitations section into an enumeration nobody reads.

    A section absent from the model raises nothing and yields no row.
    """
    rows: list[dict] = []
    for section in sections:
        entries = analysis.get(section)
        if not entries:
            continue
        counts: dict[str, int] = {}
        for entry in entries:
            for path, field in iter_observed_fields(entry):
                if field["provenance"] != PROVENANCE_NOT_DERIVABLE:
                    continue
                field_name = path.rsplit(".", 1)[-1]
                counts[field_name] = counts.get(field_name, 0) + 1
        for field_name in sorted(counts):
            rows.append(
                {
                    "section": section,
                    "field": field_name,
                    "count": counts[field_name],
                    "total": len(entries),
                }
            )
    return sorted(rows, key=lambda row: (row["section"], row["field"]))


def assert_provenance_complete(node: object, path: str = "") -> None:
    """Raises `ProvenanceError` recursively on every inventory field
    without a provenance marker or with a marker outside
    `PROVENANCE_PATTERN`.

    Two violation cases: a scalar value (`str`, `int`, `float`, `bool`,
    `None`) NOT sitting in the `value` field of a recognised provenance
    field, and a provenance field whose `provenance` does not match the
    pattern. The exception message carries the field path and the name of the
    violated condition, never the value itself - the same discipline as
    `Violation` without a text field in
    `scripts/confidentiality_guard.py`."""
    if isinstance(node, dict):
        if set(node.keys()) == {"value", "provenance"}:
            provenance = node["provenance"]
            if not isinstance(provenance, str) or not PROVENANCE_PATTERN.match(provenance):
                raise ProvenanceError(
                    f"Field '{path}' has a provenance marker outside the "
                    f"allowed pattern: {provenance!r}"
                )
            return
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            assert_provenance_complete(value, child_path)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            assert_provenance_complete(item, f"{path}[{index}]")
        return
    if node is None or isinstance(node, (str, int, float, bool)):
        raise ProvenanceError(
            f"Field '{path}' carries a scalar value with no provenance marker"
        )


@dataclass(frozen=True)
class Evidence:
    """Finding evidence: the packet number and session identifier one can
    return to in the capture, plus the pair of session endpoints
    (address:port) attached by the check engine from the communication
    matrix of THE SAME model (G-04-5b) - without it two occurrences of the
    same check are indistinguishable to the reader. Address and port are
    connection metadata which the communication matrix and the inventory of
    the same document already carry; there is no field here for raw bytes or
    payload content, and there will not be one (CHECK-06, threat
    T-2-06)."""

    packet_number: int
    session_id: int
    source: str
    target: str


@dataclass(frozen=True)
class StandardRef:
    standard: str
    edition: str
    clause: str
    clause_title: str
    # Clause title provenance: `copy` (transcribed from a legal copy of the
    # standard) or `own` (a scope description written by the project's
    # author). The closed set of allowed values is
    # `wayside.standards.mapper.CLAUSE_TITLE_SOURCES` - that is the source of
    # truth, not this declaration (G-04-3c).
    clause_title_source: str
    paraphrase: str
    verified: bool
    verification_note: str
    # The paraphrase note field (`paraphrase_note` in the catalogue file) is
    # NOT here and will not be (assumption Z-82): a field absent from this
    # model is a stronger guarantee against rendering than any test.


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    risk: str
    rationale: str
    standard_refs: tuple[StandardRef, ...]
    evidence: Evidence
    remediation: str


def build_analysis(
    *,
    capture: dict,
    conversations: list[dict],
    protocol_events: list[dict],
    zone_model: dict,
    findings: list[dict],
    methodology: dict,
    assets: list[dict],
    coverage: dict,
    low_confidence_events: list[dict],
    comm_matrix: list[dict],
) -> dict:
    """Assembles the `analysis.json` dictionary.

    Per D-02 it adds no field carrying the analysis generation timestamp -
    `capture` carries only the time window derived from `pkt.time`, handed
    in ready by the caller. `coverage` carries the assessment of capture
    window coverage against the measured polling interval (INGEST-04), built
    by `wayside.coverage`. `low_confidence_events` carries events recognised
    by the checksum discriminator
    `wayside.protocols.modbus_rtu_tunnel.detect_all` - the key ALWAYS
    exists, empty list included, and is structurally SEPARATE from
    `protocol_events`: the check engine reads only `protocol_events`, so a
    low-confidence recognition can never become the basis of a finding
    merely by sitting on a shared list (assumption Z-18, PROTO-03).
    `comm_matrix` carries the communication matrix built by
    `wayside.flow.build_comm_matrix` - one row per session with payload,
    including sessions whose protocol was not recognised (FLOW-01).
    """
    return {
        "capture": capture,
        "conversations": conversations,
        "protocol_events": protocol_events,
        "zones": zone_model["zones"],
        "conduits": zone_model["conduits"],
        "findings": findings,
        "methodology": methodology,
        "assets": assets,
        "coverage": coverage,
        "low_confidence_events": low_confidence_events,
        "comm_matrix": comm_matrix,
    }


def dump_deterministic(data: dict) -> str:
    """Serialises deterministically: sorted keys, separators without
    whitespace, characters outside ASCII written straight in UTF-8 (not
    escaped)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_atomic(path: Path, text: str) -> None:
    """Writes `text` to `path` through a temporary file in the same target
    directory plus `os.replace` - an interrupted or concurrent run leaves no
    partially written file. An explicit `newline="\\n"` removes line ending
    translation on Windows."""
    path = Path(path)
    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp_path_str, path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise


def write_atomic_bytes(path: Path, data: bytes) -> None:
    """Writes `data` to `path` through a temporary file in the same target
    directory plus `os.replace` - the same pattern as `write_atomic`. A
    separate function rather than an argument to the existing one:
    `write_atomic` opens the file in text mode with an explicit
    `newline='\\n'`, while PDF bytes are not text and have no line endings to
    translate - two opening modes in one function, behind a conditional
    branch, would hide two different contracts about the parameter's content
    in one place."""
    path = Path(path)
    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_path_str, path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise
