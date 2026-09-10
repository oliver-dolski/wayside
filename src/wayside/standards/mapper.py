"""Resolving a standard clause citation against the public catalogue
(STD-01, STD-02, STD-06).

`resolve` takes the zone model as a REQUIRED argument and raises
`StandardsError` when the zone list is empty - STD-06 requires the zone
model to exist, populated, BEFORE the first citation of a system
requirement, and a required argument makes that machine-checkable rather
than a matter of call order. The error message carries metadata only, never
the content of a standard - the same discipline as `Violation` in
`scripts/confidentiality_guard.py`.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from wayside.model import StandardRef

__all__ = [
    "CATALOG_ROOT",
    "REQUIRED_CATALOG_FIELDS",
    "CATALOG_FIELD_TYPES",
    "OPTIONAL_CATALOG_FIELD_TYPES",
    "CLAUSE_TITLE_SOURCES",
    "StandardsError",
    "load_catalog",
    "resolve",
]

CATALOG_ROOT = Path(__file__).resolve().parent

# Clause title provenance: `copy` when the title was transcribed from a
# legal copy of the standard, `own` when it is a scope description written
# by the project's author. The `verified` field describes the WHOLE entry
# (clause numbering and paraphrase text), while the clause title is a
# separate thing which until now had no marker of its own - a title invented
# for a clause without a number rendered in the same shape as a title
# confirmed against a copy (G-04-3c).
CLAUSE_TITLE_SOURCES: frozenset[str] = frozenset({"copy", "own"})

REQUIRED_CATALOG_FIELDS: tuple[str, ...] = (
    "standard",
    "edition",
    "clause",
    "clause_title",
    "clause_title_source",
    "paraphrase",
    "verified",
)

# The expected type of every field in REQUIRED_CATALOG_FIELDS. The
# `verified` field has to be a `bool` - a value of any other type (a string,
# a number) has no right to pass loading, because `resolve` passes that
# value straight on WITHOUT any conversion (G-04-2).
CATALOG_FIELD_TYPES: dict[str, type] = {
    "standard": str,
    "edition": str,
    "clause": str,
    "clause_title": str,
    "clause_title_source": str,
    "paraphrase": str,
    "verified": bool,
}

# OPTIONAL fields, type-checked only when present in the entry (Z-77) -
# forcing their presence would close the door on a fully confirmed entry,
# which needs no note about being provisional. `paraphrase_note` carries
# framing formulas addressed to an auditor (Z-82) - the field is
# deliberately NOT passed into the citation model in `resolve` below.
OPTIONAL_CATALOG_FIELD_TYPES: dict[str, type] = {
    "verification_note": str,
    "paraphrase_note": str,
}


class StandardsError(Exception):
    """The standards catalogue is incomplete, or a citation was requested
    before the zone model was populated (STD-06)."""


def _validate_entry_fields(entry: dict, yaml_path: Path) -> None:
    """Checks `REQUIRED_CATALOG_FIELDS` in three passes: the presence of
    each field, non-emptiness (except `verified`, whose legal value may be
    `False`), and the type of the value. `verified` is excluded from the
    non-emptiness check deliberately: `False` is falsy in Python but is the
    only correct value here (a provisional entry), so treating it as a
    missing field would be a fault. Given the type gate below, that
    exclusion is safe, because the type pass covers the `verified` field
    explicitly and rejects any value that is not exactly a `bool`."""
    missing = [field for field in REQUIRED_CATALOG_FIELDS if field not in entry]
    if missing:
        raise StandardsError(
            f"Catalogue entry {yaml_path} is incomplete: missing fields {missing}."
        )

    empty = [
        field
        for field in REQUIRED_CATALOG_FIELDS
        if field != "verified" and not entry.get(field)
    ]
    if empty:
        raise StandardsError(
            f"Catalogue entry {yaml_path} is incomplete: empty fields {empty}."
        )

    # The type pass: an EXACT comparison by type identity (`type(x) is T`),
    # not by `isinstance` (Z-76). In Python `bool` is a subclass of `int`, so
    # a class membership check over a numeric field would accept a boolean
    # and the gate would be weaker than it reads - the catalogue has no
    # numeric fields today, but this gate is meant to hold the ones added
    # later too. The message carries only the field name and type names (from
    # the class name attribute), NEVER the field value - the catalogue
    # carries a paraphrase of a clause from a paid standard (T-4-37).
    type_errors: list[str] = []
    for field, expected_type in CATALOG_FIELD_TYPES.items():
        value = entry[field]
        if type(value) is not expected_type:
            type_errors.append(
                f"{field} (expected {expected_type.__name__}, "
                f"got {type(value).__name__})"
            )
    for field, expected_type in OPTIONAL_CATALOG_FIELD_TYPES.items():
        if field not in entry:
            continue
        value = entry[field]
        if type(value) is not expected_type:
            type_errors.append(
                f"{field} (expected {expected_type.__name__}, "
                f"got {type(value).__name__})"
            )
    if type_errors:
        raise StandardsError(
            f"Catalogue entry {yaml_path} carries fields of the wrong type: "
            f"{', '.join(type_errors)}."
        )

    # Fourth pass: clause title provenance has to belong to a closed set, and
    # an entry with the verification field raised and a provenance other than
    # coming from a copy ends in a catalogue error (G-04-3c). Decision 0006
    # walks a human through editing this file by hand after buying a copy;
    # without this rule a human could raise `verified` while leaving the
    # title an own description, and the report would present that own
    # description as a title confirmed against a copy.
    clause_title_source = entry["clause_title_source"]
    if clause_title_source not in CLAUSE_TITLE_SOURCES:
        raise StandardsError(
            f"Catalogue entry {yaml_path} carries a clause_title_source with "
            f"the disallowed value {clause_title_source!r}. Allowed values: "
            f"{sorted(CLAUSE_TITLE_SOURCES)}."
        )
    if entry["verified"] is True and clause_title_source != "copy":
        raise StandardsError(
            f"Catalogue entry {yaml_path} has the verified field raised, but "
            f"clause_title_source={clause_title_source!r} instead of 'copy' - "
            "a confirmed title requires provenance from a copy."
        )


def load_catalog(catalog_root: Path = CATALOG_ROOT) -> dict[tuple[str, str], dict]:
    """Loads every `catalog.yaml` file under `catalog_root`, in sorted
    order, and builds a `(standard, clause) -> entry` mapping.

    Two catalogue files carrying the same (standard, clause) pair end in a
    `StandardsError` naming BOTH paths in the message, never in a silent
    overwrite - the pattern of `discover_checks` in the check engine.
    Without that gate a silent win for the file loaded later would be
    indistinguishable from a correct load, and from this phase on the tree
    holds two catalogue files."""
    catalog: dict[tuple[str, str], dict] = {}
    seen_paths: dict[tuple[str, str], Path] = {}

    for yaml_path in sorted(catalog_root.rglob("catalog.yaml")):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        entries = data.get("entries", [])
        for entry in entries:
            _validate_entry_fields(entry, yaml_path)
            key = (entry["standard"], entry["clause"])
            if key in seen_paths:
                raise StandardsError(
                    f"Duplicate (standard, clause) pair {key} between "
                    f"catalogue files: {seen_paths[key]} and {yaml_path}."
                )
            seen_paths[key] = yaml_path
            catalog[key] = entry

    return catalog


def resolve(standard: str, clause: str, *, zone_model: dict) -> StandardRef:
    """Resolves `(standard, clause)` against the catalogue. The zone model
    is a required argument: an empty zone list ends in a `StandardsError`
    (STD-06) before any catalogue is read at all."""
    if not zone_model.get("zones"):
        raise StandardsError(
            "The zone model is empty - citing a system requirement requires a "
            "populated zone model before generation (STD-06)."
        )

    catalog = load_catalog()
    entry = catalog.get((standard, clause))
    if entry is None:
        raise StandardsError(
            f"No entry in the standards catalogue for standard={standard!r}, "
            f"clause={clause!r}."
        )

    return StandardRef(
        standard=entry["standard"],
        edition=entry["edition"],
        clause=entry["clause"],
        clause_title=entry["clause_title"],
        clause_title_source=entry["clause_title_source"],
        paraphrase=entry["paraphrase"],
        # No conversion: the loading layer already guarantees the `bool`
        # type, so a conversion here could only hide a data defect, and
        # decision 0006 walks a human through editing this file by hand with
        # no guarantee they run the test suite before trusting the edit.
        verified=entry["verified"],
        verification_note=entry.get("verification_note", ""),
        # The `paraphrase_note` field is NOT passed on - that is a design
        # choice, not an oversight (assumption Z-82). A field absent from the
        # model the renderers read is a stronger guarantee that auditor-facing
        # framing formulas are not rendered than any test over the output.
    )
