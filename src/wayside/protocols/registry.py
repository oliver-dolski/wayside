"""The dissector registry: a directory scan at runtime, with no static
registry (PROTO-05, the same pattern as `checks/engine.py` for D-06).

A new protocol is a new directory with a `manifest.yaml` file and a sibling
file under `protocols/dissectors/<name>/` - this module does not change for
it, because `discover_dissectors` discovers files physically through
`sorted(dissectors_root.rglob("manifest.yaml"))`, not through a list of
imported modules (PROTO-05).

The `dissector` field is resolved as a file SIBLING to `manifest.yaml`,
through `importlib.util.spec_from_file_location`, never through
`importlib.import_module` on a dotted path - that closes the same threat
(T-4-01) which `checks/engine.py::_load_evaluator` closes for the
`evaluator` field (T-2-04).
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

__all__ = [
    "DISSECTORS_ROOT",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_LOW",
    "ALLOWED_CONFIDENCE",
    "REQUIRED_DISSECTOR_FIELDS",
    "REQUIRED_EVENT_FIELDS",
    "DissectorSchemaError",
    "DissectorSpec",
    "discover_dissectors",
    "run_dissectors",
]

DISSECTORS_ROOT = Path(__file__).resolve().parent / "dissectors"

CONFIDENCE_HIGH = "high"
CONFIDENCE_LOW = "low"
ALLOWED_CONFIDENCE: tuple[str, ...] = (CONFIDENCE_HIGH, CONFIDENCE_LOW)

REQUIRED_DISSECTOR_FIELDS: tuple[str, ...] = ("id", "confidence", "dissector")
REQUIRED_EVENT_FIELDS: tuple[str, ...] = ("packet_number", "session_id")


class DissectorSchemaError(Exception):
    """The dissector manifest file does not have a valid shape,
    `dissector` points at a disallowed module, or an event returned by a
    dissector does not have a valid shape."""


@dataclass(frozen=True)
class DissectorSpec:
    path: Path
    spec: dict
    dissect: Callable[[list], list[dict]]


def _validate_fields(spec: dict, manifest_path: Path) -> None:
    missing = [field for field in REQUIRED_DISSECTOR_FIELDS if not spec.get(field)]
    if missing:
        raise DissectorSchemaError(
            f"Dissector {manifest_path} is incomplete: missing or empty fields {missing}."
        )

    confidence = spec["confidence"]
    if confidence not in ALLOWED_CONFIDENCE:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: the confidence field has the value "
            f"{confidence!r}, allowed values are {ALLOWED_CONFIDENCE}."
        )


def _load_dissector(spec: dict, manifest_path: Path) -> Callable[[list], list[dict]]:
    dissector_ref = spec["dissector"]
    module_name, sep, func_name = dissector_ref.partition(":")
    if not sep or not module_name or not func_name:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: the dissector field has an invalid "
            f"shape {dissector_ref!r}, expected 'module:function'."
        )
    if any(token in module_name for token in ("/", "\\", ".")):
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: the dissector module name "
            f"{module_name!r} cannot contain a path separator or a dot "
            "(threat T-4-01)."
        )

    module_path = manifest_path.parent / f"{module_name}.py"
    if not module_path.is_file():
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: the dissector file does not exist: {module_path}."
        )

    module_spec = importlib.util.spec_from_file_location(
        f"wayside._protocols.{module_name}", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: failed to load the dissector module "
            f"{module_path}."
        )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

    dissect = getattr(module, func_name, None)
    if not callable(dissect):
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: the function {func_name!r} does not "
            f"exist in {module_path}."
        )
    return dissect


def discover_dissectors(dissectors_root: Path = DISSECTORS_ROOT) -> list[DissectorSpec]:
    """Scans `dissectors_root` for `manifest.yaml` files, in sorted order
    (filesystem order is not guaranteed between machines - the byte
    determinism of `analysis.json` depends on this sorting, REPORT-06). Two
    manifests with an identical `id` end in a `DissectorSchemaError`, never
    in a silent overwrite. A non-existent directory returns an empty list -
    `rglob` on a non-existent path returns an empty iterator, so that
    behaviour follows from the library."""
    dissectors: list[DissectorSpec] = []
    seen_ids: dict[str, Path] = {}

    for manifest_path in sorted(dissectors_root.rglob("manifest.yaml")):
        spec = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        _validate_fields(spec, manifest_path)

        dissector_id = spec["id"]
        if dissector_id in seen_ids:
            raise DissectorSchemaError(
                f"Duplicate dissector identifier {dissector_id!r}: "
                f"{seen_ids[dissector_id]} and {manifest_path}."
            )
        seen_ids[dissector_id] = manifest_path

        dissect = _load_dissector(spec, manifest_path)
        dissectors.append(DissectorSpec(path=manifest_path, spec=spec, dissect=dissect))

    return dissectors


def _validate_event_shape(event: dict, dissector: DissectorSpec) -> None:
    missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
    if missing:
        raise DissectorSchemaError(
            f"Dissector {dissector.path}: event without required fields {missing}."
        )
    manifest_protocol = dissector.spec["id"]
    event_protocol = event.get("protocol")
    if event_protocol is not None and event_protocol != manifest_protocol:
        raise DissectorSchemaError(
            f"Dissector {dissector.path}: the event carries a protocol field "
            f"{event_protocol!r}, contradicting the manifest identifier "
            f"{manifest_protocol!r}."
        )


def run_dissectors(
    segments: list, dissectors: list[DissectorSpec]
) -> tuple[list[dict], list[dict]]:
    """Runs every dissector over the FULL `segments` list (each dissector
    is stateless and rejects the segments that do not concern it itself);
    the registry injects the `protocol` and `confidence` fields from the
    manifest into every event a dissector returns - a dissector has no way
    to raise its own recognition confidence (assumption Z-41, threat
    T-4-03).

    The result is split into two lists by the `confidence` field from the
    MANIFEST: events from dissectors with `high` confidence go into the
    first list (`protocol_events`), those with `low` confidence into the
    second (`low_confidence_events`). Both lists are sorted by the triple
    `(packet_number, session_id, protocol)` BEFORE being returned - the
    third key is needed because two dissectors may recognise the same
    segment in the same session, and then the first pair of keys does not
    settle the order."""
    protocol_events: list[dict] = []
    low_confidence_events: list[dict] = []

    for dissector in dissectors:
        manifest_protocol = dissector.spec["id"]
        manifest_confidence = dissector.spec["confidence"]

        for event in dissector.dissect(segments):
            _validate_event_shape(event, dissector)
            enriched = dict(event)
            enriched["protocol"] = manifest_protocol
            enriched["confidence"] = manifest_confidence

            if manifest_confidence == CONFIDENCE_HIGH:
                protocol_events.append(enriched)
            else:
                low_confidence_events.append(enriched)

    def _sort_key(event: dict) -> tuple:
        return (event["packet_number"], event["session_id"], event["protocol"])

    protocol_events = sorted(protocol_events, key=_sort_key)
    low_confidence_events = sorted(low_confidence_events, key=_sort_key)

    return protocol_events, low_confidence_events
