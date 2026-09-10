"""The check engine: a directory scan at runtime, with no registry (D-06).

A new check is a new YAML file plus a sibling `.py` file in the
`checks/<category>/` subdirectory - this module does not change, because
`discover_checks` discovers files physically through
`sorted(checks_root.rglob("*.yaml"))`, not through a list of imported
modules (CHECK-01).

`evaluator` is resolved as a file SIBLING to the YAML, through
`importlib.util.spec_from_file_location`, never through
`importlib.import_module` on an arbitrary dotted path - that closes threat
T-2-04 (importing an arbitrary module named by a data file).
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

__all__ = [
    "CHECKS_ROOT",
    "REQUIRED_CHECK_FIELDS",
    "ENDPOINT_UNKNOWN",
    "CheckSchemaError",
    "CheckSpec",
    "discover_checks",
    "run_checks",
]

CHECKS_ROOT = Path(__file__).resolve().parent

# The endpoint fallback value (G-04-5b, assumption Z-92): a finding for a
# session that has no row in the communication matrix. On the real pipeline
# path this case does not occur today (a finding comes from a protocol
# event, and a protocol event from a segment with payload, which does have a
# matrix row); it does occur in the sample models of this module's tests.
ENDPOINT_UNKNOWN = "undetermined"

REQUIRED_CHECK_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "applies_to",
    "severity",
    "rationale",
    "standards",
    "evaluator",
    "remediation",
)


class CheckSchemaError(Exception):
    """The check file does not have a valid shape, or `evaluator` points at
    a disallowed module."""


@dataclass(frozen=True)
class CheckSpec:
    path: Path
    spec: dict
    evaluate: Callable[[dict], list[dict]]


def _validate_fields(spec: dict, yaml_path: Path) -> None:
    missing = [field for field in REQUIRED_CHECK_FIELDS if not spec.get(field)]
    if missing:
        raise CheckSchemaError(
            f"Check {yaml_path} is incomplete: missing or empty fields {missing}."
        )


def _load_evaluator(spec: dict, yaml_path: Path) -> Callable[[dict], list[dict]]:
    evaluator_ref = spec["evaluator"]
    module_name, sep, func_name = evaluator_ref.partition(":")
    if not sep or not module_name or not func_name:
        raise CheckSchemaError(
            f"Check {yaml_path}: the evaluator field has an invalid shape "
            f"{evaluator_ref!r}, expected 'module:function'."
        )
    if any(token in module_name for token in ("/", "\\", ".")):
        raise CheckSchemaError(
            f"Check {yaml_path}: the evaluator module name {module_name!r} "
            "cannot contain a path separator or a dot (threat T-2-04)."
        )

    module_path = yaml_path.parent / f"{module_name}.py"
    if not module_path.is_file():
        raise CheckSchemaError(
            f"Check {yaml_path}: the evaluator file does not exist: {module_path}."
        )

    module_spec = importlib.util.spec_from_file_location(
        f"wayside._checks.{module_name}", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise CheckSchemaError(
            f"Check {yaml_path}: failed to load the evaluator module "
            f"{module_path}."
        )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

    evaluate = getattr(module, func_name, None)
    if not callable(evaluate):
        raise CheckSchemaError(
            f"Check {yaml_path}: the function {func_name!r} does not exist "
            f"in {module_path}."
        )
    return evaluate


def discover_checks(checks_root: Path = CHECKS_ROOT) -> list[CheckSpec]:
    """Scans `checks_root` for `*.yaml` files, in sorted order (filesystem
    order is not guaranteed between machines). Two files with an identical
    `id` end in a `CheckSchemaError`, never in a silent overwrite."""
    checks: list[CheckSpec] = []
    seen_ids: dict[str, Path] = {}

    for yaml_path in sorted(checks_root.rglob("*.yaml")):
        spec = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        _validate_fields(spec, yaml_path)

        check_id = spec["id"]
        if check_id in seen_ids:
            raise CheckSchemaError(
                f"Duplicate check identifier {check_id!r}: "
                f"{seen_ids[check_id]} and {yaml_path}."
            )
        seen_ids[check_id] = yaml_path

        evaluate = _load_evaluator(spec, yaml_path)
        checks.append(CheckSpec(path=yaml_path, spec=spec, evaluate=evaluate))

    return checks


def _dedupe_standards(standards: list[dict]) -> list[dict]:
    """Removes repeated citations by the (standard, clause) pair, keeping
    the FIRST occurrence - the order from the YAML file stays untouched
    (CHECK-02, edge: adjacency/ordering)."""
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for entry in standards:
        key = (entry["standard"], entry["clause"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def _endpoints_by_session(analysis: dict) -> dict[int, tuple[str, str]]:
    """A mapping from session identifier to the pair of endpoints (source,
    target), built from the communication matrix of THE SAME model
    (G-04-5b). Modelled on `_dedupe_standards` above: a private, pure
    function, one entry per matrix row.

    Access to the `comm_matrix` key tolerates its absence (assumption Z-92)
    - the sample model of this module's tests has no communication matrix,
    and an exception would knock them over for no gain. Every matrix row is
    an observed field wrapped in a `{"value": ..., "provenance": ...}`
    dictionary, so the mapping reaches for the field's value, not for the
    field itself."""
    mapping: dict[int, tuple[str, str]] = {}
    for row in analysis.get("comm_matrix") or []:
        session_id = row["session_id"]["value"]
        source = row["source"]["value"]
        target = row["target"]["value"]
        mapping[session_id] = (source, target)
    return mapping


def run_checks(analysis: dict, checks: list[CheckSpec]) -> list[dict]:
    """Runs every check over `analysis` and collects the results into one
    flat list (the `scan_files` pattern) - no check breaks the loop. The
    result is sorted by the triple (check_id, session_id, packet_number).

    Every finding gets the pair of session addresses (G-04-5b), attached
    from a mapping built ONCE before the loop over checks, not once per
    finding. The evidence dictionary returned by an evaluator is NOT mutated
    (assumption Z-91): the engine assembles a NEW dictionary from its
    contents plus two new keys - an evaluator may return a shared dictionary
    or one built on a model event, and tests calling an evaluator directly
    assert equality of the full evidence dictionary."""
    findings: list[dict] = []
    endpoints_by_session = _endpoints_by_session(analysis)

    for check in checks:
        standards = _dedupe_standards(check.spec["standards"])
        for result in check.evaluate(analysis):
            finding = {
                "check_id": check.spec["id"],
                "title": check.spec["title"],
                "severity": check.spec["severity"],
                "rationale": check.spec["rationale"],
                "standards": standards,
                "remediation": check.spec["remediation"],
            }
            finding.update(result)
            # A missing evidence key or a missing session identifier in an
            # evaluator's result is still to end in a key error - that is a
            # signal of an invalid check result shape, not a legal absence of
            # data.
            session_id = finding["evidence"]["session_id"]
            source, target = endpoints_by_session.get(
                session_id, (ENDPOINT_UNKNOWN, ENDPOINT_UNKNOWN)
            )
            finding["evidence"] = {
                **finding["evidence"],
                "source": source,
                "target": target,
            }
            findings.append(finding)

    findings.sort(
        key=lambda f: (
            f["check_id"],
            f["evidence"]["session_id"],
            f["evidence"]["packet_number"],
        )
    )
    return findings
