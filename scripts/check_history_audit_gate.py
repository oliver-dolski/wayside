"""Shape gate for the history audit record (`compliance/history-audit.md`).

This module is dependency-isolated from the rest of the `wayside` package and
uses the Python standard library ONLY, plus the module of the sibling gate
(`check_pub_gate`) from THE SAME directory. That is a condition, not a
preference: the gate has to work as a preliminary step before every public
push, on a machine without a synchronized project environment as well
(without `uv sync`) - exactly the same reason stated in the docstring of
`check_pub_gate.py`.

This script checks the SHAPE of the record ONLY, and how current it is
against the present HEAD - never whether the scan of the three surfaces
ACTUALLY ran. That is checked by the test carrying the slow marker
(`tests/test_history_audit.py`), run separately (locally on demand, in CI by
an explicit step). The record and the scan are two halves of the same
decision (D-21): a record without a repeated scan is a signature with no
content, and a scan without a record is a result with no trace.

The frontmatter is parsed by THE READER OF THE SIBLING GATE
(`check_pub_gate.load_record`) - the same shape (`key: value` pairs between
two `---` lines), so that the two record gates of this repository do not end
up with two readers that drift apart.

The `check_pub_gate` import works in BOTH invocation contexts of this script:
run directly by file path (`python scripts/check_history_audit_gate.py` -
Python automatically adds the script directory as the first `sys.path` entry)
and imported from a test that explicitly adds the `scripts/` directory to
`sys.path` (`tests/test_check_history_audit_gate.py`, following
`tests/test_check_pub_gate.py`).

Exit codes (part of the contract, they must stay distinguishable, SIX of them):
    0 - record complete, signed by a human, current (if currency was
        demanded), with an explicit result
    1 - result `hits-outside-exceptions` while the `--require-clean` flag was
        given
    3 - the record file is absent
    4 - record incomplete or breaking a shape rule (including an `author`
        field belonging to the set of agent names)
    5 - the record IS WAITING for a human signature (the `author` or
        `confirmed_on` field is empty) - a PENDING state, NOT a shape error
        (decision R-8): the executor of a plan has no way to sign on behalf
        of a human, and telling an unfinished record apart from a bad one is
        what lets this gate be useful at both moments
    6 - the `head_sha` field differs from the present HEAD, ONLY when the
        `--require-current` flag was given (assumption Z-100: without that
        flag the difference is not an error - the record ages with every
        further commit, and currency is demanded in the ONE place where it
        matters: in the gate before a public push, that is in the checkpoint
        of task 3)
"""

from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

import check_pub_gate

__all__ = [
    "DEFAULT_RECORD_PATH",
    "REQUIRED_KEYS",
    "VALID_RESULTS",
    "REQUIRED_SURFACES",
    "REQUIRED_RULES",
    "EXIT_OK",
    "EXIT_REQUIRE_CLEAN_FAILED",
    "EXIT_MISSING_FILE",
    "EXIT_INVALID_SHAPE",
    "EXIT_PENDING",
    "EXIT_STALE_HEAD",
    "validate_record",
    "main",
]

DEFAULT_RECORD_PATH = "compliance/history-audit.md"

REQUIRED_KEYS: tuple[str, ...] = (
    "requirement",
    "scope",
    "audited_on",
    "head_sha",
    "surfaces",
    "rules_checked",
    "exceptions_file",
    "result",
    "author",
    "confirmed_on",
)

VALID_RESULTS: frozenset[str] = frozenset({"clean", "hits-outside-exceptions", "pending"})

# The three surfaces from task 1 (`tests/test_history_audit.py::HISTORY_SURFACES`).
# Not imported from there directly: a test module is not a dependency this
# script (standard library plus the sibling gate, see the isolation test over
# the syntax tree) may carry. The values are nonetheless IDENTICAL - this is
# the only place where the record is put side by side with the actual scope of
# the scan, so widening the scan surface requires widening this tuple in BOTH
# places, otherwise the record claims more than the scan checked.
REQUIRED_SURFACES: tuple[str, str, str] = ("tree-content", "commit-message", "file-name")

# The four SHAPE rules of the identity layer (`IDENTITY_RULE_IDS[:-1]` in
# `scripts/confidentiality_guard.py` and in `tests/test_history_audit.py`) -
# NOT the fifth, local one (`identity-local-literal`), because that one works
# ONLY locally from a gitignored file and the history audit (which has to run
# in CI) has nothing to check it against. The same remark about a single point
# of comparison as above for `REQUIRED_SURFACES` applies to this tuple too.
REQUIRED_RULES: tuple[str, ...] = (
    "identity-private-ipv4",
    "identity-mac-address",
    "identity-device-name",
    "identity-project-name",
)

EXIT_OK = 0
EXIT_REQUIRE_CLEAN_FAILED = 1
EXIT_MISSING_FILE = 3
EXIT_INVALID_SHAPE = 4
EXIT_PENDING = 5
EXIT_STALE_HEAD = 6


def _current_head_sha() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def validate_record(fields: dict[str, str], body: str) -> list[str]:
    """Checks the SHAPE of the record ONLY (presence of the keys, allowed
    values, whether the dates parse, the rule for the `author` field) and
    returns a list of errors - an EMPTY list means the shape is valid.

    An EMPTY `author` field and an EMPTY `confirmed_on` field are NOT shape
    errors here (decision R-8) - that is a separate state (PENDING),
    recognized by `main()` AFTER this function returns an empty list. A
    NON-EMPTY `author` field belonging to the set of agent names IS a shape
    error - the executor of a plan has no way to sign on behalf of a human,
    and an attempt to do so (or to type an obvious placeholder) is meant to
    trip the same gate the sibling gate applies to the `reviewer` field.
    """
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        return [f"Record incomplete: missing fields {', '.join(missing)}."]

    errors: list[str] = []

    result = fields["result"].strip()
    if result not in VALID_RESULTS:
        errors.append(
            f"The result field carries a disallowed value: {result!r} (allowed: "
            f"{sorted(VALID_RESULTS)})."
        )

    surfaces = {s.strip() for s in fields["surfaces"].split(",") if s.strip()}
    if surfaces != set(REQUIRED_SURFACES):
        errors.append(
            f"The surfaces field carries an incomplete or wrong list of "
            f"surfaces: {fields['surfaces']!r} (required: "
            f"{sorted(REQUIRED_SURFACES)})."
        )

    rules = {r.strip() for r in fields["rules_checked"].split(",") if r.strip()}
    if rules != set(REQUIRED_RULES):
        errors.append(
            f"The rules_checked field carries an incomplete or wrong list of "
            f"rules: {fields['rules_checked']!r} (required: "
            f"{sorted(REQUIRED_RULES)})."
        )

    audited_on = fields["audited_on"].strip()
    try:
        datetime.date.fromisoformat(audited_on)
    except ValueError:
        errors.append(
            f"The audited_on field is not a valid ISO date (YYYY-MM-DD): "
            f"{audited_on!r}."
        )

    author = fields["author"].strip()
    if author and check_pub_gate.reviewer_is_invalid(author):
        errors.append(
            "The author field is a placeholder or points at an agent "
            "instead of a human."
        )

    confirmed_on = fields["confirmed_on"].strip()
    if confirmed_on:
        try:
            datetime.date.fromisoformat(confirmed_on)
        except ValueError:
            errors.append(
                f"The confirmed_on field is not a valid ISO date (YYYY-MM-DD): "
                f"{confirmed_on!r}."
            )

    return errors


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_history_audit_gate",
        description=(
            "Shape gate for the record of the three-surface audit of the "
            "whole repository history (PUB-05): checks the shape and the "
            "currency of the record ONLY, never whether the scan actually ran."
        ),
    )
    parser.add_argument(
        "--record",
        default=DEFAULT_RECORD_PATH,
        help=f"Path to the record (default {DEFAULT_RECORD_PATH}).",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help=(
            "Force result=clean: a record with the result hits-outside-exceptions "
            "then exits with code 1 instead of 0."
        ),
    )
    parser.add_argument(
        "--require-current",
        action="store_true",
        help=(
            "Force the head_sha field to equal the present HEAD: a record "
            "pointing at another hash then exits with code 6. Without this "
            "flag the difference is not an error (assumption Z-100)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    record_path = Path(args.record)

    try:
        fields, body = check_pub_gate.load_record(record_path)
    except FileNotFoundError:
        print(f"No record file: {record_path}", file=sys.stderr)
        return EXIT_MISSING_FILE
    except check_pub_gate.RecordShapeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_SHAPE

    shape_errors = validate_record(fields, body)
    if shape_errors:
        for error in shape_errors:
            print(error, file=sys.stderr)
        return EXIT_INVALID_SHAPE

    author = fields["author"].strip()
    confirmed_on = fields["confirmed_on"].strip()
    if not author or not confirmed_on:
        print(
            "The audit record is waiting for a human signature (the author or "
            "confirmed_on field is empty) - this is an expected state, not an error.",
            file=sys.stderr,
        )
        return EXIT_PENDING

    if args.require_current:
        current_head = _current_head_sha()
        record_head = fields["head_sha"].strip()
        if record_head != current_head:
            print(
                f"The record points at the HEAD hash {record_head!r}, the present "
                f"HEAD is {current_head!r} - a repeated audit is required before "
                "a public push.",
                file=sys.stderr,
            )
            return EXIT_STALE_HEAD

    result = fields["result"].strip()
    print(f"result={result}")
    if args.require_clean and result != "clean":
        print(
            "result=clean was required (the --require-clean flag), and the record "
            f"carries the result {result!r}.",
            file=sys.stderr,
        )
        return EXIT_REQUIRE_CLEAN_FAILED

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
