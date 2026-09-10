"""Shape gate for the PUB-01 record (`compliance/pre-publication-review.md`).

This module is dependency-isolated from the rest of the `wayside` package and
uses the Python standard library ONLY. That is a condition, not a preference:
the gate has to work as a preliminary step before every public push, on a
machine without a synchronized project environment as well (without
`uv sync`).

This script checks the SHAPE of the record ONLY - the presence of the
required fields, whether the date parses, the absence of a block quote in the
body, and the rules for the `reviewer` field. It does not and cannot check
whether the recorded verdict matches what a human actually said - that is the
subject of the `backstop` verification in PLAN.md, not of code.

The frontmatter is parsed by a small hand-written reader of `key: value`
pairs between two `---` separator lines, without any YAML library.

Exit codes (part of the contract, they must stay distinguishable):
    0 - record complete with an explicit verdict (`go` or `no-go`)
    1 - verdict `no-go` while the `--require-go` flag was given
    3 - the record file is absent
    4 - record incomplete or breaking the body rule
    5 - verdict still `pending`
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

__all__ = [
    "load_record",
    "validate_record",
    "main",
    "reviewer_is_invalid",
    "AGENT_REVIEWER_NAMES",
    "RecordShapeError",
]

DEFAULT_RECORD_PATH = "compliance/pre-publication-review.md"

REQUIRED_KEYS: tuple[str, ...] = (
    "requirement",
    "scope",
    "reviewed_on",
    "reviewer",
    "verdict",
)

VALID_VERDICTS: frozenset[str] = frozenset({"go", "no-go", "pending"})

# The only control against a fabricated verdict that can be written down in
# code: the `reviewer` field must not belong to the list of agent names. It
# does not catch a human impersonating himself, nor an agent typing in the
# author's real name - the agreement between the record and the spoken
# decision remains a backstop-class predicate (see PLAN.md, must_haves).
#
# The list stays bilingual on purpose: the author writes this field by hand
# and a Polish placeholder ("skrypt", "asystent") is exactly the mistake this
# threshold is meant to catch. Widening the detection never costs correctness.
AGENT_REVIEWER_NAMES: frozenset[str] = frozenset(
    {
        "agent",
        "ai",
        "assistant",
        "asystent",
        "automated",
        "bot",
        "llm",
        "model",
        "script",
        "skrypt",
    }
)

# Token boundaries inside the `reviewer` field. Splitting on whitespace alone
# let `some-bot` and `helper_agent` through even though a bare `bot` was
# rejected - that was a tokenization bug, not a weakness of the heuristic.
_REVIEWER_TOKEN_SPLIT = re.compile(r"[^0-9A-Za-z]+")

EXIT_OK = 0
EXIT_REQUIRE_GO_FAILED = 1
EXIT_MISSING_FILE = 3
EXIT_INVALID_SHAPE = 4
EXIT_PENDING = 5


class RecordShapeError(ValueError):
    """The frontmatter is malformed (missing separators, a line without a colon)."""


def load_record(path: Path) -> tuple[dict[str, str], str]:
    """Reads the record: the frontmatter as key-value pairs plus the body.

    Raises `FileNotFoundError` when the file does not exist, and
    `RecordShapeError` when the frontmatter is not closed between two `---`
    lines. Empty lines and lines starting with `#` inside the frontmatter are
    skipped.
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    if not lines or lines[0].strip() != "---":
        raise RecordShapeError(
            f"The record {path} does not start with the frontmatter separator '---'."
        )

    fields: dict[str, str] = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip() != "---":
        raw_line = lines[idx]
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            if ":" not in raw_line:
                raise RecordShapeError(
                    f"The record {path}, line {idx + 1}: no colon in the "
                    f"frontmatter ({raw_line!r})."
                )
            key, _, value = raw_line.partition(":")
            fields[key.strip()] = value.strip()
        idx += 1

    if idx >= len(lines):
        raise RecordShapeError(
            f"The record {path} has no closing frontmatter separator '---'."
        )

    body = "\n".join(lines[idx + 1 :])
    return fields, body


def _reviewer_is_invalid(reviewer: str) -> bool:
    """Checks the `reviewer` field: empty, a placeholder, or an agent name.

    What this function is NOT: proof that a human made the decision. A name
    typed on a keyboard cannot be told apart from a name typed by an agent, so
    every such check is a release threshold, not a control. The actual control
    sits higher up: the verdict is reached at a `gate="blocking-human"`
    checkpoint, which is never approved automatically in any mode. Here we
    catch a slip and a placeholder, not a determined forger.

    A known boundary of the same family: the tokenization splits on
    non-alphanumeric boundaries, so "some-bot" and "some_bot" are caught, but
    a run-together form ("somebot", "SomeAgent") is not. We deliberately do
    not widen this to substring matching - "agent" occurs inside real
    surnames, and a false alarm would block a human verdict.
    """
    if not reviewer:
        return True
    if "<" in reviewer or ">" in reviewer:
        return True
    if "tbd" in reviewer.lower():
        return True
    tokens = {tok.lower() for tok in _REVIEWER_TOKEN_SPLIT.split(reviewer) if tok}
    if tokens & AGENT_REVIEWER_NAMES:
        return True
    return False


# Public alias (assumption Z-102, plan 05-04): `scripts/check_history_audit_gate.py`
# imports the author-field check FROM THIS gate instead of copying it - two
# lists of agent names in two files would drift apart, exactly the principle
# D-19 applies to the patterns of the identity layer. The private name
# (`_reviewer_is_invalid`) stays UNTOUCHED - this change is PURELY additive,
# no existing exit code or behaviour of this module changes.
reviewer_is_invalid = _reviewer_is_invalid


def _body_has_blockquote(body: str) -> int | None:
    """Returns the number of the first body line starting with a markdown

    block quote (`>`), or `None` when the body is clean.
    """
    for line_no, line in enumerate(body.splitlines(), start=1):
        if line.strip().startswith(">"):
            return line_no
    return None


def validate_record(fields: dict[str, str], body: str) -> tuple[int, str]:
    """Checks the shape of the record and returns (exit_code, message).

    The order of the checks matters: a missing field and a breach of the body
    rule (a block quote) are shape violations and always win, on a record that
    is not yet resolved (`pending`) as well. The `pending` verdict is checked
    BEFORE the rules for `reviewer`/`reviewed_on`, because those fields are
    deliberately empty in the initial state - that is not a shape violation,
    it is the state "not decided yet".
    """
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        return (
            EXIT_INVALID_SHAPE,
            f"Record incomplete: missing fields {', '.join(missing)}.",
        )

    blockquote_line = _body_has_blockquote(body)
    if blockquote_line is not None:
        return (
            EXIT_INVALID_SHAPE,
            f"The record carries a block quote on line {blockquote_line} of the body: "
            f"the record must neither quote nor paraphrase the agreement.",
        )

    verdict = fields["verdict"].strip()
    if verdict not in VALID_VERDICTS:
        return (
            EXIT_INVALID_SHAPE,
            f"The verdict field carries a disallowed value: {verdict!r}.",
        )

    if verdict == "pending":
        return (
            EXIT_PENDING,
            "The PUB-01 gate verdict has not been reached yet (verdict=pending).",
        )

    reviewer = fields["reviewer"].strip()
    if _reviewer_is_invalid(reviewer):
        return (
            EXIT_INVALID_SHAPE,
            "The reviewer field is empty, is a placeholder, or points at "
            "an agent instead of a human.",
        )

    reviewed_on = fields["reviewed_on"].strip()
    if not reviewed_on:
        return (EXIT_INVALID_SHAPE, "The reviewed_on field is empty.")
    try:
        datetime.date.fromisoformat(reviewed_on)
    except ValueError:
        return (
            EXIT_INVALID_SHAPE,
            f"The reviewed_on field is not a valid ISO date (YYYY-MM-DD): "
            f"{reviewed_on!r}.",
        )

    return (EXIT_OK, f"verdict={verdict}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_pub_gate",
        description=(
            "Shape gate for the PUB-01 record: checks whether the review of "
            "the employment agreement is recorded in a machine-readable form."
        ),
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Path to the record (default {DEFAULT_RECORD_PATH}).",
    )
    parser.add_argument(
        "--require-go",
        action="store_true",
        help=(
            "Force verdict=go: a record with verdict=no-go then exits with "
            "code 1 instead of 0."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    record_path = Path(args.record_path)

    try:
        fields, body = load_record(record_path)
    except FileNotFoundError:
        print(f"No record file: {record_path}", file=sys.stderr)
        return EXIT_MISSING_FILE
    except RecordShapeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_SHAPE

    code, message = validate_record(fields, body)

    if code == EXIT_OK:
        verdict = fields["verdict"].strip()
        print(f"verdict={verdict}")
        if args.require_go and verdict != "go":
            print(
                "verdict=go was required (the --require-go flag), and the record "
                f"carries the verdict {verdict!r}.",
                file=sys.stderr,
            )
            return EXIT_REQUIRE_GO_FAILED
        return EXIT_OK

    print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
