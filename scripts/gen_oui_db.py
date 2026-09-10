"""One-off generator of the vendor table from the IEEE OUI registry (ASSET-02).

Usage:
    uv run python scripts/gen_oui_db.py
        Downloads `IEEE_OUI_CSV_URL` over the network and writes
        `src/wayside/assets/oui_table.tsv` (the default path).

    uv run python scripts/gen_oui_db.py --source path/to/oui.csv
        Builds the table from a CSV file already sitting on disk - zero
        network connections. The fallback route for a machine cut off from
        the network (`03-RESEARCH.md`, section "Environment Availability").

    uv run python scripts/gen_oui_db.py --output output/path.tsv
        Overrides the output path - useful when building the file into a
        temporary directory for a test or a comparison.

This script is a DEVELOPER operation, run by hand. `wayside analyze` never
calls it and never reaches for the network - the runtime layer
(`src/wayside/assets/oui.py`) reads only the file produced here, already
sitting on disk (Pattern 6, `03-RESEARCH.md`).

Two runs against the same CSV source, on the same day, produce a byte
identical output file - the header comment carries the file's generation
date, so byte reproducibility is bounded by one calendar day (assumption
Z-24 from PLAN.md: this file does NOT fall under the determinism gate of
`scripts/gen_fixtures.py --check`, because the data comes from a third
party and is not a fixture generated out of the repository itself).
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import sys
import urllib.request
from pathlib import Path

from wayside.assets.oui import OUI_TABLE_PATH, normalize_mac_prefix

__all__ = [
    "IEEE_OUI_CSV_URL",
    "fetch_oui_csv",
    "build_table",
    "write_table",
    "main",
]

# Address confirmed as the official endpoint of the IEEE Registration
# Authority registry [CITED: WebSearch 2026-09-04, 03-RESEARCH.md Pattern 6].
IEEE_OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# Column names expected in the header of the registry CSV. Used only to read
# values AFTER `csv.DictReader` has derived the header from the first row of
# the source file itself - the vendor's file format is not a contract of
# this project, so column order is never assumed.
_COLUMN_PREFIX = "Assignment"
_COLUMN_ORGANIZATION = "Organization Name"


def fetch_oui_csv(*, url: str = IEEE_OUI_CSV_URL, source_path: Path | None = None) -> str:
    """Returns the content of the IEEE OUI registry CSV file as a string.

    `source_path` given: reads the file from disk, with an explicit
    `encoding="utf-8"`, and does NOT touch the network - the fallback route
    for a disconnected machine. `source_path` omitted: downloads `url`
    through `urllib.request` from the standard library, over the encrypted
    protocol only, with no redirect onto an unencrypted one.
    """
    if source_path is not None:
        return Path(source_path).read_text(encoding="utf-8")

    if not url.startswith("https://"):
        raise ValueError(
            f"The source address {url!r} does not use the encrypted protocol (https)."
        )

    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset)


def build_table(csv_text: str) -> list[tuple[str, str]]:
    """Parses the IEEE OUI registry CSV into a list of (prefix, organisation
    name) pairs.

    Column names are read from the first row of the source file by
    `csv.DictReader` - the vendor's file format is not a contract this
    project controls. The prefix is normalized by
    `wayside.assets.oui.normalize_mac_prefix` (the same function the runtime
    layer uses for lookups - one source of truth about the shape of a
    prefix). The organisation name is cleared of tab and end-of-line
    characters by collapsing whitespace - a tab inside a name would break
    the output format of the table.

    A row with an invalid prefix or an empty name is skipped, but the NUMBER
    of skipped rows is printed to stderr - silently losing rows during a data
    transformation is the same failure mode as silently dropping a host from
    the inventory.

    A prefix appearing in the source more than once (the IEEE registry does
    contain such cases - the same range reassigned over time) keeps the LAST
    organisation name encountered: that is the same order of precedence
    `load_oui_table` applies when building its dictionary from the file, so
    the generator's output file and its reading in the runtime layer stay
    consistent.

    Returns the list of pairs sorted ascending by prefix.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    fieldnames = reader.fieldnames or []
    if _COLUMN_PREFIX not in fieldnames or _COLUMN_ORGANIZATION not in fieldnames:
        raise ValueError(
            f"The CSV source lacks the expected columns {_COLUMN_PREFIX!r} and "
            f"{_COLUMN_ORGANIZATION!r} in its first row - found "
            f"{fieldnames!r}."
        )

    table: dict[str, str] = {}
    skipped = 0
    for row in reader:
        raw_prefix = (row.get(_COLUMN_PREFIX) or "").strip()
        raw_name = (row.get(_COLUMN_ORGANIZATION) or "").strip()
        prefix = normalize_mac_prefix(raw_prefix)
        cleaned_name = " ".join(raw_name.split())
        if prefix is None or not cleaned_name:
            skipped += 1
            continue
        table[prefix] = cleaned_name

    if skipped:
        print(
            f"Skipped {skipped} source row(s) with an invalid prefix "
            "or an empty organisation name.",
            file=sys.stderr,
        )

    return sorted(table.items())


def write_table(rows: list[tuple[str, str]], output_path: Path, *, source: str) -> Path:
    """Writes the prefix-to-vendor table under `output_path`.

    Explicit `encoding="utf-8"` and explicit `newline="\\n"` - the same
    discipline as `model.write_atomic` from Phase 2: a file written on
    Windows must not diverge in line endings from a file written elsewhere.
    The first three lines are comments carrying the source, the file's
    generation date and the number of entries; then the data rows, prefix
    and name separated by a tab, in the order `build_table` already sorted.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated_on = datetime.date.today().isoformat()
    lines = [
        f"# source: {source}\n",
        f"# generated on: {generated_on}\n",
        f"# entries: {len(rows)}\n",
    ]
    lines.extend(f"{prefix}\t{name}\n" for prefix, name in rows)

    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(lines)
    return output_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help=(
            "Path to an IEEE OUI registry CSV file already sitting on disk. "
            "Given: zero network connections. Omitted: a download from "
            f"{IEEE_OUI_CSV_URL}."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUI_TABLE_PATH,
        help=f"Path of the output file (default {OUI_TABLE_PATH}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        csv_text = fetch_oui_csv(source_path=args.source)
    except (OSError, ValueError) as exc:
        print(f"Could not read the IEEE OUI registry source: {exc}", file=sys.stderr)
        return 1

    try:
        rows = build_table(csv_text)
    except ValueError as exc:
        print(f"The CSV source has an unexpected shape: {exc}", file=sys.stderr)
        return 1

    if not rows:
        print("The source carried no valid data row.", file=sys.stderr)
        return 1

    source_label = str(args.source) if args.source is not None else IEEE_OUI_CSV_URL
    output_path = write_table(rows, args.output, source=source_label)
    print(f"Written {len(rows)} vendor entries to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
