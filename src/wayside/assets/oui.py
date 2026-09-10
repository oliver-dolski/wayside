"""Device vendor lookup from a MAC address prefix against a local table
derived from the IEEE registry (ASSET-02).

Three things stated outright, as the documentation of this module requires
across the project:

1. The data comes from a one-off download of the IEEE OUI registry,
   performed by hand through `scripts/gen_oui_db.py` - a developer script
   which is NEVER called by this runtime layer.
2. This layer reads only a local file from disk (`OUI_TABLE_PATH`) and
   NEVER performs any network request - `wayside analyze` stays passive and
   fit to run on a disconnected network.
3. The vendor is an INFERENCE derived from the table, not an observation
   from the traffic (assumption Z-23): the organisation name may be out of
   date, or may name a chip supplier rather than the final device
   manufacturer. Every result of this module is therefore meant to carry a
   marker of the `inferred` family, never `observed` - this module does not
   assign the marker itself, the caller does
   (`wayside.assets.inventory.build_assets`).

`OUI_TABLE_PATH` is derived from `Path(__file__).resolve().parent`, never
from the process's current directory - the same principle `CATALOG_ROOT`
carries in `wayside.standards.mapper`.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "OUI_TABLE_PATH",
    "OUI_PREFIX_LEN",
    "PROVENANCE_METHOD_OUI",
    "OuiTableError",
    "normalize_mac_prefix",
    "load_oui_table",
    "lookup_vendor",
]

OUI_TABLE_PATH = Path(__file__).resolve().parent / "oui_table.tsv"
OUI_PREFIX_LEN = 6
PROVENANCE_METHOD_OUI = "oui-lookup"

_HEX_DIGITS = frozenset("0123456789ABCDEF")
_SEPARATOR_TRANSLATION = str.maketrans("", "", ":-.")


class OuiTableError(Exception):
    """The vendor table is unreadable, absent from disk, or carries a row
    breaking the two-column tab-separated format."""


def normalize_mac_prefix(mac: str) -> str | None:
    """Returns the MAC address prefix as six upper-case hexadecimal
    characters, without separators, or `None` for invalid input.

    It strips colons, hyphens and dots, upper-cases the letters and checks
    that the result has at least `OUI_PREFIX_LEN` characters and that every
    character of the prefix is a hexadecimal digit. A MAC address comes from
    a frame, that is from untrusted input - the function NEVER raises: an
    invalid value is expected input, not a program error.
    """
    stripped = mac.translate(_SEPARATOR_TRANSLATION).upper()
    if len(stripped) < OUI_PREFIX_LEN:
        return None
    prefix = stripped[:OUI_PREFIX_LEN]
    if not all(ch in _HEX_DIGITS for ch in prefix):
        return None
    return prefix


def load_oui_table(path: Path = OUI_TABLE_PATH) -> dict[str, str]:
    """Loads the prefix-to-vendor table from the text file at `path`, with
    an explicit `encoding="utf-8"`.

    Empty rows and rows starting with a hash sign are skipped. Every
    remaining row has to have exactly two parts separated by a tab (prefix,
    organisation name) and the prefix has to pass `normalize_mac_prefix`;
    any other number of parts or an invalid prefix raises `OuiTableError`
    with the ROW NUMBER in the message - silently skipping a damaged row
    would turn a damaged data file into a silent, incomplete answer. A
    non-existent path raises `OuiTableError` with a message naming the
    absence of the table in this tree (assumption Z-21) -
    `wayside.pipeline.analyze` turns that into an explicit warning, never
    into a silent undetermined field.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OuiTableError(
            f"The vendor table was not read from the path {path} - the file "
            "has not been bundled with this repository tree."
        ) from exc

    table: dict[str, str] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            raise OuiTableError(
                f"Vendor table {path}, row {line_no}: expected two "
                f"tab-separated columns, found {len(parts)}."
            )
        raw_prefix, vendor_name = parts
        prefix = normalize_mac_prefix(raw_prefix)
        if prefix is None:
            raise OuiTableError(
                f"Vendor table {path}, row {line_no}: the prefix "
                f"{raw_prefix!r} is not valid hexadecimal notation."
            )
        table[prefix] = vendor_name
    return table


def lookup_vendor(mac: str, table: dict[str, str]) -> str | None:
    """Returns the organisation name for the address `mac` against `table`,
    or `None` when the address is invalid or its prefix has no match in the
    table. It composes `normalize_mac_prefix` with a dictionary read through
    `.get` - it never raises."""
    prefix = normalize_mac_prefix(mac)
    if prefix is None:
        return None
    return table.get(prefix)
