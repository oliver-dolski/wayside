"""Rozwiazywanie powolania na punkt normy wobec publicznego katalogu
(STD-01, STD-02, STD-06).

`resolve` przyjmuje model strefy jako argument WYMAGANY i podnosi
`StandardsError`, gdy lista stref jest pusta - STD-06 wymaga, zeby model
strefy istnial wypelniony PRZED pierwszym powolaniem na wymaganie systemowe,
a argument wymagany czyni to sprawdzalnym maszynowo, nie kwestia kolejnosci
wywolan. Komunikat bledu niesie wylacznie metadane, nigdy tresc normy - ta
sama dyscyplina co `Violation` w `scripts/confidentiality_guard.py`.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from wayside.model import StandardRef

__all__ = [
    "CATALOG_ROOT",
    "REQUIRED_CATALOG_FIELDS",
    "StandardsError",
    "load_catalog",
    "resolve",
]

CATALOG_ROOT = Path(__file__).resolve().parent

REQUIRED_CATALOG_FIELDS: tuple[str, ...] = (
    "standard",
    "edition",
    "clause",
    "clause_title",
    "paraphrase",
    "verified",
)


class StandardsError(Exception):
    """Katalog norm niekompletny albo powolanie zadane przed wypelnieniem
    modelu strefy (STD-06)."""


def _validate_entry_fields(entry: dict, yaml_path: Path) -> None:
    """Sprawdza `REQUIRED_CATALOG_FIELDS`: obecnosc kazdego pola, i - poza
    `verified`, ktorego legalna wartoscia jest `False` - takze niepustosc.
    `verified` jest wykluczone z kontroli niepustosci celowo: `False` jest
    fasz-owate w Pythonie, ale jest tu jedyna poprawna wartoscia (wpis
    prowizoryczny), wiec traktowanie go jak brakujacego pola byloby bledem."""
    missing = [field for field in REQUIRED_CATALOG_FIELDS if field not in entry]
    if missing:
        raise StandardsError(
            f"Wpis katalogu {yaml_path} niekompletny: brak pol {missing}."
        )

    empty = [
        field
        for field in REQUIRED_CATALOG_FIELDS
        if field != "verified" and not entry.get(field)
    ]
    if empty:
        raise StandardsError(
            f"Wpis katalogu {yaml_path} niekompletny: puste pola {empty}."
        )


def load_catalog(catalog_root: Path = CATALOG_ROOT) -> dict[tuple[str, str], dict]:
    """Wczytuje wszystkie pliki `catalog.yaml` pod `catalog_root`, w
    kolejnosci posortowanej, i buduje mapowanie `(standard, clause) -> wpis`."""
    catalog: dict[tuple[str, str], dict] = {}

    for yaml_path in sorted(catalog_root.rglob("catalog.yaml")):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        entries = data.get("entries", [])
        for entry in entries:
            _validate_entry_fields(entry, yaml_path)
            catalog[(entry["standard"], entry["clause"])] = entry

    return catalog


def resolve(standard: str, clause: str, *, zone_model: dict) -> StandardRef:
    """Rozwiazuje `(standard, clause)` wobec katalogu. Model strefy jest
    argumentem wymaganym: pusta lista stref konczy sie `StandardsError`
    (STD-06), zanim jakikolwiek katalog zostanie w ogole odczytany."""
    if not zone_model.get("zones"):
        raise StandardsError(
            "Model strefy jest pusty - powolanie na wymaganie systemowe "
            "wymaga wypelnionego modelu strefy przed wygenerowaniem (STD-06)."
        )

    catalog = load_catalog()
    entry = catalog.get((standard, clause))
    if entry is None:
        raise StandardsError(
            f"Brak wpisu w katalogu norm dla standard={standard!r}, "
            f"clause={clause!r}."
        )

    return StandardRef(
        standard=entry["standard"],
        edition=entry["edition"],
        clause=entry["clause"],
        clause_title=entry["clause_title"],
        paraphrase=entry["paraphrase"],
        verified=bool(entry["verified"]),
        verification_note=entry.get("verification_note", ""),
    )
