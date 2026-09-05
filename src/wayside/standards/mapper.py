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
    "CATALOG_FIELD_TYPES",
    "OPTIONAL_CATALOG_FIELD_TYPES",
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

# Typ oczekiwany kazdego pola z REQUIRED_CATALOG_FIELDS. Pole `verified` musi
# byc `bool` - wartosc dowolnego innego typu (napis, liczba) nie ma prawa
# przejsc przez wczytanie, bo `resolve` przekazuje ta wartosc dalej BEZ zadnej
# konwersji (G-04-2).
CATALOG_FIELD_TYPES: dict[str, type] = {
    "standard": str,
    "edition": str,
    "clause": str,
    "clause_title": str,
    "paraphrase": str,
    "verified": bool,
}

# Pola OPCJONALNE, kontrolowane co do typu tylko wtedy, gdy sa obecne we
# wpisie (Z-77) - wymuszenie obecnosci zamknelo by droge wpisu w pelni
# potwierdzonego, ktory zadnej notatki o prowizorycznosci nie potrzebuje.
OPTIONAL_CATALOG_FIELD_TYPES: dict[str, type] = {
    "verification_note": str,
}


class StandardsError(Exception):
    """Katalog norm niekompletny albo powolanie zadane przed wypelnieniem
    modelu strefy (STD-06)."""


def _validate_entry_fields(entry: dict, yaml_path: Path) -> None:
    """Sprawdza `REQUIRED_CATALOG_FIELDS` w trzech przebiegach: obecnosc
    kazdego pola, niepustosc (poza `verified`, ktorego legalna wartoscia jest
    `False`), i typ wartosci. `verified` jest wykluczone z kontroli
    niepustosci celowo: `False` jest fasz-owate w Pythonie, ale jest tu
    jedyna poprawna wartoscia (wpis prowizoryczny), wiec traktowanie go jak
    brakujacego pola byloby bledem. Od bramki typu ponizej to wylaczenie jest
    bezpieczne, bo przebieg typu obejmuje pole `verified` wprost i odrzuci
    kazda wartosc, ktora nie jest dokladnie `bool`."""
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

    # Przebieg typu: porownanie DOKLADNE przez tozsamosc typu (`type(x) is T`),
    # nie przez `isinstance` (Z-76). `bool` jest w Pythonie podklasa `int`,
    # wiec sprawdzenie przynaleznosci do klasy nad polem liczbowym przyjeloby
    # wartosc logiczna i bramka bylaby slabsza, niz sie czyta - katalog nie ma
    # dzis pol liczbowych, ale ta bramka ma trzymac takze te, ktore powstana
    # pozniej. Komunikat niesie wylacznie nazwe pola i nazwy typow (z atrybutu
    # nazwy klasy), NIGDY wartosc pola - katalog niesie parafraze punktu
    # platnej normy (T-4-37).
    type_errors: list[str] = []
    for field, expected_type in CATALOG_FIELD_TYPES.items():
        value = entry[field]
        if type(value) is not expected_type:
            type_errors.append(
                f"{field} (oczekiwano {expected_type.__name__}, "
                f"otrzymano {type(value).__name__})"
            )
    for field, expected_type in OPTIONAL_CATALOG_FIELD_TYPES.items():
        if field not in entry:
            continue
        value = entry[field]
        if type(value) is not expected_type:
            type_errors.append(
                f"{field} (oczekiwano {expected_type.__name__}, "
                f"otrzymano {type(value).__name__})"
            )
    if type_errors:
        raise StandardsError(
            f"Wpis katalogu {yaml_path} niesie pola zlego typu: "
            f"{', '.join(type_errors)}."
        )


def load_catalog(catalog_root: Path = CATALOG_ROOT) -> dict[tuple[str, str], dict]:
    """Wczytuje wszystkie pliki `catalog.yaml` pod `catalog_root`, w
    kolejnosci posortowanej, i buduje mapowanie `(standard, clause) -> wpis`.

    Dwa pliki katalogu niosace ta sama pare (standard, clause) koncza sie
    `StandardsError` z OBIEMA sciezkami w komunikacie, nigdy cichym
    nadpisaniem - wzorzec `discover_checks` silnika checkow. Bez tej bramki
    cicha wygrana pliku wczytanego pozniej bylaby nieodrozialna od
    poprawnego wczytania, a od tej fazy w drzewie stoja dwa pliki katalogu."""
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
                    f"Zduplikowana para (standard, clause) {key} miedzy "
                    f"plikami katalogu: {seen_paths[key]} oraz {yaml_path}."
                )
            seen_paths[key] = yaml_path
            catalog[key] = entry

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
        # Bez konwersji: warstwa wczytujaca gwarantuje juz typ `bool`, wiec
        # konwersja w tym miejscu moglaby juz tylko ukryc defekt danych, a
        # decyzja 0006 prowadzi czlowieka przez reczna edycje tego pliku bez
        # gwarancji, ze przed zaufaniem edycji uruchomi pakiet testow.
        verified=entry["verified"],
        verification_note=entry.get("verification_note", ""),
    )
