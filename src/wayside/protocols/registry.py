"""Rejestr dissectorow: skan katalogu w czasie dzialania, bez rejestru
statycznego (PROTO-05, ten sam wzorzec co `checks/engine.py` dla D-06).

Nowy protokol to nowy katalog z plikiem `manifest.yaml` i plikiem
siostrzanym pod `protocols/dissectors/<nazwa>/` - ten modul sie przy tym
nie zmienia, bo `discover_dissectors` odkrywa pliki fizycznie przez
`sorted(dissectors_root.rglob("manifest.yaml"))`, nie przez liste
zaimportowanych modulow (PROTO-05).

Pole `dissector` jest rozwiazywane jako plik SIOSTRZANY wobec
`manifest.yaml`, przez `importlib.util.spec_from_file_location`, nigdy przez
`importlib.import_module` na sciezce z kropkami - to zamyka to samo
zagrozenie (T-4-01), ktore `checks/engine.py::_load_evaluator` zamyka dla
pola `evaluator` (T-2-04).
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
    """Plik manifestu dissectora nie ma poprawnego ksztaltu, `dissector`
    wskazuje na niedozwolony modul, albo zdarzenie zwrocone przez dissector
    nie ma poprawnego ksztaltu."""


@dataclass(frozen=True)
class DissectorSpec:
    path: Path
    spec: dict
    dissect: Callable[[list], list[dict]]


def _validate_fields(spec: dict, manifest_path: Path) -> None:
    missing = [field for field in REQUIRED_DISSECTOR_FIELDS if not spec.get(field)]
    if missing:
        raise DissectorSchemaError(
            f"Dissector {manifest_path} niekompletny: brak albo puste pola {missing}."
        )

    confidence = spec["confidence"]
    if confidence not in ALLOWED_CONFIDENCE:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: pole confidence ma wartosc "
            f"{confidence!r}, dozwolone wartosci to {ALLOWED_CONFIDENCE}."
        )


def _load_dissector(spec: dict, manifest_path: Path) -> Callable[[list], list[dict]]:
    dissector_ref = spec["dissector"]
    module_name, sep, func_name = dissector_ref.partition(":")
    if not sep or not module_name or not func_name:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: pole dissector ma niepoprawny ksztalt "
            f"{dissector_ref!r}, oczekiwano 'modul:funkcja'."
        )
    if any(token in module_name for token in ("/", "\\", ".")):
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: nazwa modulu dissectora {module_name!r} "
            "nie moze zawierac separatora sciezki ani kropki (zagrozenie T-4-01)."
        )

    module_path = manifest_path.parent / f"{module_name}.py"
    if not module_path.is_file():
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: plik dissectora nie istnieje: {module_path}."
        )

    module_spec = importlib.util.spec_from_file_location(
        f"wayside._protocols.{module_name}", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: nie udalo sie zaladowac modulu dissectora "
            f"{module_path}."
        )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

    dissect = getattr(module, func_name, None)
    if not callable(dissect):
        raise DissectorSchemaError(
            f"Dissector {manifest_path}: funkcja {func_name!r} nie istnieje w "
            f"{module_path}."
        )
    return dissect


def discover_dissectors(dissectors_root: Path = DISSECTORS_ROOT) -> list[DissectorSpec]:
    """Skanuje `dissectors_root` w poszukiwaniu plikow `manifest.yaml`, w
    kolejnosci posortowanej (kolejnosc systemu plikow nie jest gwarantowana
    miedzy maszynami - determinizm bajtowy `analysis.json` zalezy od tego
    sortowania, REPORT-06). Dwa manifesty o identycznym `id` koncza sie
    `DissectorSchemaError`, nigdy cichym nadpisaniem. Katalog nieistniejacy
    zwraca liste pusta - `rglob` na sciezce nieistniejacej zwraca iterator
    pusty, wiec to zachowanie wynika z biblioteki."""
    dissectors: list[DissectorSpec] = []
    seen_ids: dict[str, Path] = {}

    for manifest_path in sorted(dissectors_root.rglob("manifest.yaml")):
        spec = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        _validate_fields(spec, manifest_path)

        dissector_id = spec["id"]
        if dissector_id in seen_ids:
            raise DissectorSchemaError(
                f"Zduplikowany identyfikator dissectora {dissector_id!r}: "
                f"{seen_ids[dissector_id]} oraz {manifest_path}."
            )
        seen_ids[dissector_id] = manifest_path

        dissect = _load_dissector(spec, manifest_path)
        dissectors.append(DissectorSpec(path=manifest_path, spec=spec, dissect=dissect))

    return dissectors


def _validate_event_shape(event: dict, dissector: DissectorSpec) -> None:
    missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
    if missing:
        raise DissectorSchemaError(
            f"Dissector {dissector.path}: zdarzenie bez pol wymaganych {missing}."
        )
    manifest_protocol = dissector.spec["id"]
    event_protocol = event.get("protocol")
    if event_protocol is not None and event_protocol != manifest_protocol:
        raise DissectorSchemaError(
            f"Dissector {dissector.path}: zdarzenie niesie pole protocol "
            f"{event_protocol!r}, sprzeczne z identyfikatorem manifestu "
            f"{manifest_protocol!r}."
        )


def run_dissectors(
    segments: list, dissectors: list[DissectorSpec]
) -> tuple[list[dict], list[dict]]:
    """Uruchamia kazdy dissector nad PELNA lista `segments` (kazdy dissector
    jest bezstanowy i sam odrzuca segmenty, ktore go nie dotycza), rejestr
    wstrzykuje pola `protocol` i `confidence` z manifestu do kazdego
    zdarzenia zwroconego przez dissector - dissector nie ma jak podniesc
    wlasnej pewnosci rozpoznania (zalozenie Z-41, zagrozenie T-4-03).

    Wynik jest rozdzielany na dwie listy po polu `confidence` z MANIFESTU:
    zdarzenia dissectorow o pewnosci `high` ida do pierwszej listy
    (`protocol_events`), o pewnosci `low` do drugiej
    (`low_confidence_events`). Obie listy sa sortowane po trojce
    `(packet_number, session_id, protocol)` PRZED zwrotem - trzeci klucz
    jest potrzebny, bo dwa dissectory moga rozpoznac ten sam segment w tej
    samej sesji, a wtedy para pierwszych kluczy nie rozstrzyga kolejnosci."""
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
