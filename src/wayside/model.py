"""Model kanoniczny: `analysis.json` jako jedyne zrodlo, dataclassy findingu
i zapis atomowy.

`Evidence` ma DOKLADNIE dwa pola i zadnego pola na surowe bajty ani na
tresc ladunku - to wlasnosc typu (zagrozenie T-2-06), na wzor `Violation`
w `scripts/confidentiality_guard.py`, ktore rowniez nie niesie dopasowanego
tekstu.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Evidence",
    "StandardRef",
    "Finding",
    "build_analysis",
    "dump_deterministic",
    "write_atomic",
    "PROVENANCE_OBSERVED",
    "PROVENANCE_NOT_DERIVABLE",
    "PROVENANCE_PATTERN",
    "ObservedField",
    "ProvenanceError",
    "observed",
    "inferred",
    "not_derivable",
    "iter_observed_fields",
    "assert_provenance_complete",
]

# Nosnik prowieniencji pola (zalozenie Z-01): kazde pole inwentarza niesie
# nie tylko wartosc, ale i sposob, w jaki ta wartosc powstala. Trzy rodziny
# znacznikow: `observed` (odczytane wprost z ramki), `inferred:<metoda>`
# (wyliczone, z nazwana metoda wnioskowania) i `not-derivable-passively`
# (nie da sie ustalic z pasywnego zrzutu - MUST NOT pomijac takiego pola).
PROVENANCE_OBSERVED = "observed"
PROVENANCE_NOT_DERIVABLE = "not-derivable-passively"
PROVENANCE_PATTERN = re.compile(r"^(observed|inferred:[a-z0-9_-]+|not-derivable-passively)$")


@dataclass(frozen=True)
class ObservedField:
    """Wartosc razem ze znacznikiem jej pochodzenia. `__post_init__` odrzuca
    znacznik spoza `PROVENANCE_PATTERN` od razu przy konstrukcji - ten sam
    styl co `severity_to_risk` w `risk.py`, ktory na wartosci spoza listy
    podnosi wyjatek zamiast zwracac wartosc domyslna."""

    value: object
    provenance: str

    def __post_init__(self) -> None:
        if not PROVENANCE_PATTERN.match(self.provenance):
            raise ValueError(
                f"Znacznik pochodzenia poza dozwolonym wzorcem: {self.provenance!r}"
            )


class ProvenanceError(Exception):
    """Pole inwentarza bez znacznika pochodzenia albo ze znacznikiem spoza
    `PROVENANCE_PATTERN`, wykryte przez `assert_provenance_complete`."""


def observed(value: object) -> ObservedField:
    """Pole odczytane wprost z ramki."""
    return ObservedField(value=value, provenance=PROVENANCE_OBSERVED)


def inferred(value: object, method: str) -> ObservedField:
    """Pole wyliczone metoda `method` (bez prefiksu `inferred:` - dopisywany
    tutaj)."""
    return ObservedField(value=value, provenance=f"inferred:{method}")


def not_derivable() -> ObservedField:
    """Pole, ktorego nie da sie ustalic z pasywnego zrzutu. `value` jest
    zawsze `None` - brak pola nigdy nie zastepuje tego znacznika."""
    return ObservedField(value=None, provenance=PROVENANCE_NOT_DERIVABLE)


def iter_observed_fields(node: object, path: str = "") -> Iterator[tuple[str, dict]]:
    """Generator przechodzacy rekurencyjnie po strukturze juz zserializowanej
    do slownikow i list (wynik `dataclasses.asdict`).

    Slownik o zbiorze kluczy dokladnie rownym `{"value", "provenance"}` JEST
    polem prowieniencji: generator oddaje pare `(path, node)` i NIE schodzi
    glebiej w `value` - wartosc bedaca przypadkiem takim samym slownikiem nie
    jest liczona dwa razy. Kazdy inny slownik jest kontenerem i generator
    schodzi w jego wartosci. Lista jest kontenerem i generator schodzi w jej
    elementy."""
    if isinstance(node, dict):
        if set(node.keys()) == {"value", "provenance"}:
            yield path, node
            return
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from iter_observed_fields(value, child_path)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            yield from iter_observed_fields(item, f"{path}[{index}]")


def assert_provenance_complete(node: object, path: str = "") -> None:
    """Podnosi `ProvenanceError` rekurencyjnie na kazdym polu inwentarza bez
    znacznika pochodzenia albo ze znacznikiem spoza `PROVENANCE_PATTERN`.

    Dwa przypadki naruszenia: wartosc skalarna (`str`, `int`, `float`,
    `bool`, `None`) NIE bedaca w polu `value` rozpoznanego pola prowieniencji,
    oraz pole prowieniencji, ktorego `provenance` nie pasuje do wzorca.
    Komunikat wyjatku niesie sciezke pola i nazwe naruszonego warunku, nigdy
    samej wartosci - ta sama dyscyplina co `Violation` bez pola tekstowego w
    `scripts/confidentiality_guard.py`."""
    if isinstance(node, dict):
        if set(node.keys()) == {"value", "provenance"}:
            provenance = node["provenance"]
            if not isinstance(provenance, str) or not PROVENANCE_PATTERN.match(provenance):
                raise ProvenanceError(
                    f"Pole '{path}' ma znacznik pochodzenia poza dozwolonym "
                    f"wzorcem: {provenance!r}"
                )
            return
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            assert_provenance_complete(value, child_path)
        return
    if isinstance(node, list):
        for index, item in enumerate(node):
            assert_provenance_complete(item, f"{path}[{index}]")
        return
    if node is None or isinstance(node, (str, int, float, bool)):
        raise ProvenanceError(
            f"Pole '{path}' niesie wartosc skalarna bez znacznika pochodzenia"
        )


@dataclass(frozen=True)
class Evidence:
    """Dowod findingu: numer pakietu i identyfikator sesji, do ktorych da
    sie wrocic w zrzucie. Celowo bez pola na surowe bajty ani tresc
    ladunku (CHECK-06, zagrozenie T-2-06)."""

    packet_number: int
    session_id: int


@dataclass(frozen=True)
class StandardRef:
    standard: str
    edition: str
    clause: str
    clause_title: str
    paraphrase: str
    verified: bool
    verification_note: str


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    risk: str
    rationale: str
    standard_refs: tuple[StandardRef, ...]
    evidence: Evidence
    remediation: str


def build_analysis(
    *,
    capture: dict,
    conversations: list[dict],
    protocol_events: list[dict],
    zone_model: dict,
    findings: list[dict],
    methodology: dict,
    assets: list[dict],
    coverage: dict,
    low_confidence_events: list[dict],
    comm_matrix: list[dict],
) -> dict:
    """Skleja slownik `analysis.json`.

    Zgodnie z D-02 nie dolacza zadnego pola ze znacznikiem czasu
    wygenerowania analizy - `capture` niesie wylacznie okno czasowe
    wyprowadzone z `pkt.time`, przekazane juz gotowe przez wywolujacego.
    `coverage` niesie ocene pokrycia okna zrzutu wobec zmierzonego odstepu
    odpytywania (INGEST-04), zbudowana przez `wayside.coverage`.
    `low_confidence_events` niesie zdarzenia rozpoznane dyskryminatorem
    sumy kontrolnej `wayside.protocols.modbus_rtu_tunnel.detect_all` -
    klucz istnieje ZAWSZE, takze przy pustej liscie, i jest strukturalnie
    ODDZIELONY od `protocol_events`: silnik checkow czyta wylacznie
    `protocol_events`, wiec rozpoznanie o niskiej pewnosci nigdy nie moze
    stac sie podstawa findingu przez sam fakt obecnosci na wspolnej liscie
    (zalozenie Z-18, PROTO-03).
    `comm_matrix` niesie macierz komunikacji zbudowana przez
    `wayside.flow.build_comm_matrix` - jeden wiersz na sesje z ladunkiem,
    razem z sesjami, ktorych protokolu nie rozpoznano (FLOW-01).
    """
    return {
        "capture": capture,
        "conversations": conversations,
        "protocol_events": protocol_events,
        "zones": zone_model["zones"],
        "conduits": zone_model["conduits"],
        "findings": findings,
        "methodology": methodology,
        "assets": assets,
        "coverage": coverage,
        "low_confidence_events": low_confidence_events,
        "comm_matrix": comm_matrix,
    }


def dump_deterministic(data: dict) -> str:
    """Serializuje deterministycznie: klucze posortowane, separatory bez
    bialych znakow, polskie znaki wprost w UTF-8 (nie escapowane)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_atomic(path: Path, text: str) -> None:
    """Zapisuje `text` do `path` przez plik tymczasowy w tym samym katalogu
    docelowym i `os.replace` - przerwany albo rownolegly przebieg nie
    zostawia pliku czesciowo zapisanego. Jawny `newline="\\n"` zdejmuje
    tlumaczenie konca linii na Windows."""
    path = Path(path)
    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp_path_str, path)
    except BaseException:
        try:
            os.remove(tmp_path_str)
        except OSError:
            pass
        raise
