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
import tempfile
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Evidence",
    "StandardRef",
    "Finding",
    "build_analysis",
    "dump_deterministic",
    "write_atomic",
]


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
) -> dict:
    """Skleja slownik `analysis.json`.

    Zgodnie z D-02 nie dolacza zadnego pola ze znacznikiem czasu
    wygenerowania analizy - `capture` niesie wylacznie okno czasowe
    wyprowadzone z `pkt.time`, przekazane juz gotowe przez wywolujacego.
    """
    return {
        "capture": capture,
        "conversations": conversations,
        "protocol_events": protocol_events,
        "zones": zone_model["zones"],
        "conduits": zone_model["conduits"],
        "findings": findings,
        "methodology": methodology,
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
