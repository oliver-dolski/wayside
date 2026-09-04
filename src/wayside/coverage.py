"""Ocena pokrycia okna zrzutu wobec zmierzonego odstepu odpytywania Modbus
(INGEST-04): czysta funkcja bez stanu i bez wejscia-wyjscia, stylem jak
`src/wayside/risk.py`.

Kryterium 1 fazy 3 z `ROADMAP.md` mowi doslownie o zrzucie "krotszym niz
zaobserwowany cykl odpytywania". Wziete doslownie jest to warunek, ktory
nigdy nie jest prawdziwy: okno zrzutu z definicji obejmuje kazdy odstep
zmierzony wewnatrz niego, wiec nigdy nie jest od niego krotsze. Implementacja
doslowna dawalaby warunek martwy i test, ktory nigdy nie zapala sie na
zadnych danych.

Operacjonalizacja przyjeta w tym module: ostrzezenie zapala sie, gdy okno
zrzutu jest krotsze niz `POLL_CYCLE_WINDOW_MULTIPLIER` razy najdluzszy
zmierzony odstep miedzy kolejnymi zadaniami w tej samej sesji. Wartosc
mnoznika zostala wybrana na checkpoincie decyzyjnym Task 2 planu
03-03-PLAN.md (2026-09-04, rozstrzygniecie czlowieka: opcja `mnoznik-2`,
wartosc 2.0) - dwa powtorzenia sa najmniejsza obserwacja, ktora odroznia
cykl od zbiegu okolicznosci, a nizszy prog rzadziej zapala ostrzezenie na
zrzutach, ktore realnie wystarczaja.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

__all__ = [
    "POLL_CYCLE_WINDOW_MULTIPLIER",
    "MIN_REQUESTS_FOR_CYCLE",
    "PollingCycle",
    "measure_polling_cycles",
    "coverage_warnings",
    "build_coverage_section",
]

# Prog operacyjny wybrany na checkpoincie decyzyjnym Task 2, 03-03-PLAN.md.
POLL_CYCLE_WINDOW_MULTIPLIER: float = 2.0

# Jeden punkt nie wyznacza odstepu.
MIN_REQUESTS_FOR_CYCLE: int = 2


@dataclass(frozen=True)
class PollingCycle:
    """Zmierzony odstep miedzy kolejnymi zadaniami Modbus w jednej sesji.

    `measured_cycle_s` jest OBSERWACJA z tego zrzutu, nie deklarowanym
    okresem odpytywania urzadzenia - pojedynczy zmierzony odstep nigdy nie
    jest prezentowany jako potwierdzony cykl odpytywania.
    """

    session_id: int
    measured_cycle_s: float
    request_count: int


def measure_polling_cycles(events: list[dict]) -> list[PollingCycle]:
    """Mierzy najdluzszy odstep miedzy kolejnymi zadaniami w kazdej sesji.

    Przyjmuje `events` w ksztalcie `analysis["protocol_events"]`. Zdarzenia
    o kierunku innym niz `request` sa ignorowane. Grupowanie idzie po
    `session_id` w `dict`, nigdy w `set` - determinizm kolejnosci pliku jest
    tu kontraktem odziedziczonym z Fazy 2. Sesje o mniej niz
    `MIN_REQUESTS_FOR_CYCLE` zadaniach sa pomijane bez wpisu: jeden punkt nie
    wyznacza odstepu, a zgadywanie odstepu z jednego zdarzenia bylby
    wymyslona liczba. Zwracana lista jest uporzadkowana rosnaco po
    identyfikatorze sesji.
    """
    sessions: dict[int, list[float]] = {}
    for event in events:
        if event.get("direction") != "request":
            continue
        session_id = event["session_id"]
        sessions.setdefault(session_id, []).append(event["timestamp"])

    cycles: list[PollingCycle] = []
    for session_id in sorted(sessions):
        timestamps = sessions[session_id]
        if len(timestamps) < MIN_REQUESTS_FOR_CYCLE:
            continue
        # Odstepy miedzy kolejnymi znacznikami czasu W KOLEJNOSCI PLIKU
        # (nie posortowanymi wartosciami) - najdluzszy z nich jest wartoscia
        # najostrozniejsza (zalozenie Z-15 z 03-03-PLAN.md).
        longest = max(
            second - first for first, second in zip(timestamps, timestamps[1:])
        )
        cycles.append(
            PollingCycle(
                session_id=session_id,
                measured_cycle_s=round(longest, 6),
                request_count=len(timestamps),
            )
        )
    return cycles


def coverage_warnings(
    *, cycles: list[PollingCycle], window_duration_s: float | None
) -> list[str]:
    """Buduje ostrzezenia o oknie zrzutu zbyt krotkim wobec zmierzonego
    odstepu odpytywania.

    Okno rowne `None` (zrzut bez pakietow) daje pusta liste - nie ma
    czego mierzyc. Zmierzony odstep rowny zero daje pusta liste dla tej
    sesji: warunek progowy przy zerze jest trywialnie falszywy, a wpisanie
    tam dzielenia byloby dzieleniem przez zero. Dla kazdej pozostalej sesji
    warunek jest OSTRY - ostrzezenie powstaje, gdy okno jest MNIEJSZE niz
    `POLL_CYCLE_WINDOW_MULTIPLIER` razy zmierzony odstep; rownosc nie
    zapala ostrzezenia.
    """
    if window_duration_s is None:
        return []

    warnings: list[str] = []
    for cycle in cycles:
        if cycle.measured_cycle_s == 0:
            continue
        threshold = POLL_CYCLE_WINDOW_MULTIPLIER * cycle.measured_cycle_s
        if window_duration_s >= threshold:
            continue
        warnings.append(
            f"Okno zrzutu trwa {window_duration_s} sekundy, sesja "
            f"{cycle.session_id} niesie najdluzszy zmierzony odstep miedzy "
            f"kolejnymi zadaniami rowny {cycle.measured_cycle_s} sekundy "
            f"wobec przyjetego progu (mnoznik {POLL_CYCLE_WINDOW_MULTIPLIER}). "
            "Zaobserwowana wartosc jest pojedynczym odstepem miedzy "
            "zadaniami w tej sesji, nie potwierdzonym cyklem odpytywania."
        )
    return warnings


def build_coverage_section(
    *, cycles: list[PollingCycle], window_duration_s: float | None
) -> dict:
    """Skleja sekcje `coverage` slownika `analysis.json`."""
    return {
        "window_duration_s": (
            round(window_duration_s, 6) if window_duration_s is not None else None
        ),
        "window_multiplier_threshold": POLL_CYCLE_WINDOW_MULTIPLIER,
        "polling_cycles": [dataclasses.asdict(cycle) for cycle in cycles],
    }
