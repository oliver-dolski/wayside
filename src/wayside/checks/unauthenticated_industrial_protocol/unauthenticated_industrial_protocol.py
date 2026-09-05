"""Evaluator checka `unauthenticated-industrial-protocol` (CHECK-05).

Cztery rzeczy, ktore ten modul robi wprost:

1. Czyta WYLACZNIE zserializowany model (`analysis["protocol_events"]`),
   nigdy pakietow, zadnego modulu dekodowania ani zadnego modulu
   dissectora - checki widza wylacznie model, nigdy wewnetrzne szczegoly
   dekodowania (02-RESEARCH.md, Anti-Pattern 1).
2. Emituje jeden finding na SESJE, nie na zdarzenie (zalozenie Z-57):
   sesja z jednym zapisem i dziesiecioma odczytami dalaby jedenascie
   identycznych findingow, czyli szum, ktory badanie fazy nazywa wprost
   w sekcji Anti-Patterns.
3. NIE filtruje po klasyfikacji zdarzenia (`kind`) - warunkiem jest sama
   OBECNOSC ruchu protokolu z listy `UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS`,
   nie rodzaj operacji. To jest cala roznica wobec checka za zapis
   (`modbus-unauthenticated-write`): tamten check odpala sie na operacji
   zapisu, ten check odpala sie na samym uzyciu protokolu, niezaleznie od
   tego, czy w danej sesji doszlo do zapisu (04-RESEARCH.md, Pitfall 9).
4. Zbior protokolow objetych checkiem zyje TUTAJ, a nie w manifescie
   dissectora (zalozenie Z-60) - rozpoznanie protokolu i ocena jego
   wlasnosci sa dwiema odpowiedzialnosciami.
"""

from __future__ import annotations

__all__ = ["evaluate", "UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS"]

# Kryterium przynaleznosci: protokol przemyslowy, ktory nie ma w swojej
# specyfikacji zadnego mechanizmu uwierzytelnienia nadawcy. To jest to, co
# przyszly protokol ma spelnic, zeby tu wejsc - bez zapisania tego kryterium
# stala staje sie lista bez reguly.
UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS: frozenset[str] = frozenset({"modbus-tcp"})


def evaluate(analysis: dict) -> list[dict]:
    """Dla kazdej sesji niosacej co najmniej jedno zdarzenie protokolu z
    `UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS` zapamietuje PIERWSZE napotkane
    zdarzenie tej sesji w kolejnosci wejscia (zalozenie Z-58) i zwraca dla
    niej jeden finding z dowodem (numer pakietu, identyfikator sesji) tego
    pierwszego zdarzenia.

    Indeksowanie `analysis["protocol_events"]` jest CELOWO wymagajace: model
    bez tego klucza jest modelem o niepoprawnym ksztalcie, a `KeyError`
    jawnie to sygnalizuje, zamiast cicho zwrocic liste pusta, ktora
    wygladalaby jak legalny brak zdarzen.

    Slownik plus osobna lista kolejnosci, nigdy zbior na sciezce do
    serializacji (wzorzec wspolny tego repozytorium od Fazy 3) - kolejnosc
    wynikow wchodzi do artefaktu, a zbior jej nie ma."""
    first_seen: dict[int, dict] = {}
    order: list[int] = []

    for event in analysis["protocol_events"]:
        protocol = event.get("protocol")
        if protocol not in UNAUTHENTICATED_INDUSTRIAL_PROTOCOLS:
            continue
        session_id = event["session_id"]
        if session_id in first_seen:
            continue
        first_seen[session_id] = event
        order.append(session_id)

    results: list[dict] = []
    for session_id in order:
        event = first_seen[session_id]
        results.append(
            {
                "evidence": {
                    "packet_number": event["packet_number"],
                    "session_id": event["session_id"],
                }
            }
        )
    return results
