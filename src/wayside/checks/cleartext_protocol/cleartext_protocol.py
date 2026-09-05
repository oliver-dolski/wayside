"""Evaluator checka `cleartext-protocol` (CHECK-03).

Czyta WYLACZNIE `analysis["protocol_events"]`, nigdy pakietow, zadnego
modulu dekodowania ani zadnego modulu dissectora - checki widza wylacznie
model, nigdy wewnetrzne szczegoly dekodowania (02-RESEARCH.md,
Anti-Pattern 1). Czysta funkcja, zero I/O, zero stanu wspoldzielonego
miedzy wywolaniami.

Emituje jeden finding na pare identyfikator sesji plus identyfikator
protokolu jawnotekstowy (zalozenie Z-47), nigdy jeden finding na zdarzenie:
pojedyncza sesja HTTP niesie dziesiatki zdarzen tego samego protokolu, a
finding na kazde z nich bylby szumem zamiast sygnalem.
"""

from __future__ import annotations

__all__ = ["evaluate", "CLEARTEXT_PROTOCOLS"]

CLEARTEXT_PROTOCOLS = frozenset({"telnet", "ftp", "http"})


def evaluate(analysis: dict) -> list[dict]:
    """Dla kazdej pary (identyfikator sesji, identyfikator protokolu
    jawnotekstowy) zapamietuje PIERWSZE napotkane zdarzenie w kolejnosci
    wejscia i zwraca dla niej jeden finding z dowodem (numer pakietu,
    identyfikator sesji) tego pierwszego zdarzenia.

    Indeksowanie `analysis["protocol_events"]` jest CELOWO wymagajace: model
    bez tego klucza jest modelem o niepoprawnym ksztalcie, a `KeyError`
    jawnie to sygnalizuje, zamiast cicho zwrocic liste pusta, ktora
    wygladalaby jak legalny brak zdarzen.

    Slownik plus osobna lista kolejnosci, nigdy zbior na sciezce do
    serializacji (wzorzec wspolny tego repozytorium od Fazy 3) - kolejnosc
    wynikow wchodzi do artefaktu, a zbior jej nie ma."""
    first_seen: dict[tuple[int, str], dict] = {}
    order: list[tuple[int, str]] = []

    for event in analysis["protocol_events"]:
        protocol = event.get("protocol")
        if protocol not in CLEARTEXT_PROTOCOLS:
            continue
        key = (event["session_id"], protocol)
        if key in first_seen:
            continue
        first_seen[key] = event
        order.append(key)

    results: list[dict] = []
    for key in order:
        event = first_seen[key]
        results.append(
            {
                "evidence": {
                    "packet_number": event["packet_number"],
                    "session_id": event["session_id"],
                }
            }
        )
    return results
