"""Evaluator checka `modbus-unauthenticated-write` (CHECK-04).

Czyta WYLACZNIE `analysis["protocol_events"]`, nigdy pakietow ani pliku
pcap - checki widza wylacznie model, nigdy wewnetrzne szczegoly dekodowania
(02-RESEARCH.md, Anti-Pattern 1). Czysta funkcja, zero I/O.
"""

from __future__ import annotations

__all__ = ["evaluate"]


def evaluate(analysis: dict) -> list[dict]:
    """Wybiera zdarzenia zapisu-zadania i zwraca dla kazdego finding z
    dowodem (numer pakietu, identyfikator sesji). Metadane checka (tytul,
    waga, uzasadnienie, powolanie na norme, zalecenie) sa dolaczane przez
    silnik z pliku YAML, nie duplikowane tutaj.

    Indeksowanie `analysis["protocol_events"]` jest CELOWO wymagajace: model
    bez tego klucza jest modelem o niepoprawnym ksztalcie, a `KeyError`
    jawnie to sygnalizuje, zamiast cicho zwrocic liste pusta, ktora
    wygladalaby jak legalny brak zdarzen."""
    results: list[dict] = []
    for event in analysis["protocol_events"]:
        if event.get("kind") == "write" and event.get("direction") == "request":
            results.append(
                {
                    "evidence": {
                        "packet_number": event["packet_number"],
                        "session_id": event["session_id"],
                    }
                }
            )
    return results
