"""Rubryka wagi: czysta funkcja bez stanu i bez I/O (RISK-03).

Kryteria z `RUBRIC_CRITERIA` sa renderowane w sekcji metodyki raportu, zeby
byly udokumentowane w produkcie, nie tylko w kodzie. Ta rubryka NIE liczy
zadnego zbiorczego wskaznika i NIE przypisuje liczbowego Security Level.
"""

from __future__ import annotations

__all__ = [
    "ALLOWED_SEVERITIES",
    "SEVERITY_TO_RISK",
    "RUBRIC_CRITERIA",
    "RUBRIC_VERSION",
    "severity_to_risk",
]

ALLOWED_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

SEVERITY_TO_RISK: dict[str, str] = {
    "low": "niskie",
    "medium": "srednie",
    "high": "wysokie",
    "critical": "krytyczne",
}

RUBRIC_VERSION = "1.0"

RUBRIC_CRITERIA: dict[str, str] = {
    "low": (
        "Obserwacja o niewielkim wplywie na bezpieczenstwo, bez bezposredniej "
        "sciezki do zaklocenia dzialania procesu."
    ),
    "medium": (
        "Odstepstwo od dobrej praktyki, ktore w polaczeniu z innym warunkiem "
        "moze prowadzic do zaklocenia dzialania procesu."
    ),
    "high": (
        "Operacja, ktora sama w sobie pozwala wplynac na stan procesu bez "
        "uwierzytelnienia ani autoryzacji nadawcy."
    ),
    "critical": (
        "Warunek umozliwiajacy natychmiastowa i bezposrednia ingerencje w "
        "bezpieczenstwo procesu, bez zadnych dodatkowych warunkow."
    ),
}


def severity_to_risk(severity: str) -> str:
    """Zwraca ryzyko dla wagi. Podnosi `ValueError` na wadze poza
    `ALLOWED_SEVERITIES`, nigdy nie zwraca wagi domyslnej."""
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(
            f"Nieznana waga findingu: {severity!r}. Dozwolone: {ALLOWED_SEVERITIES}."
        )
    return SEVERITY_TO_RISK[severity]
