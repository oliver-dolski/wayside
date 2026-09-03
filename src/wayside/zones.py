"""Model strefy i kanalu (STD-06): placeholder jednostrefowy, wypelniany
automatycznie ze zrzutu, z jawnym znacznikiem `provisional`.

D-03: jedna strefa domyslna obejmujaca wszystkie zaobserwowane adresy tego
zrzutu, plus JEDEN kanal wyprowadzony z zaobserwowanego ruchu - decyzja
uzytkownika wygrywa z wczesniejszym szkicem badania (ktory proponowal zero
kanalow modelowanych).
"""

from __future__ import annotations

__all__ = ["DEFAULT_ZONE_ID", "DEFAULT_CONDUIT_ID", "build_zone_model"]

DEFAULT_ZONE_ID = "z-default"
DEFAULT_CONDUIT_ID = "c-default"


def build_zone_model(*, observed_ips: list[str], observed_protocols: list[str]) -> dict:
    """Buduje model strefy/kanalu: jedna strefa, jeden kanal, oba
    prowizoryczne. Kazda kolekcja jest jawnie posortowana (nigdy `set()`
    bezposrednio do serializacji - 02-RESEARCH.md, Pitfall 5)."""
    zone = {
        "id": DEFAULT_ZONE_ID,
        "name": "Strefa domyslna (niezroznicowana, prowizoryczna)",
        "members": sorted(set(observed_ips)),
        "provisional": True,
        "note": (
            "Wypelniona automatycznie ze zrzutu, bez pelnej topologii sieci - "
            "pelny podzial na strefy nalezy do Fazy 3 (macierz komunikacji)."
        ),
    }
    conduit = {
        "id": DEFAULT_CONDUIT_ID,
        "zones": [DEFAULT_ZONE_ID],
        "protocols": sorted(set(observed_protocols)),
        "provisional": True,
        "note": (
            "Kanal wyprowadzony z zaobserwowanego ruchu tego zrzutu, nie z "
            "zaprojektowanej segmentacji sieci."
        ),
    }
    return {"zones": [zone], "conduits": [conduit]}
