"""Zone and conduit model (STD-06): a single-zone placeholder, populated
automatically from the capture, with an explicit `provisional` marker.

D-03: one default zone covering every address observed in this capture,
plus ONE conduit derived from the observed traffic - the user's decision
wins over the earlier research sketch (which proposed zero modelled
conduits).
"""

from __future__ import annotations

__all__ = ["DEFAULT_ZONE_ID", "DEFAULT_CONDUIT_ID", "build_zone_model"]

DEFAULT_ZONE_ID = "z-default"
DEFAULT_CONDUIT_ID = "c-default"


def build_zone_model(*, observed_ips: list[str], observed_protocols: list[str]) -> dict:
    """Builds the zone/conduit model: one zone, one conduit, both
    provisional. Every collection is sorted explicitly (never a `set()`
    straight into serialisation - 02-RESEARCH.md, Pitfall 5)."""
    zone = {
        "id": DEFAULT_ZONE_ID,
        "name": "Default zone (undifferentiated, provisional)",
        "members": sorted(set(observed_ips)),
        "provisional": True,
        "note": (
            "Populated automatically from the capture, without a full network "
            "topology - a full division into zones belongs to Phase 3 (the "
            "communication matrix)."
        ),
    }
    conduit = {
        "id": DEFAULT_CONDUIT_ID,
        "zones": [DEFAULT_ZONE_ID],
        "protocols": sorted(set(observed_protocols)),
        "provisional": True,
        "note": (
            "A conduit derived from the traffic observed in this capture, not "
            "from a designed network segmentation."
        ),
    }
    return {"zones": [zone], "conduits": [conduit]}
