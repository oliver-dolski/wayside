"""An adapter between the dissector registry and the RTU-over-TCP
discriminator.

The recognition logic lives in `wayside.protocols.modbus_rtu_tunnel` - this
file delivers only the serialisation of the result into dictionaries,
because the registry knows no protocol dataclass. No other logic: every
ruling about recognition stays in the protocol layer, so
`tests/test_modbus_rtu_tunnel.py` stays unchanged and still guards what it
guarded.
"""

from __future__ import annotations

import dataclasses

from wayside.decode import Segment
from wayside.protocols import modbus_rtu_tunnel

__all__ = ["dissect"]


def dissect(segments: list[Segment]) -> list[dict]:
    return [
        dataclasses.asdict(event) for event in modbus_rtu_tunnel.detect_all(segments)
    ]
