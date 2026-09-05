"""Adapter miedzy rejestrem dissectorow i dyskryminatorem RTU po TCP.

Logika rozpoznania zyje w `wayside.protocols.modbus_rtu_tunnel` - ten plik
dowozi wylacznie serializacje wyniku do slownikow, bo rejestr nie zna zadnej
dataclassy protokolu. Zero innej logiki: kazde rozstrzygniecie o rozpoznaniu
zostaje w warstwie protokolu, wiec `tests/test_modbus_rtu_tunnel.py` zostaje
bez zmiany i nadal pilnuje tego, co pilnowal.
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
