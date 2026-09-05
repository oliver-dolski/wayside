"""Adapter miedzy rejestrem dissectorow i warstwa Modbus/TCP.

Logika rozpoznania zyje w `wayside.protocols.modbus_tcp` - ten plik dowozi
wylacznie serializacje wyniku do slownikow, bo rejestr nie zna zadnej
dataclassy protokolu. Zero innej logiki: kazde rozstrzygniecie o rozpoznaniu
zostaje w warstwie protokolu, wiec `tests/test_modbus_tcp.py` zostaje bez
zmiany i nadal pilnuje tego, co pilnowal.
"""

from __future__ import annotations

import dataclasses

from wayside.decode import Segment
from wayside.protocols import modbus_tcp

__all__ = ["dissect"]


def dissect(segments: list[Segment]) -> list[dict]:
    return [dataclasses.asdict(event) for event in modbus_tcp.dissect_all(segments)]
