"""Dekodowanie ramek Ether/IP/TCP oraz rekonstrukcja sesji TCP w kolejnosci pliku.

Ten modul importuje `wayside.pcap` JAKO PIERWSZY, przed jakimkolwiek importem
`scapy.layers.*` - `wayside.pcap` wykonuje przy imporcie izolacje cache scapy
przez `XDG_CACHE_HOME` (patrz `wayside/pcap.py`), a `scapy.main` wylicza
katalog cache tylko raz. Duplikowanie tej logiki w drugim miejscu
zaprzeczyloby jej celowi.

Import `Ether` z `scapy.layers.l2` rejestruje mapowanie DLT_EN10MB -> Ether
w `conf.l2types` jako efekt uboczny samego modulu (`scapy.layers.l2` woala
`conf.l2types.register(...)` przy imporcie) - bez tego `rdpcap` nie
rozpoznaje warstwy Ethernet i zwraca surowe pakiety `Raw`, nawet gdy IP/TCP
sa tez zaimportowane gdzie indziej. `decode_segments` nie odwoluje sie do
klasy `Ether` bezposrednio, ale import musi tu byc, zanim jakikolwiek kod tej
sciezki odczytu wywola `rdpcap`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import wayside.pcap  # noqa: F401  - importowany PIERWSZY, patrz docstring modulu

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.l2 import Ether  # noqa: E402,F401
from scapy.layers.inet import IP, TCP  # noqa: E402

__all__ = ["SESSION_KEY_SEPARATOR", "Segment", "decode_segments"]

SESSION_KEY_SEPARATOR = "<->"


@dataclass(frozen=True)
class Segment:
    """Jeden segment TCP z niepustym ladunkiem, w kolejnosci pliku pcap."""

    packet_number: int
    session_id: int
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


def _canonical_session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """Buduje klucz sesji niezalezny od kierunku ruchu.

    Oba punkty koncowe sa kanonizowane jako `(ip, port)` posortowane
    leksykograficznie, zeby oba kierunki tej samej konwersacji TCP dostaly
    ten sam klucz.
    """
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    low, high = sorted((endpoint_a, endpoint_b))
    return f"{low[0]}:{low[1]}{SESSION_KEY_SEPARATOR}{high[0]}:{high[1]}"


def decode_segments(packets) -> list[Segment]:
    """Dekoduje liste pakietow scapy do listy `Segment`.

    Pomija ramki bez warstwy IP albo TCP oraz ramki z pustym ladunkiem TCP.
    `packet_number` jest 1-bazowym indeksem w `packets` (konwencja pola
    "frame.number" znanego z popularnych analizatorow ruchu), niezaleznie od
    tego, ile segmentow zostalo pominietych. `session_id` jest przypisywany
    sekwencyjnie, w kolejnosci pliku, przy pierwszym napotkaniu kanonicznej
    4-tuple - trzymany w `dict`, nigdy w `set`, bo kolejnosc wstawiania jest
    tu gwarancja determinizmu (02-RESEARCH.md, Pitfall 5).
    """
    segments: list[Segment] = []
    session_ids: dict[str, int] = {}
    next_session_id = 0

    for packet_number, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        tcp_layer = pkt[TCP]
        payload = bytes(tcp_layer.payload)
        if not payload:
            continue

        ip_layer = pkt[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)

        session_key = _canonical_session_key(src_ip, src_port, dst_ip, dst_port)
        if session_key not in session_ids:
            session_ids[session_key] = next_session_id
            next_session_id += 1

        segments.append(
            Segment(
                packet_number=packet_number,
                session_id=session_ids[session_key],
                timestamp=float(pkt.time),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                payload=payload,
            )
        )

    return segments
