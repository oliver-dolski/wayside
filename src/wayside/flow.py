"""Macierz komunikacji: kto z kim rozmawia, w ktora strone, jakim protokolem
i ile tego bylo (FLOW-01, FLOW-02, FLOW-03).

Co ta macierz pokazuje: sesje TCP, ktore dotarly do punktu przechwytywania
i mialy co najmniej jeden segment z ladunkiem (zalozenie Z-31). Sesje zlozone
wylacznie z pakietow bez ladunku sa POLICZONE i nazwane w sekcji ograniczen
raportu, a nie dopisane tutaj: identyfikatory sesji pochodza z
`decode.decode_segments` i sa wspolne dla `conversations`, `protocol_events`
i tej macierzy, wiec wiersz spoza tamtej numeracji rozjechalby przestrzen
identyfikatorow miedzy sekcjami modelu.

Czego ta macierz NIE pokazuje: obrazu sieci. Nieobecnosc rozmowy w tej tabeli
nie jest dowodem, ze rozmowa nie miala miejsca - jest dowodem, ze nie dotarla
do tego punktu podsluchu. Zdania z `VANTAGE_POINT_LIMITATIONS` stoja w raporcie
po to, zeby czytelnik nie musial sam na to wpasc.

Sesja, ktorej protokolu nie rozpoznano, MA wiersz z etykieta `tcp`. Znikniecie
takiego wiersza bylo by klamstwem przez pominiecie, a to jest ta czesc raportu,
w ktorej takie klamstwo kosztuje najwiecej: czytelnik buduje z niej obraz sieci.
"""

from __future__ import annotations

import dataclasses

import wayside.pcap  # noqa: F401  - izolacja cache scapy PRZED importem warstw

from scapy.layers.inet import IP, TCP  # noqa: E402

from wayside.decode import (  # noqa: E402
    Segment,
    SessionInitiator,
    _canonical_session_key,
)
from wayside.model import inferred, not_derivable, observed  # noqa: E402

__all__ = [
    "PROTOCOL_MODBUS_TCP",
    "PROTOCOL_MODBUS_RTU_TUNNEL",
    "PROTOCOL_UNRECOGNIZED",
    "PROTOCOL_LABELS",
    "COMPLETENESS_CLAIM_TERMS",
    "VANTAGE_POINT_LIMITATIONS",
    "build_comm_matrix",
    "vantage_point_limitations",
]

PROTOCOL_MODBUS_TCP = "modbus-tcp"
PROTOCOL_MODBUS_RTU_TUNNEL = "modbus-rtu-over-tcp"
PROTOCOL_UNRECOGNIZED = "tcp"

# Zamkniety zbior etykiet protokolu, na wzor `ROLE_LABELS` z planu 03-06.
# Kolejnosc jest kolejnoscia rozstrzygania i NIE jest przemienna: sesja z ruchem
# rozpoznanym po naglowku MBAP jest Modbusem po TCP, nawet gdy niesie w tle
# segment przypadkiem dopasowany suma kontrolna.
PROTOCOL_LABELS: tuple[str, ...] = (
    PROTOCOL_MODBUS_TCP,
    PROTOCOL_MODBUS_RTU_TUNNEL,
    PROTOCOL_UNRECOGNIZED,
)

PROVENANCE_METHOD_PAYLOAD_SHAPE = "payload-shape"
PROVENANCE_METHOD_FIRST_SENDER = "first-observed-sender"

# Lancuchy sugerujace zupelnosc obrazu sieci - DANE TESTOWE dla bramki
# maszynowej FLOW-03, w tym samym stylu co `FORBIDDEN_ROLE_LABELS`
# w `assets/inventory.py`. Zyja w kodzie produkcyjnym, zeby bramka i tekst
# raportu mialy jedno zrodlo prawdy.
COMPLETENESS_CLAIM_TERMS: tuple[str, ...] = (
    "kompletn",
    "wszystkie urzadzenia",
    "wszystkich urzadzen",
    "wszystkie hosty",
    "wszystkich hostow",
    "pelna lista",
    "pelny inwentarz",
    "pelny obraz",
    "cala siec",
    "calej sieci",
    "complete list",
    "full picture",
    "all devices",
)

# Stale zdania nazywajace martwe pole widzenia pasywnej obserwacji. Sa stalymi,
# a nie tekstem sklejanym w warstwie renderowania, bo to jest tresc, ktora ma
# brzmiec identycznie w kazdym raporcie i ktorej nie wolno zgubic przy edycji
# szablonu.
VANTAGE_POINT_LIMITATIONS: tuple[str, ...] = (
    "Ten raport opisuje wylacznie ruch, ktory dotarl do punktu przechwytywania. "
    "Urzadzenie nieobecne w wyniku nie jest urzadzeniem nieobecnym w sieci - jest "
    "urzadzeniem, ktorego ruch tego punktu nie minal.",
    "Urzadzenie stojace za brama protokolu jest widoczne wylacznie pod adresem tej "
    "bramy. Adres sieciowy w tym raporcie moze wiec odpowiadac wiecej niz jednemu "
    "urzadzeniu fizycznemu.",
    "Wiele hostow ukrytych za jednym adresem po translacji adresow jest z tego "
    "punktu nieodroznialnych. Jeden wiersz inwentarza moze odpowiadac wiecej niz "
    "jednemu urzadzeniu.",
)


def _endpoint(ip: str, port: int) -> str:
    return f"{ip}:{port}"


def _observed_endpoint(value: str):
    return observed(value)


def _inferred_endpoint(value: str):
    return inferred(value, PROVENANCE_METHOD_FIRST_SENDER)


def _wire_length(pkt) -> int:
    """Dlugosc pakietu na drucie (zalozenie Z-34).

    `wirelen` ustawia czytelnik scapy przy odczycie zrzutu. Atrybut nieobecny
    (np. pakiet zbudowany w pamieci, nie odczytany z pliku) zastepuje dlugosc
    bajtow pakietu - jawna droga zapasowa, nie cicha wartosc zero. Zero dalo by
    wolumen zerowy dla calej sesji, czyli PEWNA, BLEDNA liczbe w raporcie, a to
    jest najgorszy tryb porazki w tym projekcie.
    """
    wirelen = getattr(pkt, "wirelen", None)
    if wirelen is None:
        return len(bytes(pkt))
    return int(wirelen)


def build_comm_matrix(
    *,
    packets,
    segments: list[Segment],
    events: list[dict],
    low_confidence_events: list[dict],
    initiators: dict[int, SessionInitiator],
) -> list[dict]:
    """Buduje macierz komunikacji, jeden wiersz na sesje z ladunkiem.

    Kolejnosc wierszy jest kolejnoscia pierwszego napotkania sesji w pliku -
    `dict` plus osobna lista `order`, nigdy `set` na sciezce do serializacji
    (`03-PATTERNS.md`, Shared Patterns).

    KAZDE pole wiersza przechodzi przez `dataclasses.asdict` na `ObservedField`,
    wlacznie z identyfikatorem sesji. Jednolitosc jest tu warta jednego
    dodatkowego opakowania: bramka prowieniencji chodzi wtedy po calej sekcji
    bez wyjatkow, a wyjatek jest tym, o czym sie zapomina.
    """
    rows: dict[int, dict[str, object]] = {}
    order: list[int] = []
    first_sender: dict[int, tuple[str, str]] = {}
    session_by_key: dict[str, int] = {}
    packet_counts: dict[int, int] = {}
    volume_bytes: dict[int, int] = {}

    # Przebieg pierwszy: sesje i pierwszy nadawca ladunku.
    for segment in segments:
        key = _canonical_session_key(
            segment.src_ip, segment.src_port, segment.dst_ip, segment.dst_port
        )
        session_by_key.setdefault(key, segment.session_id)
        if segment.session_id in first_sender:
            continue
        order.append(segment.session_id)
        first_sender[segment.session_id] = (
            _endpoint(segment.src_ip, segment.src_port),
            _endpoint(segment.dst_ip, segment.dst_port),
        )
        packet_counts[segment.session_id] = 0
        volume_bytes[segment.session_id] = 0

    # Przebieg drugi: liczba pakietow i wolumen na drucie, po WSZYSTKICH
    # pakietach sesji, nie po samych segmentach z ladunkiem (zalozenie Z-33).
    # Pakiet o kluczu nieobecnym w odwzorowaniu nalezy do sesji bez ladunku,
    # policzonej osobno w sekcji ograniczen.
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        key = _canonical_session_key(
            str(ip_layer.src), int(tcp_layer.sport), str(ip_layer.dst), int(tcp_layer.dport)
        )
        session_id = session_by_key.get(key)
        if session_id is None:
            continue
        packet_counts[session_id] += 1
        volume_bytes[session_id] += _wire_length(pkt)

    modbus_sessions = {event["session_id"] for event in events}
    rtu_sessions = {event["session_id"] for event in low_confidence_events}

    for session_id in order:
        source_value, target_value = first_sender[session_id]
        initiator = initiators.get(session_id)
        if initiator is not None:
            initiator_endpoint = _endpoint(initiator.ip, initiator.port)
            # Strona inicjujaca jest znana, wiec zrodlo i cel wiersza sa
            # OBSERWACJA, a nie wnioskiem z tego, kto pierwszy wyslal ladunek.
            other = target_value if source_value == initiator_endpoint else source_value
            source_value, target_value = initiator_endpoint, other
            initiator_field = observed(initiator_endpoint)
            endpoint_field = _observed_endpoint
        else:
            # Zalozenie Z-30: inicjator NIEUSTALONY, a kierunek wniosek
            # oznaczony jako wniosek. Pierwszy nadawca ladunku nie jest
            # zamiennikiem strony inicjujacej.
            initiator_field = not_derivable()
            endpoint_field = _inferred_endpoint

        if session_id in modbus_sessions:
            protocol_field = inferred(PROTOCOL_MODBUS_TCP, PROVENANCE_METHOD_PAYLOAD_SHAPE)
        elif session_id in rtu_sessions:
            protocol_field = inferred(
                PROTOCOL_MODBUS_RTU_TUNNEL, PROVENANCE_METHOD_PAYLOAD_SHAPE
            )
        else:
            # To, ze widziano TCP, jest obserwacja - nierozpoznanie protokolu
            # aplikacyjnego nie czyni z niej wniosku.
            protocol_field = observed(PROTOCOL_UNRECOGNIZED)

        rows[session_id] = {
            "session_id": observed(session_id),
            "source": endpoint_field(source_value),
            "target": endpoint_field(target_value),
            "direction": endpoint_field(f"{source_value} -> {target_value}"),
            "initiator": initiator_field,
            "protocol": protocol_field,
            "volume_bytes": observed(volume_bytes[session_id]),
            "packet_count": observed(packet_counts[session_id]),
        }

    return [
        {name: dataclasses.asdict(field) for name, field in rows[session_id].items()}
        for session_id in order
    ]


def vantage_point_limitations(
    *,
    host_count: int,
    session_count: int,
    payloadless_session_count: int,
    window_duration_s: float | None,
) -> list[str]:
    """Zdania o martwym polu widzenia: stale plus jedno zdanie z liczbami
    TEGO przebiegu.

    Sama formula ogolna jest tania i dlatego bezwartosciowa - czytelnik czyta
    ja jako zastrzezenie prawne i pomija. Zdanie podajace, ile adresow, ile
    sesji i jak dlugie okno faktycznie widziano, wiaze ograniczenie z tym
    konkretnym zrzutem (FLOW-03).
    """
    if window_duration_s is None:
        window_sentence = "okno czasowe zrzutu nie zostalo ustalone"
    else:
        window_sentence = f"okno czasowe zrzutu ma dlugosc {window_duration_s} s"

    # Zdanie z liczbami stoi PIERWSZE, przed zdaniami stalymi: formula ogolna
    # czytana jako pierwsza jest odbierana jako zastrzezenie prawne i pomijana,
    # a liczby z tego przebiegu wiaza ograniczenie z tym konkretnym zrzutem.
    lines = [
        f"Zakres tego przebiegu: adresow zaobserwowanych {host_count}, sesji "
        f"z ladunkiem {session_count}, sesji bez ani jednego segmentu z ladunkiem "
        f"{payloadless_session_count}, {window_sentence}."
    ]
    lines.extend(VANTAGE_POINT_LIMITATIONS)

    if payloadless_session_count:
        lines.append(
            f"Sesji TCP zlozonych wylacznie z pakietow bez ladunku: "
            f"{payloadless_session_count}. Nie maja wiersza w macierzy komunikacji, "
            "bo nie niosa ani jednego segmentu do rozpoznania - sa policzone tutaj, "
            "zeby nie zniknely bez sladu."
        )

    return lines
