"""Budowa inwentarza hostow z segmentow: adres IP i adres MAC, kazde pole
z wlasnym znacznikiem pochodzenia (ASSET-01, ASSET-03).

Ta lista NIE jest lista urzadzen widocznych w sieci - jest lista adresow IP,
ktore pojawily sie w ruchu przechwyconym w tym punkcie podsluchu. Zrzut
pokazuje wylacznie ruch, ktory dotarl do sondy (MUST NOT prezentowac
inwentarza jako kompletnej listy urzadzen w sieci).

Zalozenie Z-03: jeden adres IP niesie co najwyzej jeden adres MAC - pierwszy
zaobserwowany w kolejnosci pliku. Drugi, rozny adres MAC dla tego samego IP
przestawia pole `mac` na `not-derivable-passively`, zamiast wybierac jeden z
dwoch: punkt przechwytywania za routerem widzi adres warstwy drugiej routera,
nie hosta, wiec podanie jednego z dwoch jako `observed` bylby podaniem
cudzego adresu jako adresu hosta.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from wayside.assets.oui import PROVENANCE_METHOD_OUI
from wayside.decode import Segment
from wayside.model import (
    PROVENANCE_NOT_DERIVABLE,
    ObservedField,
    inferred,
    not_derivable,
    observed,
)

__all__ = [
    "ROLE_MODBUS_CLIENT",
    "ROLE_MODBUS_SERVER",
    "ROLE_MODBUS_BOTH",
    "ROLE_UNDETERMINED",
    "ROLE_LABELS",
    "FORBIDDEN_ROLE_LABELS",
    "CONFIDENCE_LEVELS",
    "MIN_EVENTS_FOR_MEDIUM_CONFIDENCE",
    "build_assets",
]

ROLE_MODBUS_CLIENT = "klient Modbus"
ROLE_MODBUS_SERVER = "serwer Modbus"
ROLE_MODBUS_BOTH = "klient i serwer Modbus"
ROLE_UNDETERMINED = "nieustalona"

# Zamkniety zbior etykiet roli, na wzor `ALLOWED_SEVERITIES` w `risk.py`
# (zalozenie Z-26). Wszystkie cztery wartosci sa BEHAWIORALNE: mowia, co adres
# robil w zaobserwowanym ruchu, nie czym urzadzenie jest w procesie. Etykieta
# organizacyjna wymaga wiedzy, ktorej pasywny zrzut nie niesie, a zamkniety
# zbior zamienia te dyscypline z konwencji autora we wlasnosc kodu.
ROLE_LABELS: tuple[str, ...] = (
    ROLE_MODBUS_CLIENT,
    ROLE_MODBUS_SERVER,
    ROLE_MODBUS_BOTH,
    ROLE_UNDETERMINED,
)

# Etykiety organizacyjne, czyli DANE TESTOWE dla bramki maszynowej z planu
# 03-06 Task 3 - w tym samym stylu co `EXTERNAL_DISSECTOR_PATTERNS`
# w `tests/test_no_external_dissector.py`. Zyja w kodzie produkcyjnym po to,
# zeby bramka i implementacja miały jedno zrodlo prawdy zamiast dwoch list,
# ktore rozjada sie przy pierwszej zmianie. Kazda z nich twierdzilaby cos
# o funkcji urzadzenia w procesie - a z kierunku ruchu w jednym oknie tego
# ustalic nie mozna (03-RESEARCH.md, Pitfall 4).
FORBIDDEN_ROLE_LABELS: tuple[str, ...] = (
    "stanowisko operatorskie",
    "stacja inzynierska",
    "stacja inżynierska",
    "historian",
    "system nadzorczy",
    "sterownik programowalny",
    "HMI",
    "engineering workstation",
    "operator workstation",
    "SCADA",
    "PLC",
    "RTU",
    "IED",
)

# Zamkniety zbior poziomow pewnosci roli (zalozenie Z-27). Wartosci `wysoka`
# NIE MA i nie bedzie: ograniczeniem nie jest liczebnosc probki, tylko to, ze
# zaobserwowane okno moze nie obejmowac zachowania odwrotnego - laptop
# inzyniera, ktory przez kwadrans tylko odczytywal, wyglada tak samo przy
# dziesieciu zdarzeniach co przy tysiacu. Trzeci poziom w zbiorze bylby
# zaproszeniem do jego uzycia.
CONFIDENCE_LEVELS: tuple[str, ...] = ("niska", "srednia")

# Prog pewnosci sredniej (zalozenie Z-28). Trzy zdarzenia to najmniejsza
# liczba, przy ktorej kierunek przestaje byc pojedyncza wymiana. Liczba jest
# arbitralna w tym samym stopniu co kazda inna i dlatego stoi jako nazwana
# stala, a nie jako liczba w warunku.
MIN_EVENTS_FOR_MEDIUM_CONFIDENCE = 3

PROVENANCE_METHOD_ROLE = "modbus-traffic-direction"
PROVENANCE_METHOD_ROLE_CONFIDENCE = "event-count-and-direction"


def build_assets(
    *,
    segments: list[Segment],
    events: list[dict] | None = None,
    vendor_lookup: Callable[[str], str | None] | None = None,
) -> list[dict]:
    """Buduje liste hostow w kolejnosci pierwszego zaobserwowania adresu IP
    w pliku. Kazdy wpis ma klucze `ip`, `mac`, `oui_vendor`, `unit_ids`
    i `gateway`, kazda wartosc jest slownikiem o ksztalcie
    `{"value": ..., "provenance": ...}` (wynik `dataclasses.asdict` na
    `ObservedField`).

    `events` jest lista slownikow w ksztalcie `analysis["protocol_events"]`,
    czyli wynikiem `dataclasses.asdict` na `ModbusEvent`. Wartosc `None`
    znaczy tyle co lista pusta - kazdy wywolujacy sprzed tego argumentu
    dziala dalej bez zmiany.

    Regula pol `unit_ids` i `gateway` (ASSET-04, ASSET-05): wartosci Unit ID
    sa zbierane WYLACZNIE pod adresem docelowym zdarzen o kierunku `request`,
    bo Unit ID adresuje urzadzenie logiczne po stronie serwera. Adres bez ani
    jednej takiej wartosci daje `not_derivable()` w obu polach. Adres
    z wartosciami daje `observed(lista posortowana rosnaco)`.

    `vendor_lookup` jest funkcja przyjmujaca adres MAC i zwracajaca nazwe
    producenta albo `None` (zalozenie Z-20). Ten modul NIE importuje
    `wayside.assets.oui.lookup_vendor` ani `load_oui_table` - wywolujacy
    (`wayside.pipeline.analyze`) wstrzykuje gotowa funkcje domknieta nad
    wczytana tabela, wiec ten plik i jego testy pozostaja calkowicie
    niezalezne od tego, czy plik danych lezy w drzewie repozytorium.

    Regula pola `oui_vendor`, w tej kolejnosci: adres MAC hosta nieustalony
    (brak warstwy Ethernet albo niezgodnosc wedlug Z-03) daje
    `not_derivable()` BEZ wolania `vendor_lookup`; `vendor_lookup` rowne
    `None` daje `not_derivable()`; wynik `vendor_lookup` rowny `None` daje
    `not_derivable()`; wynik niepusty daje
    `inferred(nazwa, PROVENANCE_METHOD_OUI)` - producent jest WNIOSKIEM z
    tabeli, nigdy obserwacja z ruchu (zalozenie Z-23).

    Uzywa `dict` plus osobnej listy `order` dla kolejnosci wstawiania -
    nigdy `set` na sciezce do wyniku, bo `model.dump_deterministic` sortuje
    wylacznie klucze slownika, wiec kolejnosc listy jest obowiazkiem
    producenta danych (wzorzec identyczny z `pipeline._build_conversations`).
    """
    hosts: dict[str, dict[str, object]] = {}
    order: list[str] = []
    first_mac: dict[str, str | None] = {}

    # `set` jest tu dopuszczalny WYLACZNIE jako struktura robocza wewnatrz
    # funkcji - do wyniku wchodzi lista posortowana, nigdy kolejnosc iteracji
    # zbioru.
    unit_ids_by_server: dict[str, set[int]] = {}
    # Liczone sa WYLACZNIE zdarzenia o kierunku `request`: odpowiedz jest
    # lustrem zadania, wiec policzenie obu podwoiloby te sama obserwacje.
    requests_sent: dict[str, int] = {}
    requests_received: dict[str, int] = {}
    for event in events or []:
        if event.get("direction") != "request":
            continue
        # `unit_id` jest polem specyficznym dla Modbusa: od Fazy 4 (PROTO-05)
        # `events` niesie takze zdarzenia protokolow jawnotekstowych, ktore
        # tego pola nie maja - `"unit_id" in event`, nigdy `event["unit_id"]`
        # bez warunku, zeby zdarzenie bez tego pola nie podnosilo KeyError.
        if "unit_id" in event:
            unit_ids_by_server.setdefault(event["dst_ip"], set()).add(event["unit_id"])
        requests_sent[event["src_ip"]] = requests_sent.get(event["src_ip"], 0) + 1
        requests_received[event["dst_ip"]] = requests_received.get(event["dst_ip"], 0) + 1

    def _oui_vendor_field(mac: str | None) -> object:
        if mac is None or vendor_lookup is None:
            return not_derivable()
        vendor_name = vendor_lookup(mac)
        if vendor_name is None:
            return not_derivable()
        return inferred(vendor_name, PROVENANCE_METHOD_OUI)

    def _unit_ids_field(ip: str) -> object:
        seen = unit_ids_by_server.get(ip)
        if not seen:
            return not_derivable()
        return observed(sorted(seen))

    def _gateway_field(ip: str) -> object:
        seen = unit_ids_by_server.get(ip)
        if seen is not None and len(seen) > 1:
            return inferred(True, "multiple-unit-ids")
        # Galezi zwracajacej `False` tu nie ma i nie bedzie (zalozenie Z-25):
        # jedna wartosc Unit ID pod adresem jest brakiem dowodu na brame, nie
        # dowodem jej braku - brama z jednym podpietym urzadzeniem wyglada
        # w zrzucie identycznie jak urzadzenie bez bramy.
        return not_derivable()

    def _role_field(sent: int, received: int) -> object:
        if sent > 0 and received > 0:
            return inferred(ROLE_MODBUS_BOTH, PROVENANCE_METHOD_ROLE)
        if sent > 0:
            return inferred(ROLE_MODBUS_CLIENT, PROVENANCE_METHOD_ROLE)
        if received > 0:
            return inferred(ROLE_MODBUS_SERVER, PROVENANCE_METHOD_ROLE)
        # ASSET-07: jedyne pole inwentarza, w ktorym brak wiedzy ma WARTOSC,
        # a nie `null`. Rola nieustalona ma byc widocznym wierszem raportu,
        # bo host pominiety w inwentarzu wyglada jak host, ktorego nie ma,
        # a host z pusta rubryka wyglada jak usterka renderowania. Znacznik
        # pochodzenia niesie ten sam komunikat co wszedzie indziej.
        return ObservedField(value=ROLE_UNDETERMINED, provenance=PROVENANCE_NOT_DERIVABLE)

    def _role_evidence_field(sent: int, received: int) -> object:
        if sent == 0 and received == 0:
            # Zero zaobserwowanych zdarzen jest OBSERWACJA, nie brakiem
            # obserwacji - stad znacznik `observed` takze tutaj.
            return observed(
                "Zero zdarzen Modbus powiazanych z tym adresem w tym zrzucie "
                "(zadania wyslane: 0, zadania odebrane: 0)."
            )
        return observed(
            f"Zadania Modbus wyslane przez ten adres: {sent}; "
            f"zadania Modbus odebrane przez ten adres: {received}."
        )

    def _role_confidence_field(sent: int, received: int) -> object:
        total = sent + received
        directions_seen = (1 if sent > 0 else 0) + (1 if received > 0 else 0)
        if total >= MIN_EVENTS_FOR_MEDIUM_CONFIDENCE and directions_seen == 1:
            return inferred("srednia", PROVENANCE_METHOD_ROLE_CONFIDENCE)
        return inferred("niska", PROVENANCE_METHOD_ROLE_CONFIDENCE)

    def _visit(ip: str, mac: str | None) -> None:
        if ip not in hosts:
            order.append(ip)
            first_mac[ip] = mac
            hosts[ip] = {
                "ip": observed(ip),
                "mac": observed(mac) if mac is not None else not_derivable(),
                "oui_vendor": _oui_vendor_field(mac),
                "unit_ids": _unit_ids_field(ip),
                "gateway": _gateway_field(ip),
                "role": _role_field(requests_sent.get(ip, 0), requests_received.get(ip, 0)),
                "role_evidence": _role_evidence_field(
                    requests_sent.get(ip, 0), requests_received.get(ip, 0)
                ),
                "role_confidence": _role_confidence_field(
                    requests_sent.get(ip, 0), requests_received.get(ip, 0)
                ),
            }
            return

        # Drugi, rozny adres MAC dla tego samego IP (Z-03): przestaw pole
        # na not_derivable() i zostaw je tam - druga niezgodnosc niczego
        # juz nie zmienia. Adres MAC nieobecny przy pierwszym napotkaniu
        # zostaje not_derivable() na stale, nawet jesli pozniejszy segment
        # niesie adres MAC - brak wiedzy na starcie nie zamienia sie w
        # pewnosc pozniej. Pole oui_vendor NIE jest przeliczane tutaj - jest
        # ustalane wylacznie przy pierwszym napotkaniu adresu IP, spojnie z
        # polem mac, ktorego wtedy dotyczy.
        if first_mac[ip] is not None and mac is not None and mac != first_mac[ip]:
            hosts[ip]["mac"] = not_derivable()

    for segment in segments:
        _visit(segment.src_ip, segment.src_mac)
        _visit(segment.dst_ip, segment.dst_mac)

    return [
        {field_name: dataclasses.asdict(field_value) for field_name, field_value in hosts[ip].items()}
        for ip in order
    ]
