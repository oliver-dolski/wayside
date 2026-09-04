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
from wayside.model import inferred, not_derivable, observed

__all__ = ["build_assets"]


def build_assets(
    *,
    segments: list[Segment],
    vendor_lookup: Callable[[str], str | None] | None = None,
) -> list[dict]:
    """Buduje liste hostow w kolejnosci pierwszego zaobserwowania adresu IP
    w pliku. Kazdy wpis ma klucze `ip`, `mac` i `oui_vendor`, kazda wartosc
    jest slownikiem o ksztalcie `{"value": ..., "provenance": ...}` (wynik
    `dataclasses.asdict` na `ObservedField`).

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

    def _oui_vendor_field(mac: str | None) -> object:
        if mac is None or vendor_lookup is None:
            return not_derivable()
        vendor_name = vendor_lookup(mac)
        if vendor_name is None:
            return not_derivable()
        return inferred(vendor_name, PROVENANCE_METHOD_OUI)

    def _visit(ip: str, mac: str | None) -> None:
        if ip not in hosts:
            order.append(ip)
            first_mac[ip] = mac
            hosts[ip] = {
                "ip": observed(ip),
                "mac": observed(mac) if mac is not None else not_derivable(),
                "oui_vendor": _oui_vendor_field(mac),
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
