"""Renderowanie raportu markdown osmiosekcyjnego, bez silnika szablonow
(D-05, REPORT-01).

`SECTIONS` jest literalna krotka, kolejnosc jest kontraktem. Sekcja
metodyki renderuje `risk.RUBRIC_CRITERIA`, zeby kryteria byly udokumentowane
w produkcie, nie tylko w kodzie. Zaden finding nie jest zaslepka: dowod,
powolanie i parafraza pochodza z modelu przekazanego przez wywolujacego.
"""

from __future__ import annotations

from datetime import datetime

from wayside import risk
from wayside.model import collect_not_derivable_fields

__all__ = ["SECTIONS", "render_markdown"]

SECTIONS: tuple[str, ...] = (
    "Streszczenie",
    "Zakres",
    "Metodyka",
    "Inwentarz",
    "Macierz komunikacji",
    "Ograniczenia",
    "Findingi",
    "Zalecenia",
)


# Pola wpisu hosta renderowane wlasnym punktem z etykieta czytelna dla
# czlowieka, ponizej petli ogolnej po kluczach wpisu.
_HOST_FIELDS_WITH_OWN_ROW: frozenset[str] = frozenset(
    {"oui_vendor", "unit_ids", "gateway", "role", "role_evidence", "role_confidence"}
)


def render_markdown(
    analysis: dict, *, generated_at: datetime, warnings: tuple[str, ...] = ()
) -> str:
    """Renderuje `analysis` do markdown, zwyklymi funkcjami Pythona.
    Znacznik czasu wygenerowania raportu wchodzi WYLACZNIE tutaj, przez
    argument `generated_at` (D-02) - `analysis.json` go nie niesie.
    Analogicznie `warnings` (ostrzezenia z `AnalyzeResult`, np. zrzut
    strukturalnie pusty, D-01) wchodzi tylko tutaj - nie jest czescia
    schematu `analysis.json`."""
    capture = analysis.get("capture", {})
    findings = analysis.get("findings", [])

    lines: list[str] = []
    lines.append("# Raport Wayside")
    lines.append("")
    lines.append(f"Wygenerowano: {generated_at.isoformat()}")
    lines.append("")

    lines.append(f"## {SECTIONS[0]}")
    lines.append("")
    if findings:
        lines.append(
            f"Analiza zrzutu `{capture.get('filename', '?')}` wykazala "
            f"{len(findings)} finding(i) wymagajacy(ych) uwagi."
        )
    else:
        lines.append(
            f"Analiza zrzutu `{capture.get('filename', '?')}` nie wykazala "
            "zadnego findingu w tym przebiegu."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[1]}")
    lines.append("")
    lines.append(
        f"Zrzut niesie {capture.get('packet_count', 0)} pakietow. Analiza "
        "obejmuje wylacznie protokol Modbus/TCP, rozpoznawany po ksztalcie "
        "naglowka MBAP, niezaleznie od numeru portu."
    )
    first_seen = capture.get("first_seen")
    last_seen = capture.get("last_seen")
    if first_seen is not None and last_seen is not None:
        window_sentence = (
            f"Okno czasowe zrzutu: od {first_seen} do {last_seen} "
            "(znaczniki czasu epoki Unix)."
        )
    else:
        window_sentence = (
            "Okno czasowe zrzutu nie zostalo ustalone - zrzut nie zawiera "
            "ani jednego pakietu."
        )
    snaplen = capture.get("snaplen")
    if snaplen is not None:
        snaplen_sentence = f"Snaplen odczytany z naglowka zrzutu: {snaplen} bajtow."
    else:
        snaplen_note = capture.get("snaplen_note") or (
            "snaplen nie zostal jednoznacznie ustalony"
        )
        snaplen_sentence = f"Snaplen nie zostal jednoznacznie ustalony ({snaplen_note})."
    # Wartosc zero renderowana jawnie - brak ucietych ramek jest wynikiem
    # analizy zrzutu, nie brakiem zdania o nim (INGEST-03).
    snaplen_truncated_count = capture.get("snaplen_truncated_packet_count", 0)
    snaplen_truncated_sentence = (
        f"Ramek ucietych przez snaplen: {snaplen_truncated_count}."
    )
    # PROTO-03: wartosc zero renderowana jawnie, tak samo jak liczba ramek
    # ucietych przez snaplen wyzej - odczyt przez .get z wartoscia zapasowa,
    # zeby model budowany recznie w tests/test_report_render.py nadal sie
    # renderowal.
    low_confidence_count = len(analysis.get("low_confidence_events", []))
    low_confidence_sentence = (
        "Zdarzen rozpoznanych z niska pewnoscia (modbus-rtu-over-tcp): "
        f"{low_confidence_count}."
    )
    lines.append(
        f"{window_sentence} {snaplen_sentence} {snaplen_truncated_sentence} "
        f"{low_confidence_sentence}"
    )
    lines.append("")

    lines.append(f"## {SECTIONS[2]}")
    lines.append("")
    lines.append(
        "Kazdy finding niesie wskaznik zaobserwowanego zachowania w ruchu "
        "sieciowym, nigdy ocene, czy instalacja spelnia albo nie spelnia "
        "wymagan normy. Waga findingu wynika z ponizszych, udokumentowanych "
        f"kryteriow rubryki (wersja {risk.RUBRIC_VERSION}), nie z wymyslonej skali:"
    )
    lines.append("")
    for severity in risk.ALLOWED_SEVERITIES:
        criterion = risk.RUBRIC_CRITERIA.get(severity, "")
        lines.append(f"- **{severity}**: {criterion}")
    lines.append("")

    lines.append(f"## {SECTIONS[3]}")
    lines.append("")
    assets = analysis.get("assets", [])
    if not assets:
        lines.append(
            "Zaden host z warstwa IP nie zostal zaobserwowany w tym zrzucie."
        )
        lines.append("")
    else:
        for host in assets:
            ip_field = host["ip"]
            lines.append(f"### {ip_field['value']}")
            lines.append("")
            for field_name, field_value in host.items():
                # Pola z wlasnymi punktami nizej (ASSET-02, ASSET-04 do
                # ASSET-07) sa wylaczone z tej petli ogolnej, zeby nie
                # renderowac ich dwa razy - raz pod nazwa klucza, raz pod
                # etykieta czytelna dla czlowieka.
                if field_name in _HOST_FIELDS_WITH_OWN_ROW:
                    continue
                value = field_value["value"]
                provenance = field_value["provenance"]
                rendered_value = "nieustalone" if value is None else value
                lines.append(f"- {field_name}: {rendered_value} ({provenance})")
            # Odczyt przez .get z obsluga braku klucza, zeby model budowany
            # recznie w tests/test_report_render.py nadal sie renderowal.
            oui_vendor = host.get("oui_vendor")
            if oui_vendor is not None:
                vendor_value = oui_vendor["value"]
                vendor_provenance = oui_vendor["provenance"]
                rendered_vendor = "nieustalony" if vendor_value is None else vendor_value
                lines.append(f"- Producent: {rendered_vendor} ({vendor_provenance})")

            unit_ids = host.get("unit_ids")
            if unit_ids is not None:
                unit_ids_value = unit_ids["value"]
                rendered_unit_ids = (
                    "nieustalone"
                    if unit_ids_value is None
                    else ", ".join(str(unit_id) for unit_id in unit_ids_value)
                )
                lines.append(
                    f"- Podadresy Unit ID: {rendered_unit_ids} ({unit_ids['provenance']})"
                )

            gateway = host.get("gateway")
            if gateway is not None:
                if gateway["value"]:
                    # Liczba urzadzen logicznych wyliczana z dlugosci listy
                    # podadresow tego samego hosta, nie z osobnego pola modelu:
                    # jedno zrodlo tej liczby, dwa miejsca jej uzycia.
                    logical_devices = len((unit_ids or {}).get("value") or [])
                    rendered_gateway = (
                        f"prawdopodobna brama z {logical_devices} "
                        "urzadzeniami logicznymi za nia"
                    )
                else:
                    # Przy wartosci `null` NIE renderujemy zdania o tym, ze host
                    # brama nie jest (zalozenie Z-25): to ta sama pulapka co
                    # wartosc `false` w modelu, tylko przeniesiona do tekstu.
                    rendered_gateway = "nieustalone"
                lines.append(
                    f"- Brama: {rendered_gateway} ({gateway['provenance']})"
                )

            role = host.get("role")
            if role is not None:
                lines.append(f"- Rola: {role['value']} ({role['provenance']})")

            # Dowod roli stoi BEZPOSREDNIO pod rola: etykieta bez towarzyszacego
            # dowodu w tym samym miejscu jest sygnalem, ktorego doswiadczony
            # recenzent szuka najpierw (PITFALLS.md, Pitfall 9).
            role_evidence = host.get("role_evidence")
            if role_evidence is not None:
                lines.append(
                    f"- Dowod roli: {role_evidence['value']} ({role_evidence['provenance']})"
                )

            role_confidence = host.get("role_confidence")
            if role_confidence is not None:
                lines.append(
                    f"- Pewnosc roli: {role_confidence['value']} "
                    f"({role_confidence['provenance']})"
                )
            lines.append("")

    lines.append(f"## {SECTIONS[4]}")
    lines.append("")
    comm_matrix = analysis.get("comm_matrix", [])
    if not comm_matrix:
        lines.append(
            "Zadna sesja TCP z ladunkiem nie zostala zaobserwowana w tym zrzucie."
        )
        lines.append("")
    else:
        # Tabela jest tu wlasciwym ksztaltem, w odroznieniu od inwentarza:
        # osiem kolumn krotkich wartosci czyta sie w wierszu, a porownanie sesji
        # miedzy soba jest cala trescia macierzy. Znacznik pochodzenia stoi przy
        # kierunku i przy stronie inicjujacej, czyli tam, gdzie rozroznienie
        # obserwacji od wniosku zmienia odczyt; kolumny czysto liczbowe ze
        # znacznikiem `observed` znacznika nie niosa, zeby tabela pozostala
        # czytelna.
        lines.append(
            "| Sesja | Zrodlo | Cel | Kierunek | Protokol | Wolumen (B) | "
            "Pakietow | Strona inicjujaca |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for row in comm_matrix:
            direction = row.get("direction", {})
            initiator = row.get("initiator", {})
            initiator_value = initiator.get("value")
            rendered_initiator = (
                "nieustalona" if initiator_value is None else initiator_value
            )
            lines.append(
                f"| {row.get('session_id', {}).get('value', '?')} "
                f"| {row.get('source', {}).get('value', '?')} "
                f"| {row.get('target', {}).get('value', '?')} "
                f"| {direction.get('value', '?')} ({direction.get('provenance', '?')}) "
                f"| {row.get('protocol', {}).get('value', '?')} "
                f"| {row.get('volume_bytes', {}).get('value', '?')} "
                f"| {row.get('packet_count', {}).get('value', '?')} "
                f"| {rendered_initiator} ({initiator.get('provenance', '?')}) |"
            )
        lines.append("")

    lines.append(f"## {SECTIONS[5]}")
    lines.append("")
    for warning in warnings:
        lines.append(f"- {warning}")
    if warnings:
        lines.append("")
    lines.append(
        "Ten raport pochodzi z pionowego przekroju: jeden zrzut, jeden "
        "check, jeden punkt normy. Model strefy i kanalu jest placeholderem "
        "jednostrefowym wyprowadzonym automatycznie z tego zrzutu, nie "
        "zaprojektowana topologia sieci. Numeracja punktu normy jest "
        "prowizoryczna i czeka na zestawienie z legalnym egzemplarzem normy."
    )
    lines.append("")

    # REPORT-02: lista pol nieustalonych powstaje z TEGO modelu, nie z listy
    # pisanej recznie - dopisanie nowego pola inwentarza albo macierzy trafia
    # tu samo, bez zmiany w warstwie renderowania.
    not_derivable_rows = collect_not_derivable_fields(analysis)
    if not_derivable_rows:
        lines.append(
            "Pola, ktorych nie da sie ustalic z tego zrzutu, zebrane po nazwie pola:"
        )
        lines.append("")
        for row in not_derivable_rows:
            lines.append(
                f"- sekcja `{row['section']}`, pole `{row['field']}`: "
                f"{row['count']} z {row['total']} wpisow"
            )
    else:
        lines.append(
            "W tym przebiegu kazde pole sekcji inwentarza i macierzy komunikacji "
            "zostalo ustalone z zaobserwowanego ruchu."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[6]}")
    lines.append("")
    if not findings:
        lines.append("Brak findingow w tym przebiegu.")
        lines.append("")
    for finding in findings:
        evidence = finding["evidence"]
        lines.append(f"### {finding['title']}")
        lines.append("")
        lines.append(f"- Identyfikator checka: `{finding['check_id']}`")
        lines.append(f"- Waga: {finding['severity']} (ryzyko: {finding['risk']})")
        lines.append(
            f"- Dowod: pakiet nr {evidence['packet_number']}, "
            f"sesja nr {evidence['session_id']}"
        )
        lines.append(f"- Uzasadnienie: {finding['rationale']}")
        for ref in finding["standard_refs"]:
            lines.append(
                f"- Powolanie na norme: {ref['standard']} {ref['clause']} - "
                f"{ref['clause_title']}"
            )
            lines.append(f"  - Parafraza: {ref['paraphrase']}")
            if ref["verified"]:
                lines.append("  - Status: zweryfikowane")
            else:
                lines.append(
                    "  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** "
                    f"({ref['verification_note']})"
                )
        lines.append(f"- Zalecenie: {finding['remediation']}")
        lines.append("")

    lines.append(f"## {SECTIONS[7]}")
    lines.append("")
    if not findings:
        lines.append("Brak zalecen w tym przebiegu.")
    else:
        for finding in findings:
            lines.append(f"- {finding['remediation']}")
    lines.append("")

    return "\n".join(lines) + "\n"
