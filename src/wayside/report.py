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
from wayside.flow import PROTOCOL_UNRECOGNIZED
from wayside.model import collect_not_derivable_fields

__all__ = [
    "SECTIONS",
    "render_markdown",
    "citation_line",
    "citation_scope_line",
    "finding_count_phrase",
    "finding_genitive_phrase",
    "session_parties_line",
    "aggregated_remediations",
]

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

# Etykieta opisu wlasnego (G-04-3c) - nazywa rzecz wprost, a nie lagodzi ja:
# czytelnik ma wiedziec, ze to zdanie napisal autor narzedzia, a nie komitet
# normalizacyjny. Stala wspoldzielona przez markdown i PDF (przez import w
# `report_pdf.py`), zeby ksztalt etykiety nie mogl rozjechac sie miedzy
# formatami.
CITATION_SCOPE_LABEL = "Zakres punktu (opis własny, nie tytuł z egzemplarza)"


def citation_line(ref: dict) -> str:
    """Buduje linie powolania na norme (G-04-3c).

    Dla prowieniencji z egzemplarza (`clause_title_source == "egzemplarz"`)
    zwraca ksztalt dzisiejszy: sygnatura, numer punktu, separator i tytul
    punktu - tytul jest wtedy PRZEPISANY z legalnego egzemplarza normy. Dla
    prowieniencji wlasnej zwraca sam poczatek, bez tytulu i bez separatora:
    tytul wymyslony dla punktu bez numeru nie ma stac w tym samym ksztalcie,
    co tytul potwierdzony."""
    base = f"Powołanie na normę: {ref['standard']} {ref['clause']}"
    if ref["clause_title_source"] == "egzemplarz":
        return f"{base} - {ref['clause_title']}"
    return base


def finding_count_phrase(count: int) -> str:
    """Buduje zdanie o liczbie findingow z poprawna polska odmiana (G-04-4).

    Liczba rowna jeden daje forme pojedyncza. Liczba, ktorej ostatnia cyfra
    nalezy do przedzialu od dwoch do czterech, daje forme mnoga - CHYBA ZE
    dwie ostatnie cyfry naleza do przedzialu od dwunastu do czternastu, bo
    ten przedzial jest wyjatkiem od reguly koncowki w calej polskiej
    odmianie rzeczownikow policzalnych (12, 13, 14, ale takze 112, 213 -
    dowolna setka/tysiac z tymi samymi dwiema ostatnimi cyframi). Kazda inna
    liczba daje forme mnoga dopelniaczowa."""
    if count == 1:
        return f"{count} finding wymagający uwagi"
    last_two_digits = count % 100
    last_digit = count % 10
    if last_digit in (2, 3, 4) and last_two_digits not in (12, 13, 14):
        return f"{count} findingi wymagające uwagi"
    return f"{count} findingów wymagających uwagi"


def citation_scope_line(ref: dict) -> str | None:
    """Buduje linie opisu wlasnego zakresu punktu (G-04-3c).

    Zwraca `None` dla prowieniencji z egzemplarza - tytul juz stoi w linii
    powolania i osobna linia opisu byłaby powtorzeniem. Dla prowieniencji
    wlasnej zwraca linie z `CITATION_SCOPE_LABEL` i trescia pola tytulu."""
    if ref["clause_title_source"] == "egzemplarz":
        return None
    return f"{CITATION_SCOPE_LABEL}: {ref['clause_title']}"


def finding_genitive_phrase(count: int) -> str:
    """Buduje forme dopelniaczowa liczby findingow, obok `finding_count_phrase`
    (G-04-5a). Liczba rowna jeden daje forme pojedyncza ("1 findingu"), kazda
    inna liczba forme dopelniaczowa liczby mnogiej ("N findingów") - BEZ
    wyjatku dla przedzialu dwanascie-czternascie: w tej konstrukcji (rzeczownik
    w dopelniaczu po liczebniku glownym) forma jest ta sama dla kazdej liczby
    wiekszej niz jeden, w odroznieniu od `finding_count_phrase` powyzej, ktora
    ma inny ksztalt gramatyczny (rzeczownik w mianowniku/bierniku zgadzajacy
    sie z liczebnikiem)."""
    if count == 1:
        return f"{count} findingu"
    return f"{count} findingów"


def aggregated_remediations(findings: list[dict]) -> list[tuple[str, int]]:
    """Zbiera zalecenia findingow bez powtorzen (G-04-5a).

    Zwraca liste par (tresc zalecenia, liczba findingow, ktore je niosa), w
    kolejnosci PIERWSZEGO wystapienia zalecenia na liscie wejsciowej. Wzorzec
    identyczny z `checks.engine._dedupe_standards`: slownik zliczajacy plus
    osobna lista kolejnosci, nigdy zbior na sciezce do serializacji -
    kolejnosc wierszy raportu wchodzi do artefaktu porownywanego bajtowo,
    a zbior jej nie ma.

    Porownanie idzie po PELNYM lancuchu zalecenia (zalozenie Z-94): dwa
    zalecenia rozniace sie samym koncem sa dwoma roznymi zaleceniami."""
    counts: dict[str, int] = {}
    order: list[str] = []
    for finding in findings:
        remediation = finding["remediation"]
        if remediation not in counts:
            order.append(remediation)
        counts[remediation] = counts.get(remediation, 0) + 1
    return [(remediation, counts[remediation]) for remediation in order]


def session_parties_line(evidence: dict) -> str:
    """Buduje linie uczestnikow sesji, ktorej finding dotyczy (G-04-5b):
    strony sesji w postaci adres zrodlowy, strzalka, adres docelowy, wziete
    z pary punktow koncowych dopisanej do dowodu przez silnik checkow.
    Wspolna funkcja czysta dla markdown i PDF (`report_pdf.py` importuje ja
    ta sama droga co `citation_line`)."""
    return f"Uczestnicy sesji: {evidence['source']} -> {evidence['target']}"


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
            f"Analiza zrzutu `{capture.get('filename', '?')}` wykazała "
            f"{finding_count_phrase(len(findings))}."
        )
    else:
        lines.append(
            f"Analiza zrzutu `{capture.get('filename', '?')}` nie wykazała "
            "żadnego findingu w tym przebiegu."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[1]}")
    lines.append("")
    # PROTO-05: lista protokolow idzie z danych (`analysis["protocol_events"]`),
    # nie z zamknietej listy stalych - kolejny dissector w rejestrze nie
    # wymaga zmiany tego zdania (04-RESEARCH.md, Pitfall 4).
    recognized_protocols = sorted(
        {event["protocol"] for event in analysis.get("protocol_events", [])}
    )
    if recognized_protocols:
        protocols_sentence = (
            f"Zrzut niesie {capture.get('packet_count', 0)} pakietów. W tym "
            f"zrzucie rozpoznano protokół(y): {', '.join(recognized_protocols)}, "
            "rozpoznawane po kształcie zawartości segmentu, nigdy po numerze "
            "portu."
        )
    else:
        protocols_sentence = (
            f"Zrzut niesie {capture.get('packet_count', 0)} pakietów. W tym "
            "zrzucie żaden protokół aplikacyjny nie został rozpoznany; "
            "rozpoznanie idzie po kształcie zawartości segmentu, nigdy po "
            "numerze portu."
        )
    scope_boundary_sentence = (
        "Ruch, którego protokołu nie rozpoznano, ma wiersz w macierzy "
        f"komunikacji z etykietą `{PROTOCOL_UNRECOGNIZED}` i nie jest "
        "podstawą żadnego findingu."
    )
    lines.append(f"{protocols_sentence} {scope_boundary_sentence}")
    first_seen = capture.get("first_seen")
    last_seen = capture.get("last_seen")
    if first_seen is not None and last_seen is not None:
        window_sentence = (
            f"Okno czasowe zrzutu: od {first_seen} do {last_seen} "
            "(znaczniki czasu epoki Unix)."
        )
    else:
        window_sentence = (
            "Okno czasowe zrzutu nie zostało ustalone - zrzut nie zawiera "
            "ani jednego pakietu."
        )
    snaplen = capture.get("snaplen")
    if snaplen is not None:
        snaplen_sentence = f"Snaplen odczytany z nagłówka zrzutu: {snaplen} bajtów."
    else:
        snaplen_note = capture.get("snaplen_note") or (
            "snaplen nie został jednoznacznie ustalony"
        )
        snaplen_sentence = f"Snaplen nie został jednoznacznie ustalony ({snaplen_note})."
    # Wartosc zero renderowana jawnie - brak ucietych ramek jest wynikiem
    # analizy zrzutu, nie brakiem zdania o nim (INGEST-03).
    snaplen_truncated_count = capture.get("snaplen_truncated_packet_count", 0)
    snaplen_truncated_sentence = (
        f"Ramek uciętych przez snaplen: {snaplen_truncated_count}."
    )
    # PROTO-03: wartosc zero renderowana jawnie, tak samo jak liczba ramek
    # ucietych przez snaplen wyzej - odczyt przez .get z wartoscia zapasowa,
    # zeby model budowany recznie w tests/test_report_render.py nadal sie
    # renderowal.
    low_confidence_count = len(analysis.get("low_confidence_events", []))
    low_confidence_sentence = f"Zdarzeń rozpoznanych z niską pewnością: {low_confidence_count}."
    lines.append(
        f"{window_sentence} {snaplen_sentence} {snaplen_truncated_sentence} "
        f"{low_confidence_sentence}"
    )
    lines.append("")

    lines.append(f"## {SECTIONS[2]}")
    lines.append("")
    lines.append(
        "Każdy finding niesie wskaźnik zaobserwowanego zachowania w ruchu "
        "sieciowym, nigdy ocenę, czy instalacja spełnia albo nie spełnia "
        "wymagań normy. Waga findingu wynika z poniższych, udokumentowanych "
        f"kryteriów rubryki (wersja {risk.RUBRIC_VERSION}), nie z wymyślonej skali:"
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
            "Żaden host z warstwą IP nie został zaobserwowany w tym zrzucie."
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
                        "urządzeniami logicznymi za nią"
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
                    f"- Dowód roli: {role_evidence['value']} ({role_evidence['provenance']})"
                )

            role_confidence = host.get("role_confidence")
            if role_confidence is not None:
                lines.append(
                    f"- Pewność roli: {role_confidence['value']} "
                    f"({role_confidence['provenance']})"
                )
            lines.append("")

    lines.append(f"## {SECTIONS[4]}")
    lines.append("")
    comm_matrix = analysis.get("comm_matrix", [])
    if not comm_matrix:
        lines.append(
            "Żadna sesja TCP z ładunkiem nie została zaobserwowana w tym zrzucie."
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
            "| Sesja | Źródło | Cel | Kierunek | Protokół | Wolumen (B) | "
            "Pakietów | Strona inicjująca |"
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
        "check, jeden punkt normy. Model strefy i kanału jest placeholderem "
        "jednostrefowym wyprowadzonym automatycznie z tego zrzutu, nie "
        "zaprojektowaną topologią sieci. Numeracja punktu normy jest "
        "prowizoryczna i czeka na zestawienie z legalnym egzemplarzem normy."
    )
    lines.append("")

    # REPORT-02: lista pol nieustalonych powstaje z TEGO modelu, nie z listy
    # pisanej recznie - dopisanie nowego pola inwentarza albo macierzy trafia
    # tu samo, bez zmiany w warstwie renderowania.
    not_derivable_rows = collect_not_derivable_fields(analysis)
    if not_derivable_rows:
        lines.append(
            "Pola, których nie da się ustalić z tego zrzutu, zebrane po nazwie pola:"
        )
        lines.append("")
        for row in not_derivable_rows:
            lines.append(
                f"- sekcja `{row['section']}`, pole `{row['field']}`: "
                f"{row['count']} z {row['total']} wpisów"
            )
    else:
        lines.append(
            "W tym przebiegu każde pole sekcji inwentarza i macierzy komunikacji "
            "zostało ustalone z zaobserwowanego ruchu."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[6]}")
    lines.append("")
    if not findings:
        lines.append("Brak findingów w tym przebiegu.")
        lines.append("")
    for finding in findings:
        evidence = finding["evidence"]
        lines.append(f"### {finding['title']}")
        lines.append("")
        lines.append(f"- Identyfikator checka: `{finding['check_id']}`")
        lines.append(f"- Waga: {finding['severity']} (ryzyko: {finding['risk']})")
        lines.append(f"- {session_parties_line(evidence)}")
        lines.append(
            f"- Dowód: pakiet nr {evidence['packet_number']}, "
            f"sesja nr {evidence['session_id']}"
        )
        lines.append(f"- Uzasadnienie: {finding['rationale']}")
        for ref in finding["standard_refs"]:
            lines.append(f"- {citation_line(ref)}")
            scope_line = citation_scope_line(ref)
            if scope_line is not None:
                lines.append(f"  - {scope_line}")
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
        lines.append("Brak zaleceń w tym przebiegu.")
    else:
        for remediation, count in aggregated_remediations(findings):
            lines.append(f"- {remediation} (dotyczy {finding_genitive_phrase(count)})")
    lines.append("")

    return "\n".join(lines) + "\n"
