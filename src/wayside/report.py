"""Renderowanie raportu markdown siedmiosekcyjnego, bez silnika szablonow
(D-05, REPORT-01).

`SECTIONS` jest literalna krotka, kolejnosc jest kontraktem. Sekcja
metodyki renderuje `risk.RUBRIC_CRITERIA`, zeby kryteria byly udokumentowane
w produkcie, nie tylko w kodzie. Zaden finding nie jest zaslepka: dowod,
powolanie i parafraza pochodza z modelu przekazanego przez wywolujacego.
"""

from __future__ import annotations

from datetime import datetime

from wayside import risk

__all__ = ["SECTIONS", "render_markdown"]

SECTIONS: tuple[str, ...] = (
    "Streszczenie",
    "Zakres",
    "Metodyka",
    "Inwentarz",
    "Ograniczenia",
    "Findingi",
    "Zalecenia",
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
                # ASSET-02: pole oui_vendor ma wlasny punkt z etykieta
                # "Producent" nizej, wiec jest wylaczone z tej petli
                # ogolnej, zeby nie renderowac go dwa razy.
                if field_name == "oui_vendor":
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
            lines.append("")

    lines.append(f"## {SECTIONS[4]}")
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

    lines.append(f"## {SECTIONS[5]}")
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

    lines.append(f"## {SECTIONS[6]}")
    lines.append("")
    if not findings:
        lines.append("Brak zalecen w tym przebiegu.")
    else:
        for finding in findings:
            lines.append(f"- {finding['remediation']}")
    lines.append("")

    return "\n".join(lines) + "\n"
