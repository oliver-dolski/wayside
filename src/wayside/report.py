"""Renderowanie raportu markdown szesciosekcyjnego, bez silnika szablonow
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
            f"Analiza zrzutu `{capture.get('path', '?')}` wykazala "
            f"{len(findings)} finding(i) wymagajacy(ych) uwagi."
        )
    else:
        lines.append(
            f"Analiza zrzutu `{capture.get('path', '?')}` nie wykazala "
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
    lines.append("")

    lines.append(f"## {SECTIONS[2]}")
    lines.append("")
    lines.append(
        "Kazdy finding niesie wskaznik zaobserwowanego zachowania w ruchu "
        "sieciowym, nigdy werdykt zgodnosci albo niezgodnosci z norma. Waga "
        "findingu wynika z ponizszych, udokumentowanych kryteriow rubryki "
        f"(wersja {risk.RUBRIC_VERSION}), nie z wymyslonej skali:"
    )
    lines.append("")
    for severity in risk.ALLOWED_SEVERITIES:
        criterion = risk.RUBRIC_CRITERIA.get(severity, "")
        lines.append(f"- **{severity}**: {criterion}")
    lines.append("")

    lines.append(f"## {SECTIONS[3]}")
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

    lines.append(f"## {SECTIONS[4]}")
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

    lines.append(f"## {SECTIONS[5]}")
    lines.append("")
    if not findings:
        lines.append("Brak zalecen w tym przebiegu.")
    else:
        for finding in findings:
            lines.append(f"- {finding['remediation']}")
    lines.append("")

    return "\n".join(lines) + "\n"
