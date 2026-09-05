"""Renderowanie raportu do PDF z osadzonym fontem Unicode, wprost ze slownika
modelu analizy - bez silnika szablonow (D-05, zalozenie Z-56, ta sama zasada
co `report.py`).

Piec rzeczy, ktore ten modul niesie i ktore MUSZA pozostac prawdziwe przy
kazdej edycji.

1. Renderowanie idzie z TEGO SAMEGO slownika modelu, z ktorego powstaje
   markdown (`render_markdown`), NIGDY z parsowania tekstu markdown z
   powrotem - to jest jedno zrodlo prawdy dla listy findingow w obu
   formatach (REPORT-03, `04-RESEARCH.md` Anti-Patterns). Ten modul
   importuje z `wayside.report` wylacznie krotke `SECTIONS` i dwie funkcje
   czyste budujace linie powolania (`citation_line`, `citation_scope_line`)
   - nigdy logike petli ani stan.
2. Brak silnika szablonow (D-05, zalozenie Z-56): tresc sklada sie
   wywolaniami biblioteki `fpdf2` wprost, bez Jinja2 ani innego templatera -
   ta sama dyscyplina co `report.py`.
3. Znacznik czasu wygenerowania wchodzi WYLACZNIE argumentem `generated_at`
   wywolujacego (D-02, zalozenie Z-54) - ten modul nie odczytuje zegara
   systemowego ani razu, co jest warunkiem determinizmu bajtowego miedzy
   dwoma przebiegami w osobnych procesach (04-RESEARCH.md, Pitfall 7).
4. Wszystkie metadane dokumentu PDF (tytul, autor, tworca, producent) sa
   stalymi modulowymi w `PDF_METADATA` (zalozenie Z-54) - zadne pole nie
   niesie nazwy uzytkownika systemu ani nazwy maszyny, bo artefakt jest
   wysylany klientowi.
5. Font jest osadzany z katalogu pakietu (`assets/fonts/`, zalozenie Z-52).
   Wybor DejaVu Sans ma dwa powody: pelne pokrycie polskiej diakrytyki
   (a, c, e, l, n, o, s, z, z) i licencja pozwalajaca na redystrybucje w
   publicznym repozytorium - font systemowy jest odrzucony, bo jego sciezka
   nie jest odtwarzalna miedzy maszynami.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fpdf import FPDF

from wayside import risk
from wayside.flow import PROTOCOL_UNRECOGNIZED
from wayside.model import collect_not_derivable_fields
from wayside.report import (
    SECTIONS,
    citation_line,
    citation_scope_line,
    finding_count_phrase,
    session_parties_line,
)

__all__ = [
    "FONT_DIR",
    "FONT_REGULAR_PATH",
    "FONT_BOLD_PATH",
    "FONT_FAMILY",
    "PDF_METADATA",
    "PdfRenderError",
    "render_pdf",
]

FONT_DIR = Path(__file__).resolve().parent / "assets" / "fonts"
FONT_REGULAR_PATH = FONT_DIR / "DejaVuSans.ttf"
FONT_BOLD_PATH = FONT_DIR / "DejaVuSans-Bold.ttf"
FONT_FAMILY = "dejavu-sans"

# Stale (zalozenie Z-54): zadne pole nie niesie nazwy uzytkownika systemu ani
# nazwy maszyny - artefakt wysylany klientowi nie moze zdradzac srodowiska
# autora. Data utworzenia dokumentu NIE stoi tutaj - wchodzi z argumentu
# `generated_at` przez `set_creation_date`.
PDF_METADATA: dict[str, str] = {
    "title": "Raport Wayside",
    "author": "Wayside",
    "creator": "Wayside",
    "producer": "Wayside",
}

# Pola wpisu hosta renderowane wlasnym punktem z etykieta czytelna dla
# czlowieka, ponizej petli ogolnej po kluczach wpisu - lustro
# `report._HOST_FIELDS_WITH_OWN_ROW` (prywatne w tamtym module, wiec ten
# modul niesie wlasna kopie, nie import: dwa niezalezne renderery tego
# samego modelu, nie jeden import wewnetrznego symbolu drugiego).
_HOST_FIELDS_WITH_OWN_ROW: frozenset[str] = frozenset(
    {"oui_vendor", "unit_ids", "gateway", "role", "role_evidence", "role_confidence"}
)

_HEADING_SIZE = 13
_BODY_SIZE = 10
_TITLE_SIZE = 16
_LINE_HEIGHT = 5.5
_HEADING_LINE_HEIGHT = 8


class PdfRenderError(Exception):
    """Podnoszony w dwoch przypadkach: brak pliku fontu wymaganego do
    renderowania (sprawdzane PRZED rozpoczeciem budowy dokumentu) i
    niepowodzenie osadzenia fontu w dokumencie."""


def _require_font_files() -> None:
    for path in (FONT_REGULAR_PATH, FONT_BOLD_PATH):
        if not path.is_file():
            raise PdfRenderError(
                f"Brak pliku fontu wymaganego do renderowania PDF: {path}"
            )


def _heading(pdf: FPDF, text: str) -> None:
    pdf.set_font(FONT_FAMILY, style="b", size=_HEADING_SIZE)
    pdf.multi_cell(0, _HEADING_LINE_HEIGHT, text, align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _body(pdf: FPDF, text: str, *, wrapmode: str = "WORD") -> None:
    # `align="L"` wprost - domyslna wartosc `multi_cell` jest wyjustowana
    # (Align.J), a justowanie rozklada dodatkowe spacje miedzy slowami w
    # sposob zalezny od szerokosci wiersza. Warstwa tekstowa wyciagnieta
    # `pypdf.extract_text()` odzwierciedla te dodatkowe spacje (pojedyncza
    # albo podwojna, zaleznie od linii), co lamie kazde porownanie
    # podciagu obejmujace wiecej niz jedno slowo - lewe wyrownanie
    # eliminuje ten tryb porazki calkowicie, kosztem estetyki bez znaczenia
    # dla bramki maszynowej.
    pdf.set_font(FONT_FAMILY, style="", size=_BODY_SIZE)
    pdf.multi_cell(
        0, _LINE_HEIGHT, text, align="L", new_x="LMARGIN", new_y="NEXT",
        wrapmode=wrapmode,
    )


def _bold_line(pdf: FPDF, text: str) -> None:
    pdf.set_font(FONT_FAMILY, style="b", size=_BODY_SIZE)
    pdf.multi_cell(0, _LINE_HEIGHT, text, align="L", new_x="LMARGIN", new_y="NEXT")


def render_pdf(
    analysis: dict, *, generated_at: datetime, warnings: tuple[str, ...] = ()
) -> bytes:
    """Renderuje `analysis` do PDF. Sygnatura IDENTYCZNA z
    `report.render_markdown` - te same nazwy argumentow, ta sama wartosc
    domyslna `warnings`. Znacznik czasu wygenerowania raportu wchodzi
    WYLACZNIE tutaj, przez argument `generated_at` (D-02) - `analysis.json`
    go nie niesie. Zwraca bajty gotowego dokumentu PDF."""
    _require_font_files()

    capture = analysis.get("capture", {})
    findings = analysis.get("findings", [])

    pdf = FPDF()
    pdf.add_font(FONT_FAMILY, style="", fname=str(FONT_REGULAR_PATH))
    pdf.add_font(FONT_FAMILY, style="b", fname=str(FONT_BOLD_PATH))
    pdf.set_title(PDF_METADATA["title"])
    pdf.set_author(PDF_METADATA["author"])
    pdf.set_creator(PDF_METADATA["creator"])
    pdf.set_producer(PDF_METADATA["producer"])
    pdf.set_creation_date(generated_at)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font(FONT_FAMILY, style="b", size=_TITLE_SIZE)
    pdf.multi_cell(0, 9, "Raport Wayside", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT_FAMILY, style="", size=_BODY_SIZE)
    pdf.multi_cell(
        0, _LINE_HEIGHT, f"Wygenerowano: {generated_at.isoformat()}",
        align="L", new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(2)

    # --- Streszczenie -------------------------------------------------------
    _heading(pdf, SECTIONS[0])
    if findings:
        _body(
            pdf,
            f"Analiza zrzutu `{capture.get('filename', '?')}` wykazała "
            f"{finding_count_phrase(len(findings))}.",
        )
    else:
        _body(
            pdf,
            f"Analiza zrzutu `{capture.get('filename', '?')}` nie wykazała "
            "żadnego findingu w tym przebiegu.",
        )

    # --- Zakres ---------------------------------------------------------
    _heading(pdf, SECTIONS[1])
    # PROTO-05: lista protokolow idzie z danych, nie z zamknietej listy
    # stalych - ta sama zasada co `report.render_markdown`.
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
    _body(pdf, f"{protocols_sentence} {scope_boundary_sentence}")

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
    snaplen_truncated_count = capture.get("snaplen_truncated_packet_count", 0)
    snaplen_truncated_sentence = (
        f"Ramek uciętych przez snaplen: {snaplen_truncated_count}."
    )
    low_confidence_count = len(analysis.get("low_confidence_events", []))
    low_confidence_sentence = f"Zdarzeń rozpoznanych z niską pewnością: {low_confidence_count}."
    _body(
        pdf,
        f"{window_sentence} {snaplen_sentence} {snaplen_truncated_sentence} "
        f"{low_confidence_sentence}",
    )

    # --- Metodyka ---------------------------------------------------------
    _heading(pdf, SECTIONS[2])
    _body(
        pdf,
        "Każdy finding niesie wskaźnik zaobserwowanego zachowania w ruchu "
        "sieciowym, nigdy ocenę, czy instalacja spełnia albo nie spełnia "
        "wymagań normy. Waga findingu wynika z poniższych, udokumentowanych "
        f"kryteriów rubryki (wersja {risk.RUBRIC_VERSION}), nie z wymyślonej skali:",
    )
    for severity in risk.ALLOWED_SEVERITIES:
        criterion = risk.RUBRIC_CRITERIA.get(severity, "")
        _body(pdf, f"- {severity}: {criterion}")

    # --- Inwentarz ----------------------------------------------------------
    _heading(pdf, SECTIONS[3])
    assets = analysis.get("assets", [])
    if not assets:
        _body(pdf, "Żaden host z warstwą IP nie został zaobserwowany w tym zrzucie.")
    else:
        for host in assets:
            ip_field = host["ip"]
            _bold_line(pdf, str(ip_field["value"]))
            for field_name, field_value in host.items():
                if field_name in _HOST_FIELDS_WITH_OWN_ROW:
                    continue
                value = field_value["value"]
                provenance = field_value["provenance"]
                rendered_value = "nieustalone" if value is None else value
                _body(pdf, f"- {field_name}: {rendered_value} ({provenance})")

            oui_vendor = host.get("oui_vendor")
            if oui_vendor is not None:
                vendor_value = oui_vendor["value"]
                vendor_provenance = oui_vendor["provenance"]
                rendered_vendor = "nieustalony" if vendor_value is None else vendor_value
                _body(pdf, f"- Producent: {rendered_vendor} ({vendor_provenance})")

            unit_ids = host.get("unit_ids")
            if unit_ids is not None:
                unit_ids_value = unit_ids["value"]
                rendered_unit_ids = (
                    "nieustalone"
                    if unit_ids_value is None
                    else ", ".join(str(unit_id) for unit_id in unit_ids_value)
                )
                _body(
                    pdf,
                    f"- Podadresy Unit ID: {rendered_unit_ids} ({unit_ids['provenance']})",
                )

            gateway = host.get("gateway")
            if gateway is not None:
                if gateway["value"]:
                    logical_devices = len((unit_ids or {}).get("value") or [])
                    rendered_gateway = (
                        f"prawdopodobna brama z {logical_devices} "
                        "urządzeniami logicznymi za nią"
                    )
                else:
                    rendered_gateway = "nieustalone"
                _body(pdf, f"- Brama: {rendered_gateway} ({gateway['provenance']})")

            role = host.get("role")
            if role is not None:
                _body(pdf, f"- Rola: {role['value']} ({role['provenance']})")

            role_evidence = host.get("role_evidence")
            if role_evidence is not None:
                _body(
                    pdf,
                    f"- Dowód roli: {role_evidence['value']} ({role_evidence['provenance']})",
                )

            role_confidence = host.get("role_confidence")
            if role_confidence is not None:
                _body(
                    pdf,
                    f"- Pewność roli: {role_confidence['value']} "
                    f"({role_confidence['provenance']})",
                )
            pdf.ln(1)

    # --- Macierz komunikacji --------------------------------------------
    # Roznica formatu wobec markdown: tabela o osmiu kolumnach nie miesci sie
    # na stronie i lamalaby sie nieczytelnie, wiec kazda sesja idzie liniami
    # etykieta-wartosc (04-03-PLAN.md, Task 3).
    _heading(pdf, SECTIONS[4])
    comm_matrix = analysis.get("comm_matrix", [])
    if not comm_matrix:
        _body(pdf, "Żadna sesja TCP z ładunkiem nie została zaobserwowana w tym zrzucie.")
    else:
        for row in comm_matrix:
            direction = row.get("direction", {})
            initiator = row.get("initiator", {})
            initiator_value = initiator.get("value")
            rendered_initiator = (
                "nieustalona" if initiator_value is None else initiator_value
            )
            _body(pdf, f"Sesja: {row.get('session_id', {}).get('value', '?')}")
            _body(pdf, f"Źródło: {row.get('source', {}).get('value', '?')}")
            _body(pdf, f"Cel: {row.get('target', {}).get('value', '?')}")
            _body(
                pdf,
                f"Kierunek: {direction.get('value', '?')} "
                f"({direction.get('provenance', '?')})",
            )
            _body(pdf, f"Protokół: {row.get('protocol', {}).get('value', '?')}")
            _body(pdf, f"Wolumen (B): {row.get('volume_bytes', {}).get('value', '?')}")
            _body(pdf, f"Pakietów: {row.get('packet_count', {}).get('value', '?')}")
            _body(
                pdf,
                f"Strona inicjująca: {rendered_initiator} "
                f"({initiator.get('provenance', '?')})",
            )
            pdf.ln(1)

    # --- Ograniczenia --------------------------------------------------
    _heading(pdf, SECTIONS[5])
    for warning in warnings:
        _body(pdf, f"- {warning}")
    _body(
        pdf,
        "Ten raport pochodzi z pionowego przekroju: jeden zrzut, jeden "
        "check, jeden punkt normy. Model strefy i kanału jest placeholderem "
        "jednostrefowym wyprowadzonym automatycznie z tego zrzutu, nie "
        "zaprojektowaną topologią sieci. Numeracja punktu normy jest "
        "prowizoryczna i czeka na zestawienie z legalnym egzemplarzem normy.",
    )

    not_derivable_rows = collect_not_derivable_fields(analysis)
    if not_derivable_rows:
        _body(
            pdf,
            "Pola, których nie da się ustalić z tego zrzutu, zebrane po nazwie pola:",
        )
        for row in not_derivable_rows:
            _body(
                pdf,
                f"- sekcja `{row['section']}`, pole `{row['field']}`: "
                f"{row['count']} z {row['total']} wpisów",
            )
    else:
        _body(
            pdf,
            "W tym przebiegu każde pole sekcji inwentarza i macierzy komunikacji "
            "zostało ustalone z zaobserwowanego ruchu.",
        )

    # --- Findingi ----------------------------------------------------------
    _heading(pdf, SECTIONS[6])
    if not findings:
        _body(pdf, "Brak findingów w tym przebiegu.")
    for finding in findings:
        evidence = finding["evidence"]
        _bold_line(pdf, finding["title"])
        _body(pdf, f"- Identyfikator checka: {finding['check_id']}")
        _body(pdf, f"- Waga: {finding['severity']} (ryzyko: {finding['risk']})")
        _body(pdf, f"- {session_parties_line(evidence)}")
        _body(
            pdf,
            f"- Dowód: pakiet nr {evidence['packet_number']}, "
            f"sesja nr {evidence['session_id']}",
        )
        _body(pdf, f"- Uzasadnienie: {finding['rationale']}")
        for ref in finding["standard_refs"]:
            _body(pdf, f"- {citation_line(ref)}")
            scope_line = citation_scope_line(ref)
            if scope_line is not None:
                _body(pdf, f"  - {scope_line}")
            _body(pdf, f"  - Parafraza: {ref['paraphrase']}")
            if ref["verified"]:
                _body(pdf, "  - Status: zweryfikowane")
            else:
                _body(
                    pdf,
                    "  - Status: PROWIZORYCZNE, NIEZWERYFIKOWANE "
                    f"({ref['verification_note']})",
                )
        _body(pdf, f"- Zalecenie: {finding['remediation']}")
        pdf.ln(2)

    # --- Zalecenia -----------------------------------------------------
    _heading(pdf, SECTIONS[7])
    if not findings:
        _body(pdf, "Brak zaleceń w tym przebiegu.")
    else:
        for finding in findings:
            _body(pdf, f"- {finding['remediation']}")

    return bytes(pdf.output())
