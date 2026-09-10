"""Rendering the report to PDF with an embedded Unicode font, straight from
the analysis model dictionary - with no template engine (D-05, assumption
Z-56, the same principle as `report.py`).

Five things this module carries which MUST stay true through every edit.

1. Rendering goes from THE SAME model dictionary the markdown is produced
   from (`render_markdown`), NEVER from parsing the markdown text back - that
   is one source of truth for the finding list in both formats (REPORT-03,
   `04-RESEARCH.md` Anti-Patterns). This module imports from `wayside.report`
   only the `SECTIONS` tuple and the pure functions building citation lines
   (`citation_line`, `citation_scope_line`) - never loop logic and never
   state.
2. No template engine (D-05, assumption Z-56): content is assembled by
   calling the `fpdf2` library directly, with no Jinja2 or other templater -
   the same discipline as `report.py`.
3. The generation timestamp enters EXCLUSIVELY through the caller's
   `generated_at` argument (D-02, assumption Z-54) - this module never reads
   the system clock, which is the condition for byte determinism between two
   runs in separate processes (04-RESEARCH.md, Pitfall 7).
4. All PDF document metadata (title, author, creator, producer) are module
   constants in `PDF_METADATA` (assumption Z-54) - no field carries the
   system user name or the machine name, because the artifact is sent to a
   client.
5. The font is embedded from the package directory (`assets/fonts/`,
   assumption Z-52). DejaVu Sans is chosen for two reasons: broad coverage of
   characters outside ASCII, which the report does carry (vendor names from
   the OUI table are the routine case), and a licence permitting
   redistribution in a public repository - a system font is rejected because
   its path is not reproducible between machines.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fpdf import FPDF

from wayside import risk
from wayside.flow import PROTOCOL_UNRECOGNIZED
from wayside.model import collect_not_derivable_fields
from wayside.report import (
    NOT_DETERMINED,
    SECTIONS,
    aggregated_remediations,
    citation_line,
    citation_scope_line,
    finding_count_phrase,
    finding_genitive_phrase,
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

# Constants (assumption Z-54): no field carries the system user name or the
# machine name - an artifact sent to a client must not reveal the author's
# environment. The document creation date is NOT here - it enters from the
# `generated_at` argument through `set_creation_date`.
PDF_METADATA: dict[str, str] = {
    "title": "Wayside report",
    "author": "Wayside",
    "creator": "Wayside",
    "producer": "Wayside",
}

# Host entry fields rendered as their own bullet with a human-readable
# label, below the generic loop over entry keys - a mirror of
# `report._HOST_FIELDS_WITH_OWN_ROW` (private in that module, so this module
# carries its own copy rather than an import: two independent renderers of
# the same model, not one importing the other's internal symbol).
_HOST_FIELDS_WITH_OWN_ROW: frozenset[str] = frozenset(
    {"oui_vendor", "unit_ids", "gateway", "role", "role_evidence", "role_confidence"}
)

_HEADING_SIZE = 13
_BODY_SIZE = 10
_TITLE_SIZE = 16
_LINE_HEIGHT = 5.5
_HEADING_LINE_HEIGHT = 8


class PdfRenderError(Exception):
    """Raised in two cases: a missing font file required for rendering
    (checked BEFORE document construction starts) and a failure to embed the
    font in the document."""


def _require_font_files() -> None:
    for path in (FONT_REGULAR_PATH, FONT_BOLD_PATH):
        if not path.is_file():
            raise PdfRenderError(
                f"Missing font file required for PDF rendering: {path}"
            )


def _heading(pdf: FPDF, text: str) -> None:
    pdf.set_font(FONT_FAMILY, style="b", size=_HEADING_SIZE)
    pdf.multi_cell(0, _HEADING_LINE_HEIGHT, text, align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _body(pdf: FPDF, text: str, *, wrapmode: str = "WORD") -> None:
    # `align="L"` explicitly - the default for `multi_cell` is justified
    # (Align.J), and justification distributes extra spaces between words in
    # a way that depends on line width. The text layer extracted by
    # `pypdf.extract_text()` reflects those extra spaces (single or double,
    # depending on the line), which breaks every substring comparison
    # spanning more than one word - left alignment removes that failure mode
    # entirely, at a cost in aesthetics that the machine gate does not see.
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
    """Renders `analysis` to PDF. The signature is IDENTICAL to
    `report.render_markdown` - the same argument names, the same `warnings`
    default. The report generation timestamp enters EXCLUSIVELY here, through
    the `generated_at` argument (D-02) - `analysis.json` does not carry it.
    Returns the bytes of the finished PDF document."""
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
    pdf.multi_cell(0, 9, "Wayside report", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(FONT_FAMILY, style="", size=_BODY_SIZE)
    pdf.multi_cell(
        0, _LINE_HEIGHT, f"Generated: {generated_at.isoformat()}",
        align="L", new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(2)

    # --- Summary ------------------------------------------------------
    _heading(pdf, SECTIONS[0])
    if findings:
        _body(
            pdf,
            f"Analysis of capture `{capture.get('filename', '?')}` raised "
            f"{finding_count_phrase(len(findings))}.",
        )
    else:
        _body(
            pdf,
            f"Analysis of capture `{capture.get('filename', '?')}` raised no "
            "finding in this run.",
        )

    # --- Scope --------------------------------------------------------
    _heading(pdf, SECTIONS[1])
    # PROTO-05: the protocol list comes from the data, not from a closed
    # list of constants - the same principle as `report.render_markdown`.
    recognized_protocols = sorted(
        {event["protocol"] for event in analysis.get("protocol_events", [])}
    )
    if recognized_protocols:
        protocols_sentence = (
            f"The capture carries {capture.get('packet_count', 0)} packets. "
            f"Protocol(s) recognised in this capture: "
            f"{', '.join(recognized_protocols)}, recognised by the shape of "
            "the segment payload, never by port number."
        )
    else:
        protocols_sentence = (
            f"The capture carries {capture.get('packet_count', 0)} packets. "
            "No application protocol was recognised in this capture; "
            "recognition goes by the shape of the segment payload, never by "
            "port number."
        )
    scope_boundary_sentence = (
        "Traffic whose protocol was not recognised has a row in the "
        f"communication matrix labelled `{PROTOCOL_UNRECOGNIZED}` and is not "
        "the basis of any finding."
    )
    _body(pdf, f"{protocols_sentence} {scope_boundary_sentence}")

    first_seen = capture.get("first_seen")
    last_seen = capture.get("last_seen")
    if first_seen is not None and last_seen is not None:
        window_sentence = (
            f"Capture time window: from {first_seen} to {last_seen} "
            "(Unix epoch timestamps)."
        )
    else:
        window_sentence = (
            "The capture time window was not established - the capture "
            "contains no packets at all."
        )
    snaplen = capture.get("snaplen")
    if snaplen is not None:
        snaplen_sentence = f"Snaplen read from the capture header: {snaplen} bytes."
    else:
        snaplen_note = capture.get("snaplen_note") or (
            "snaplen was not unambiguously established"
        )
        snaplen_sentence = (
            f"Snaplen was not unambiguously established ({snaplen_note})."
        )
    snaplen_truncated_count = capture.get("snaplen_truncated_packet_count", 0)
    snaplen_truncated_sentence = (
        f"Frames truncated by snaplen: {snaplen_truncated_count}."
    )
    low_confidence_count = len(analysis.get("low_confidence_events", []))
    low_confidence_sentence = (
        f"Events recognised with low confidence: {low_confidence_count}."
    )
    _body(
        pdf,
        f"{window_sentence} {snaplen_sentence} {snaplen_truncated_sentence} "
        f"{low_confidence_sentence}",
    )

    # --- Methodology --------------------------------------------------
    _heading(pdf, SECTIONS[2])
    _body(
        pdf,
        "Every finding carries an indicator of behaviour observed in network "
        "traffic, never a judgement on whether an installation does or does "
        "not meet the requirements of a standard. Finding severity follows "
        f"the documented rubric criteria below (version {risk.RUBRIC_VERSION}), "
        "not an invented scale:",
    )
    for severity in risk.ALLOWED_SEVERITIES:
        criterion = risk.RUBRIC_CRITERIA.get(severity, "")
        _body(pdf, f"- {severity}: {criterion}")

    # --- Asset inventory ----------------------------------------------
    _heading(pdf, SECTIONS[3])
    assets = analysis.get("assets", [])
    if not assets:
        _body(pdf, "No IP-layer host was observed in this capture.")
    else:
        for host in assets:
            ip_field = host["ip"]
            _bold_line(pdf, str(ip_field["value"]))
            for field_name, field_value in host.items():
                if field_name in _HOST_FIELDS_WITH_OWN_ROW:
                    continue
                value = field_value["value"]
                provenance = field_value["provenance"]
                rendered_value = NOT_DETERMINED if value is None else value
                _body(pdf, f"- {field_name}: {rendered_value} ({provenance})")

            oui_vendor = host.get("oui_vendor")
            if oui_vendor is not None:
                vendor_value = oui_vendor["value"]
                vendor_provenance = oui_vendor["provenance"]
                rendered_vendor = (
                    NOT_DETERMINED if vendor_value is None else vendor_value
                )
                _body(pdf, f"- Vendor: {rendered_vendor} ({vendor_provenance})")

            unit_ids = host.get("unit_ids")
            if unit_ids is not None:
                unit_ids_value = unit_ids["value"]
                rendered_unit_ids = (
                    NOT_DETERMINED
                    if unit_ids_value is None
                    else ", ".join(str(unit_id) for unit_id in unit_ids_value)
                )
                _body(
                    pdf,
                    f"- Unit ID sub-addresses: {rendered_unit_ids} "
                    f"({unit_ids['provenance']})",
                )

            gateway = host.get("gateway")
            if gateway is not None:
                if gateway["value"]:
                    logical_devices = len((unit_ids or {}).get("value") or [])
                    rendered_gateway = (
                        f"probable gateway with {logical_devices} logical "
                        "device(s) behind it"
                    )
                else:
                    rendered_gateway = NOT_DETERMINED
                _body(pdf, f"- Gateway: {rendered_gateway} ({gateway['provenance']})")

            role = host.get("role")
            if role is not None:
                _body(pdf, f"- Role: {role['value']} ({role['provenance']})")

            role_evidence = host.get("role_evidence")
            if role_evidence is not None:
                _body(
                    pdf,
                    f"- Role evidence: {role_evidence['value']} "
                    f"({role_evidence['provenance']})",
                )

            role_confidence = host.get("role_confidence")
            if role_confidence is not None:
                _body(
                    pdf,
                    f"- Role confidence: {role_confidence['value']} "
                    f"({role_confidence['provenance']})",
                )
            pdf.ln(1)

    # --- Communication matrix -------------------------------------------
    # A format difference against the markdown: a table of eight columns does
    # not fit the page and would wrap illegibly, so each session goes as
    # label-value lines (04-03-PLAN.md, Task 3).
    _heading(pdf, SECTIONS[4])
    comm_matrix = analysis.get("comm_matrix", [])
    if not comm_matrix:
        _body(pdf, "No TCP session carrying payload was observed in this capture.")
    else:
        for row in comm_matrix:
            direction = row.get("direction", {})
            initiator = row.get("initiator", {})
            initiator_value = initiator.get("value")
            rendered_initiator = (
                NOT_DETERMINED if initiator_value is None else initiator_value
            )
            _body(pdf, f"Session: {row.get('session_id', {}).get('value', '?')}")
            _body(pdf, f"Source: {row.get('source', {}).get('value', '?')}")
            _body(pdf, f"Target: {row.get('target', {}).get('value', '?')}")
            _body(
                pdf,
                f"Direction: {direction.get('value', '?')} "
                f"({direction.get('provenance', '?')})",
            )
            _body(pdf, f"Protocol: {row.get('protocol', {}).get('value', '?')}")
            _body(pdf, f"Volume (B): {row.get('volume_bytes', {}).get('value', '?')}")
            _body(pdf, f"Packets: {row.get('packet_count', {}).get('value', '?')}")
            _body(
                pdf,
                f"Initiating party: {rendered_initiator} "
                f"({initiator.get('provenance', '?')})",
            )
            pdf.ln(1)

    # --- Limitations ----------------------------------------------------
    _heading(pdf, SECTIONS[5])
    for warning in warnings:
        _body(pdf, f"- {warning}")
    _body(
        pdf,
        "This report comes from a vertical slice: one capture, one check, one "
        "standard clause. The zone and conduit model is a single-zone "
        "placeholder derived automatically from this capture, not a designed "
        "network topology. Standard clause numbering is provisional and "
        "awaits collation against a legal copy of the standard.",
    )

    not_derivable_rows = collect_not_derivable_fields(analysis)
    if not_derivable_rows:
        _body(
            pdf,
            "Fields that cannot be established from this capture, grouped by "
            "field name:",
        )
        for row in not_derivable_rows:
            _body(
                pdf,
                f"- section `{row['section']}`, field `{row['field']}`: "
                f"{row['count']} of {row['total']} entries",
            )
    else:
        _body(
            pdf,
            "In this run every field of the inventory and communication "
            "matrix sections was established from observed traffic.",
        )

    # --- Findings -------------------------------------------------------
    _heading(pdf, SECTIONS[6])
    if not findings:
        _body(pdf, "No findings in this run.")
    for finding in findings:
        evidence = finding["evidence"]
        _bold_line(pdf, finding["title"])
        _body(pdf, f"- Check identifier: {finding['check_id']}")
        _body(pdf, f"- Severity: {finding['severity']} (risk: {finding['risk']})")
        _body(pdf, f"- {session_parties_line(evidence)}")
        _body(
            pdf,
            f"- Evidence: packet no. {evidence['packet_number']}, "
            f"session no. {evidence['session_id']}",
        )
        _body(pdf, f"- Rationale: {finding['rationale']}")
        for ref in finding["standard_refs"]:
            _body(pdf, f"- {citation_line(ref)}")
            scope_line = citation_scope_line(ref)
            if scope_line is not None:
                _body(pdf, f"  - {scope_line}")
            _body(pdf, f"  - Paraphrase: {ref['paraphrase']}")
            if ref["verified"]:
                _body(pdf, "  - Status: verified")
            else:
                _body(
                    pdf,
                    "  - Status: PROVISIONAL, UNVERIFIED "
                    f"({ref['verification_note']})",
                )
        _body(pdf, f"- Remediation: {finding['remediation']}")
        pdf.ln(2)

    # --- Recommendations -------------------------------------------------
    _heading(pdf, SECTIONS[7])
    if not findings:
        _body(pdf, "No recommendations in this run.")
    else:
        for remediation, count in aggregated_remediations(findings):
            _body(pdf, f"- {remediation} (applies to {finding_genitive_phrase(count)})")

    return bytes(pdf.output())
