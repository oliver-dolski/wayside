"""Eight-section markdown report rendering, with no template engine
(D-05, REPORT-01).

`SECTIONS` is a literal tuple and its order is a contract. The methodology
section renders `risk.RUBRIC_CRITERIA` so that the criteria are documented
in the product, not only in the code. No finding is a placeholder: evidence,
citation and paraphrase all come from the model handed in by the caller.
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
    "Summary",
    "Scope",
    "Methodology",
    "Asset inventory",
    "Communication matrix",
    "Limitations",
    "Findings",
    "Recommendations",
)

# Value rendered wherever a model field is present but could not be
# established from the capture. English has no grammatical gender, so a
# single form covers every field - unlike the Polish original, which needed
# three.
NOT_DETERMINED = "not determined"


# Host entry fields rendered as their own bullet with a human-readable
# label, below the generic loop over entry keys.
_HOST_FIELDS_WITH_OWN_ROW: frozenset[str] = frozenset(
    {"oui_vendor", "unit_ids", "gateway", "role", "role_evidence", "role_confidence"}
)

# Label for an own-description clause scope (G-04-3c) - it names the thing
# outright instead of softening it: the reader is meant to know this sentence
# was written by the tool's author, not by a standards committee. Shared
# between markdown and PDF (imported by `report_pdf.py`) so the shape of the
# label cannot drift between formats.
CITATION_SCOPE_LABEL = "Clause scope (own description, not a title from the copy)"


def citation_line(ref: dict) -> str:
    """Builds the standard citation line (G-04-3c).

    For copy provenance (`clause_title_source == "copy"`) it returns today's
    shape: designation, clause number, separator and clause title - in that
    case the title has been transcribed from a legal copy of the standard.
    For own provenance it returns only the opening, with no title and no
    separator: a title invented for a clause without a number must not stand
    in the same shape as a confirmed one."""
    base = f"Standard citation: {ref['standard']} {ref['clause']}"
    if ref["clause_title_source"] == "copy":
        return f"{base} - {ref['clause_title']}"
    return base


def finding_count_phrase(count: int) -> str:
    """Builds the sentence fragment stating how many findings were raised.

    The Polish original of this function carried the full inflection rule for
    countable nouns (singular, the two-to-four plural, and the genitive
    plural, with the twelve-to-fourteen exception). English needs only the
    singular/plural split, so the rule collapses to one comparison - the
    function is kept rather than inlined because it is part of the module's
    public surface and both renderers call it."""
    if count == 1:
        return f"{count} finding requiring attention"
    return f"{count} findings requiring attention"


def citation_scope_line(ref: dict) -> str | None:
    """Builds the own-description clause scope line (G-04-3c).

    Returns `None` for copy provenance - the title already stands in the
    citation line and a separate scope line would repeat it. For own
    provenance it returns a line carrying `CITATION_SCOPE_LABEL` and the
    content of the title field."""
    if ref["clause_title_source"] == "copy":
        return None
    return f"{CITATION_SCOPE_LABEL}: {ref['clause_title']}"


def finding_genitive_phrase(count: int) -> str:
    """Builds the bare count phrase used in the recommendations section,
    alongside `finding_count_phrase` (G-04-5a).

    The name is a leftover from the Polish original, where this form was
    genuinely a different grammatical case ("N findingow") rather than a
    different word. In English the two phrases differ only by the trailing
    "requiring attention", but they are still two separate call sites with
    two separate meanings, so both functions stay."""
    if count == 1:
        return f"{count} finding"
    return f"{count} findings"


def aggregated_remediations(findings: list[dict]) -> list[tuple[str, int]]:
    """Collects finding remediations without repetition (G-04-5a).

    Returns a list of (remediation text, number of findings carrying it)
    pairs, in order of the remediation's FIRST appearance in the input list.
    The pattern is identical to `checks.engine._dedupe_standards`: a counting
    dictionary plus a separate order list, never a set on the path to
    serialisation - report row order goes into an artifact compared byte for
    byte, and a set does not have it.

    Comparison runs over the FULL remediation string (assumption Z-94): two
    remediations differing only at the very end are two different
    remediations."""
    counts: dict[str, int] = {}
    order: list[str] = []
    for finding in findings:
        remediation = finding["remediation"]
        if remediation not in counts:
            order.append(remediation)
        counts[remediation] = counts.get(remediation, 0) + 1
    return [(remediation, counts[remediation]) for remediation in order]


def session_parties_line(evidence: dict) -> str:
    """Builds the line naming the parties of the session a finding concerns
    (G-04-5b): the session endpoints as source address, arrow, target
    address, taken from the endpoint pair the check engine attaches to the
    evidence. A pure function shared by markdown and PDF (`report_pdf.py`
    imports it the same way it imports `citation_line`)."""
    return f"Session parties: {evidence['source']} -> {evidence['target']}"


def render_markdown(
    analysis: dict, *, generated_at: datetime, warnings: tuple[str, ...] = ()
) -> str:
    """Renders `analysis` to markdown with plain Python functions.

    The report generation timestamp enters ONLY here, through the
    `generated_at` argument (D-02) - `analysis.json` does not carry it. The
    same holds for `warnings` (warnings from `AnalyzeResult`, e.g. a
    structurally empty capture, D-01): they enter only here and are not part
    of the `analysis.json` schema."""
    capture = analysis.get("capture", {})
    findings = analysis.get("findings", [])

    lines: list[str] = []
    lines.append("# Wayside report")
    lines.append("")
    lines.append(f"Generated: {generated_at.isoformat()}")
    lines.append("")

    lines.append(f"## {SECTIONS[0]}")
    lines.append("")
    if findings:
        lines.append(
            f"Analysis of capture `{capture.get('filename', '?')}` raised "
            f"{finding_count_phrase(len(findings))}."
        )
    else:
        lines.append(
            f"Analysis of capture `{capture.get('filename', '?')}` raised no "
            "finding in this run."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[1]}")
    lines.append("")
    # PROTO-05: the protocol list comes from the data
    # (`analysis["protocol_events"]`), not from a closed list of constants -
    # another dissector in the registry does not require changing this
    # sentence (04-RESEARCH.md, Pitfall 4).
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
    lines.append(f"{protocols_sentence} {scope_boundary_sentence}")
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
    # Zero is rendered explicitly - no truncated frames is a result of the
    # analysis, not the absence of a sentence about it (INGEST-03).
    snaplen_truncated_count = capture.get("snaplen_truncated_packet_count", 0)
    snaplen_truncated_sentence = (
        f"Frames truncated by snaplen: {snaplen_truncated_count}."
    )
    # PROTO-03: zero rendered explicitly, exactly as with the snaplen
    # truncation count above - read through .get with a fallback so that a
    # model built by hand in tests/test_report_render.py still renders.
    low_confidence_count = len(analysis.get("low_confidence_events", []))
    low_confidence_sentence = (
        f"Events recognised with low confidence: {low_confidence_count}."
    )
    lines.append(
        f"{window_sentence} {snaplen_sentence} {snaplen_truncated_sentence} "
        f"{low_confidence_sentence}"
    )
    lines.append("")

    lines.append(f"## {SECTIONS[2]}")
    lines.append("")
    lines.append(
        "Every finding carries an indicator of behaviour observed in network "
        "traffic, never a judgement on whether an installation does or does "
        "not meet the requirements of a standard. Finding severity follows "
        f"the documented rubric criteria below (version {risk.RUBRIC_VERSION}), "
        "not an invented scale:"
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
        lines.append("No IP-layer host was observed in this capture.")
        lines.append("")
    else:
        for host in assets:
            ip_field = host["ip"]
            lines.append(f"### {ip_field['value']}")
            lines.append("")
            for field_name, field_value in host.items():
                # Fields with their own bullets below (ASSET-02, ASSET-04 to
                # ASSET-07) are excluded from this generic loop so they are
                # not rendered twice - once under the key name, once under a
                # human-readable label.
                if field_name in _HOST_FIELDS_WITH_OWN_ROW:
                    continue
                value = field_value["value"]
                provenance = field_value["provenance"]
                rendered_value = NOT_DETERMINED if value is None else value
                lines.append(f"- {field_name}: {rendered_value} ({provenance})")
            # Read through .get with missing-key handling so that a model
            # built by hand in tests/test_report_render.py still renders.
            oui_vendor = host.get("oui_vendor")
            if oui_vendor is not None:
                vendor_value = oui_vendor["value"]
                vendor_provenance = oui_vendor["provenance"]
                rendered_vendor = (
                    NOT_DETERMINED if vendor_value is None else vendor_value
                )
                lines.append(f"- Vendor: {rendered_vendor} ({vendor_provenance})")

            unit_ids = host.get("unit_ids")
            if unit_ids is not None:
                unit_ids_value = unit_ids["value"]
                rendered_unit_ids = (
                    NOT_DETERMINED
                    if unit_ids_value is None
                    else ", ".join(str(unit_id) for unit_id in unit_ids_value)
                )
                lines.append(
                    f"- Unit ID sub-addresses: {rendered_unit_ids} "
                    f"({unit_ids['provenance']})"
                )

            gateway = host.get("gateway")
            if gateway is not None:
                if gateway["value"]:
                    # The number of logical devices is derived from the length
                    # of the same host's sub-address list, not from a separate
                    # model field: one source for this number, two uses of it.
                    logical_devices = len((unit_ids or {}).get("value") or [])
                    rendered_gateway = (
                        f"probable gateway with {logical_devices} logical "
                        "device(s) behind it"
                    )
                else:
                    # On a `null` value we do NOT render a sentence saying the
                    # host is not a gateway (assumption Z-25): that is the same
                    # trap as a `false` value in the model, moved into prose.
                    rendered_gateway = NOT_DETERMINED
                lines.append(f"- Gateway: {rendered_gateway} ({gateway['provenance']})")

            role = host.get("role")
            if role is not None:
                lines.append(f"- Role: {role['value']} ({role['provenance']})")

            # Role evidence stands DIRECTLY under the role: a label without
            # its accompanying evidence in the same place is the signal an
            # experienced reviewer looks for first (PITFALLS.md, Pitfall 9).
            role_evidence = host.get("role_evidence")
            if role_evidence is not None:
                lines.append(
                    f"- Role evidence: {role_evidence['value']} "
                    f"({role_evidence['provenance']})"
                )

            role_confidence = host.get("role_confidence")
            if role_confidence is not None:
                lines.append(
                    f"- Role confidence: {role_confidence['value']} "
                    f"({role_confidence['provenance']})"
                )
            lines.append("")

    lines.append(f"## {SECTIONS[4]}")
    lines.append("")
    comm_matrix = analysis.get("comm_matrix", [])
    if not comm_matrix:
        lines.append("No TCP session carrying payload was observed in this capture.")
        lines.append("")
    else:
        # A table is the right shape here, unlike in the inventory: eight
        # columns of short values read well in a row, and comparing sessions
        # against each other is the whole content of the matrix. The
        # provenance marker stands next to direction and next to the
        # initiating party, that is where telling an observation from an
        # inference changes the reading; purely numeric columns marked
        # `observed` carry no marker, so the table stays readable.
        lines.append(
            "| Session | Source | Target | Direction | Protocol | Volume (B) | "
            "Packets | Initiating party |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for row in comm_matrix:
            direction = row.get("direction", {})
            initiator = row.get("initiator", {})
            initiator_value = initiator.get("value")
            rendered_initiator = (
                NOT_DETERMINED if initiator_value is None else initiator_value
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
        "This report comes from a vertical slice: one capture, one check, one "
        "standard clause. The zone and conduit model is a single-zone "
        "placeholder derived automatically from this capture, not a designed "
        "network topology. Standard clause numbering is provisional and "
        "awaits collation against a legal copy of the standard."
    )
    lines.append("")

    # REPORT-02: the list of not-derivable fields is produced from THIS
    # model, not from a hand-written list - adding a new inventory or matrix
    # field lands here on its own, with no change to the rendering layer.
    not_derivable_rows = collect_not_derivable_fields(analysis)
    if not_derivable_rows:
        lines.append(
            "Fields that cannot be established from this capture, grouped by "
            "field name:"
        )
        lines.append("")
        for row in not_derivable_rows:
            lines.append(
                f"- section `{row['section']}`, field `{row['field']}`: "
                f"{row['count']} of {row['total']} entries"
            )
    else:
        lines.append(
            "In this run every field of the inventory and communication "
            "matrix sections was established from observed traffic."
        )
    lines.append("")

    lines.append(f"## {SECTIONS[6]}")
    lines.append("")
    if not findings:
        lines.append("No findings in this run.")
        lines.append("")
    for finding in findings:
        evidence = finding["evidence"]
        lines.append(f"### {finding['title']}")
        lines.append("")
        lines.append(f"- Check identifier: `{finding['check_id']}`")
        lines.append(f"- Severity: {finding['severity']} (risk: {finding['risk']})")
        lines.append(f"- {session_parties_line(evidence)}")
        lines.append(
            f"- Evidence: packet no. {evidence['packet_number']}, "
            f"session no. {evidence['session_id']}"
        )
        lines.append(f"- Rationale: {finding['rationale']}")
        for ref in finding["standard_refs"]:
            lines.append(f"- {citation_line(ref)}")
            scope_line = citation_scope_line(ref)
            if scope_line is not None:
                lines.append(f"  - {scope_line}")
            lines.append(f"  - Paraphrase: {ref['paraphrase']}")
            if ref["verified"]:
                lines.append("  - Status: verified")
            else:
                lines.append(
                    "  - Status: **PROVISIONAL, UNVERIFIED** "
                    f"({ref['verification_note']})"
                )
        lines.append(f"- Remediation: {finding['remediation']}")
        lines.append("")

    lines.append(f"## {SECTIONS[7]}")
    lines.append("")
    if not findings:
        lines.append("No recommendations in this run.")
    else:
        for remediation, count in aggregated_remediations(findings):
            lines.append(
                f"- {remediation} (applies to {finding_genitive_phrase(count)})"
            )
    lines.append("")

    return "\n".join(lines) + "\n"
