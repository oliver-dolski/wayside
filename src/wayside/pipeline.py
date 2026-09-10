"""Orchestration of the whole pipeline: from a pcap file to two artifacts,
`analysis.json` and `report.md` (REPORT-04).

The markdown report is rendered from EXACTLY the same dictionary that was
serialised into `analysis.json` - not from a second representation.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from wayside import coverage, decode, flow, report, risk, zones
from wayside.assets import inventory, oui
from wayside.checks import engine as checks_engine
from wayside.model import (
    Evidence,
    Finding,
    assert_provenance_complete,
    build_analysis,
    dump_deterministic,
    write_atomic,
)
from wayside.pcap import CaptureStructure, audit_capture_structure, read_capture
from wayside.protocols import registry as protocol_registry
from wayside.standards import mapper as standards_mapper

__all__ = ["AnalyzeResult", "analyze"]


@dataclass(frozen=True)
class AnalyzeResult:
    analysis: dict
    report_markdown: str
    warnings: tuple[str, ...]
    analysis_path: Path
    report_path: Path


def _build_capture_section(
    pcap_path: Path, packets, capture_structure: CaptureStructure
) -> dict:
    """Builds the `capture` section. It carries `filename` (just
    `pcap_path.name`), NOT the full path - a full path is a function of the
    directory the process was started from, so two runs from different
    working directories would produce different `analysis.json` bytes
    despite identical analytical content (REPORT-06). `sha256` makes it
    possible to tie the report to a specific input file (threat T-2-07) - it
    is a function of the file's CONTENT, not its location, so it breaks
    determinism neither across directories nor across machines.
    `snaplen`/`snaplen_note` come from `capture_structure`, already computed
    by the D-01 gate - `analyze` does not run the audit a second time
    (INGEST-02)."""
    sha256 = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    if len(packets) == 0:
        first_seen = None
        last_seen = None
    else:
        timestamps = sorted(float(pkt.time) for pkt in packets)
        first_seen = timestamps[0]
        last_seen = timestamps[-1]
    snaplen_truncated_numbers = capture_structure.snaplen_truncated_packet_numbers
    return {
        "filename": pcap_path.name,
        "sha256": sha256,
        "packet_count": len(packets),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "snaplen": capture_structure.snaplen,
        "snaplen_note": capture_structure.snaplen_note,
        "snaplen_truncated_packet_count": len(snaplen_truncated_numbers),
        "snaplen_truncated_first_packet_number": (
            snaplen_truncated_numbers[0] if snaplen_truncated_numbers else None
        ),
    }


def _build_conversations(segments: list[decode.Segment]) -> list[dict]:
    conversations: dict[int, dict] = {}
    order: list[int] = []
    for segment in segments:
        if segment.session_id not in conversations:
            conversations[segment.session_id] = {
                "session_id": segment.session_id,
                "endpoints": sorted(
                    {
                        f"{segment.src_ip}:{segment.src_port}",
                        f"{segment.dst_ip}:{segment.dst_port}",
                    }
                ),
                "packet_count": 0,
            }
            order.append(segment.session_id)
        conversations[segment.session_id]["packet_count"] += 1
    return [conversations[session_id] for session_id in order]


def analyze(pcap_path: Path, *, out_dir: Path, generated_at: datetime) -> AnalyzeResult:
    """Runs the pipeline steps in order: structural audit (gate D-01),
    capture read, decoding, Modbus dissection, the Modbus RTU over TCP
    discriminator over the same segment list (PROTO-03), host inventory
    construction over segments and over serialised events (ASSET-04,
    ASSET-05), the communication matrix over packets, segments, events and
    session initiators (FLOW-01, FLOW-02), the provenance gate over the
    inventory and over the matrix (Z-02), the zone model, polling interval
    measurement and capture window coverage assessment (INGEST-04), the
    analysis model without findings, the check engine, resolution of
    standard citations, risk assignment, writing `analysis.json`, rendering
    and writing `report.md`."""
    pcap_path = Path(pcap_path)
    out_dir = Path(out_dir)

    # Gate D-01: structural audit BEFORE any write or decoding. A truncated
    # capture or one in an unknown format (CaptureTruncatedError /
    # CaptureFormatError) never reaches the pipeline at all, so no partial
    # artifact is created - the same split-gate shape as
    # `scripts/confidentiality_guard.py`.
    capture_structure = audit_capture_structure(pcap_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    packets = read_capture(pcap_path)
    segments = decode.decode_segments(packets)
    # FLOW-02: a pass over ALL packets, not over segments - the packet
    # opening a connection carries no payload, so it is not among segments.
    session_initiators = decode.find_session_initiators(packets, segments)
    # PROTO-05: protocol recognition enters exclusively through the registry
    # - this module refers to no specific protocol. `run_dissectors` calls
    # every dissector discovered in the registry over THE SAME segment list;
    # mutual exclusion between native Modbus/TCP and RTU-over-TCP
    # recognition is a property of the dissectors (assumption Z-17), not of
    # the call order here.
    dissectors = protocol_registry.discover_dissectors()
    protocol_events, low_confidence_events = protocol_registry.run_dissectors(
        segments, dissectors
    )

    warnings: list[str] = []
    if capture_structure.is_structurally_empty:
        # D-01: an empty capture is a legal capture, never rejected as an
        # error - but silence about it would be a silent, confident answer.
        warnings.append(
            "The capture is structurally valid and contains no packets at "
            "all - the absence of findings in this run is not a result of "
            "the analysis, only an absence of material."
        )
    elif not protocol_events:
        warnings.append(
            "No segment in this capture was recognised by any dissector in "
            "the registry - this run carries no application protocol traffic "
            "to analyse."
        )
    if capture_structure.snaplen_truncated_packet_numbers:
        # INGEST-03: a frame truncated by snaplen does not carry the full
        # payload, so the absence of a protocol event in this capture is not
        # proof of that protocol's absence - the tool says so outright, never
        # with a silent, green answer. A declarative sentence, with no modal
        # term on a line carrying a number (scripts/confidentiality_guard.py,
        # structural layer).
        truncated_numbers = capture_structure.snaplen_truncated_packet_numbers
        warnings.append(
            f"A snaplen set to {capture_structure.snaplen} bytes truncated "
            f"{len(truncated_numbers)} of {len(packets)} frames in this "
            f"capture, the first truncated frame being number "
            f"{truncated_numbers[0]}. A truncated frame does not carry the "
            "full payload, functional protocol analysis on this capture is "
            "falsified, and the absence of a protocol event is not proof of "
            "that protocol's absence."
        )
    if low_confidence_events:
        # PROTO-03: an event recognised with low confidence stands outside
        # the protocol event list and outside every finding - the tool names
        # the number of such events, the protocol(s) and the basis of
        # recognition, without referring to a constant of one specific
        # dissector (assumption Z-18, threat T-3-13).
        low_confidence_protocols = ", ".join(
            sorted({event["protocol"] for event in low_confidence_events})
        )
        low_confidence_bases = ", ".join(
            sorted({event["basis"] for event in low_confidence_events})
        )
        warnings.append(
            f"{len(low_confidence_events)} event(s) in this capture are "
            f"recognised with low confidence as {low_confidence_protocols}, "
            f"on the basis of {low_confidence_bases}, outside the protocol "
            "event list and outside every finding. This recognition carries "
            "the possibility of a false checksum match on traffic that is "
            "not Modbus."
        )

    observed_ips = sorted(
        {segment.src_ip for segment in segments} | {segment.dst_ip for segment in segments}
    )
    observed_protocols = sorted({event["protocol"] for event in protocol_events})
    zone_model = zones.build_zone_model(
        observed_ips=observed_ips, observed_protocols=observed_protocols
    )

    conversations = _build_conversations(segments)

    capture_section = _build_capture_section(pcap_path, packets, capture_structure)
    # Rounding to six decimal places removes floating point representation
    # noise (the difference of two timestamps gives e.g. 5.009999990463257
    # instead of 5.01) - the same convention as formatting the window length
    # in the `inspect` command (assumption Z-15).
    window_duration_s = (
        round(capture_section["last_seen"] - capture_section["first_seen"], 6)
        if capture_section["first_seen"] is not None
        and capture_section["last_seen"] is not None
        else None
    )
    polling_cycles = coverage.measure_polling_cycles(protocol_events)
    coverage_section = coverage.build_coverage_section(
        cycles=polling_cycles, window_duration_s=window_duration_s
    )
    # INGEST-04: a capture too short against the measured polling interval
    # ends with a warning carrying both numbers, never with a silent, green
    # answer - the same discipline as the snaplen warning above.
    warnings.extend(
        coverage.coverage_warnings(cycles=polling_cycles, window_duration_s=window_duration_s)
    )

    # ASSET-02: the OUI vendor table is loaded EXACTLY ONCE per run, BEFORE
    # the inventory is built - the file has tens of thousands of rows, and a
    # read per host would turn linear work into quadratic. Failure
    # (assumption Z-21) gives a vendor_lookup equal to None and an EXPLICIT
    # warning - never a silent undetermined field, which would look identical
    # to a field undetermined because the MAC address was locally
    # administered or absent.
    try:
        oui_table = oui.load_oui_table()
    except oui.OuiTableError:
        vendor_lookup = None
        warnings.append(
            "The OUI vendor table is not bundled with this release of the "
            "tool - the vendor field is undetermined for every host in this "
            "run, regardless of whether its MAC address was visible."
        )
    else:

        def vendor_lookup(mac: str) -> str | None:
            return oui.lookup_vendor(mac, oui_table)

    # ASSET-04/ASSET-05: `events` is `protocol_events`, that is events
    # ALREADY serialised. The order of steps is a contract here - inventory
    # construction goes AFTER `dissect_all` and after serialisation, because
    # the Unit ID under a server address comes from events, not from the
    # segments alone.
    assets = inventory.build_assets(
        segments=segments, events=protocol_events, vendor_lookup=vendor_lookup
    )
    # The provenance gate stands at the data producer, BEFORE serialisation
    # (T-3-04): an inventory field without a provenance marker never reaches
    # `analysis.json`. The gate's scope is the `assets` section, not the
    # whole `analysis` tree (assumption Z-02) - fields from Phases 1-2 are
    # not a regression.
    assert_provenance_complete(assets, path="assets")

    comm_matrix = flow.build_comm_matrix(
        packets=packets,
        segments=segments,
        events=protocol_events,
        low_confidence_events=low_confidence_events,
        initiators=session_initiators,
    )
    assert_provenance_complete(comm_matrix, path="comm_matrix")

    # FLOW-03: TCP sessions made up EXCLUSIVELY of packets without payload
    # have no row in the matrix (assumption Z-31), so without being counted
    # they would vanish without a trace. Canonical keys from packets that are
    # absent from the keys built out of segments.
    session_keys_with_payload = {
        decode._canonical_session_key(
            segment.src_ip, segment.src_port, segment.dst_ip, segment.dst_port
        )
        for segment in segments
    }
    payloadless_session_keys: set[str] = set()
    for pkt in packets:
        if not pkt.haslayer(decode.IP) or not pkt.haslayer(decode.TCP):
            continue
        tcp_layer = pkt[decode.TCP]
        key = decode._canonical_session_key(
            str(pkt[decode.IP].src),
            int(tcp_layer.sport),
            str(pkt[decode.IP].dst),
            int(tcp_layer.dport),
        )
        if key not in session_keys_with_payload:
            payloadless_session_keys.add(key)

    # The order of warnings in the limitations section is deterministic:
    # the blind spot sentences go AFTER the warnings from plans 03-03, 03-04
    # and 03-05, and that order is fixed once.
    warnings.extend(
        flow.vantage_point_limitations(
            host_count=len(assets),
            session_count=len(comm_matrix),
            payloadless_session_count=len(payloadless_session_keys),
            window_duration_s=window_duration_s,
        )
    )

    methodology = {
        "rubric_version": risk.RUBRIC_VERSION,
        "note": (
            "Finding severity follows the recorded rubric criteria, not an "
            "invented scale (RISK-03)."
        ),
    }

    analysis = build_analysis(
        capture=capture_section,
        conversations=conversations,
        protocol_events=protocol_events,
        zone_model=zone_model,
        findings=[],
        methodology=methodology,
        assets=assets,
        coverage=coverage_section,
        low_confidence_events=low_confidence_events,
        comm_matrix=comm_matrix,
    )

    checks = checks_engine.discover_checks()
    raw_findings = checks_engine.run_checks(analysis, checks)

    resolved_findings: list[dict] = []
    for raw in raw_findings:
        standard_refs = tuple(
            standards_mapper.resolve(ref["standard"], ref["clause"], zone_model=zone_model)
            for ref in raw["standards"]
        )
        finding = Finding(
            check_id=raw["check_id"],
            title=raw["title"],
            severity=raw["severity"],
            risk=risk.severity_to_risk(raw["severity"]),
            rationale=raw["rationale"],
            standard_refs=standard_refs,
            evidence=Evidence(
                packet_number=raw["evidence"]["packet_number"],
                session_id=raw["evidence"]["session_id"],
                source=raw["evidence"]["source"],
                target=raw["evidence"]["target"],
            ),
            remediation=raw["remediation"],
        )
        resolved_findings.append(dataclasses.asdict(finding))

    analysis["findings"] = resolved_findings

    analysis_text = dump_deterministic(analysis)
    analysis_path = out_dir / "analysis.json"
    write_atomic(analysis_path, analysis_text)

    report_markdown = report.render_markdown(
        analysis, generated_at=generated_at, warnings=tuple(warnings)
    )
    report_path = out_dir / "report.md"
    write_atomic(report_path, report_markdown)

    return AnalyzeResult(
        analysis=analysis,
        report_markdown=report_markdown,
        warnings=tuple(warnings),
        analysis_path=analysis_path,
        report_path=report_path,
    )
