"""Orkiestracja calego potoku: od pliku pcap do dwoch artefaktow,
`analysis.json` i `report.md` (REPORT-04).

Raport markdown jest renderowany z DOKLADNIE tego samego slownika, ktory
zostal zserializowany do `analysis.json` - nie z drugiej reprezentacji.
"""

from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from wayside import decode, report, risk, zones
from wayside.checks import engine as checks_engine
from wayside.model import (
    Evidence,
    Finding,
    build_analysis,
    dump_deterministic,
    write_atomic,
)
from wayside.pcap import audit_capture_structure, read_capture
from wayside.protocols import modbus_tcp
from wayside.standards import mapper as standards_mapper

__all__ = ["AnalyzeResult", "analyze"]


@dataclass(frozen=True)
class AnalyzeResult:
    analysis: dict
    report_markdown: str
    warnings: tuple[str, ...]
    analysis_path: Path
    report_path: Path


def _build_capture_section(pcap_path: Path, packets) -> dict:
    """Buduje sekcje `capture`. Niesie `filename` (samo `pcap_path.name`),
    NIE pelna sciezke - pelna sciezka jest funkcja katalogu uruchomienia
    procesu, wiec dwa przebiegi z roznych katalogow roboczych dawalyby
    rozne bajty `analysis.json` mimo identycznej tresci analitycznej
    (REPORT-06). `sha256` niesie mozliwosc powiazania raportu z konkretnym
    plikiem wejsciowym (zagrozenie T-2-07) - jest funkcja TRESCI pliku, nie
    jego polozenia, wiec nie lamie determinizmu ani miedzy katalogami, ani
    miedzy maszynami."""
    sha256 = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    if len(packets) == 0:
        first_seen = None
        last_seen = None
    else:
        timestamps = sorted(float(pkt.time) for pkt in packets)
        first_seen = timestamps[0]
        last_seen = timestamps[-1]
    return {
        "filename": pcap_path.name,
        "sha256": sha256,
        "packet_count": len(packets),
        "first_seen": first_seen,
        "last_seen": last_seen,
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
    """Wykonuje kroki potoku w kolejnosci: audyt strukturalny (brama D-01),
    odczyt zrzutu, dekodowanie, dysekcja Modbus, model strefy, model analizy
    bez findingow, silnik checkow, rozwiazanie powolan na norme, przypisanie
    ryzyka, zapis `analysis.json`, renderowanie i zapis `report.md`."""
    pcap_path = Path(pcap_path)
    out_dir = Path(out_dir)

    # Brama D-01: audyt strukturalny PRZED jakimkolwiek zapisem albo
    # dekodowaniem. Zrzut obciety albo o nieznanym formacie (CaptureTruncated
    # Error/CaptureFormatError) nie dochodzi do potoku wcale, wiec zaden
    # czesciowy artefakt nie powstaje - ten sam ksztalt rozdzielonej bramki
    # co `scripts/confidentiality_guard.py`.
    capture_structure = audit_capture_structure(pcap_path)

    out_dir.mkdir(parents=True, exist_ok=True)

    packets = read_capture(pcap_path)
    segments = decode.decode_segments(packets)
    events = modbus_tcp.dissect_all(segments)

    warnings: list[str] = []
    if capture_structure.is_structurally_empty:
        # D-01: zrzut pusty jest zrzutem legalnym, nigdy odrzucanym jako
        # blad - ale cisza na jego temat bylaby cicha, pewna odpowiedzia.
        warnings.append(
            "Zrzut jest strukturalnie poprawny i nie zawiera ani jednego "
            "pakietu - brak findingow w tym przebiegu nie jest wynikiem "
            "analizy, tylko brakiem materialu."
        )
    elif not events:
        warnings.append(
            "Zaden segment w zrzucie nie przeszedl walidacji MBAP - brak "
            "ruchu Modbus/TCP do analizy."
        )

    observed_ips = sorted(
        {segment.src_ip for segment in segments} | {segment.dst_ip for segment in segments}
    )
    observed_protocols = sorted({"modbus-tcp"} if events else set())
    zone_model = zones.build_zone_model(
        observed_ips=observed_ips, observed_protocols=observed_protocols
    )

    conversations = _build_conversations(segments)
    protocol_events = [dataclasses.asdict(event) for event in events]

    methodology = {
        "rubric_version": risk.RUBRIC_VERSION,
        "note": (
            "Waga findingu wynika z zapisanych kryteriow rubryki, nie z "
            "wymyslonej skali (RISK-03)."
        ),
    }

    analysis = build_analysis(
        capture=_build_capture_section(pcap_path, packets),
        conversations=conversations,
        protocol_events=protocol_events,
        zone_model=zone_model,
        findings=[],
        methodology=methodology,
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
