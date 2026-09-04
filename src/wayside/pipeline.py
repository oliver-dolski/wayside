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

from wayside import coverage, decode, report, risk, zones
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
from wayside.protocols import modbus_rtu_tunnel, modbus_tcp
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
    """Buduje sekcje `capture`. Niesie `filename` (samo `pcap_path.name`),
    NIE pelna sciezke - pelna sciezka jest funkcja katalogu uruchomienia
    procesu, wiec dwa przebiegi z roznych katalogow roboczych dawalyby
    rozne bajty `analysis.json` mimo identycznej tresci analitycznej
    (REPORT-06). `sha256` niesie mozliwosc powiazania raportu z konkretnym
    plikiem wejsciowym (zagrozenie T-2-07) - jest funkcja TRESCI pliku, nie
    jego polozenia, wiec nie lamie determinizmu ani miedzy katalogami, ani
    miedzy maszynami. `snaplen`/`snaplen_note` pochodza z `capture_structure`,
    juz wyliczonego przez brame D-01 - `analyze` nie wywoluje audytu drugi
    raz (INGEST-02)."""
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
    """Wykonuje kroki potoku w kolejnosci: audyt strukturalny (brama D-01),
    odczyt zrzutu, dekodowanie, dysekcja Modbus, dyskryminator Modbus RTU
    tunelowanego po TCP nad ta sama lista segmentow (PROTO-03), budowa
    inwentarza hostow, bramka prowieniencji nad inwentarzem (Z-02), model
    strefy, pomiar cyklu odpytywania i ocena pokrycia okna zrzutu
    (INGEST-04), model analizy bez findingow, silnik checkow, rozwiazanie
    powolan na norme, przypisanie ryzyka, zapis `analysis.json`,
    renderowanie i zapis `report.md`."""
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
    # PROTO-03: dyskryminator wolany na TEJ SAMEJ liscie segmentow co
    # dissect_all - wzajemne wykluczenie miedzy natywnym Modbus/TCP i
    # rozpoznaniem RTU-po-TCP jest wlasnoscia modbus_rtu_tunnel.detect_all
    # (zalozenie Z-17), nie kolejnosci wywolan tutaj.
    low_confidence_events = modbus_rtu_tunnel.detect_all(segments)

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
    if capture_structure.snaplen_truncated_packet_numbers:
        # INGEST-03: ramka uciety przez snaplen nie niesie pelnego ladunku,
        # wiec brak zdarzenia protokolu na tym zrzucie nie jest dowodem jego
        # nieobecnosci - narzedzie mowi to wprost, nigdy cicha, zielona
        # odpowiedzia. Zdanie oznajmujace, bez terminu modalnego w linii z
        # liczba (scripts/confidentiality_guard.py, warstwa strukturalna).
        truncated_numbers = capture_structure.snaplen_truncated_packet_numbers
        warnings.append(
            f"Snaplen ustawiony na {capture_structure.snaplen} bajtow uciol "
            f"{len(truncated_numbers)} z {len(packets)} ramek w tym zrzucie, "
            f"pierwsza obcieta ramka to numer {truncated_numbers[0]}. Obcieta "
            "ramka nie niesie pelnego ladunku, analiza funkcjonalna protokolu "
            "na tym zrzucie jest falszowana, a brak zdarzenia protokolu nie "
            "jest dowodem jego nieobecnosci."
        )
    if low_confidence_events:
        # PROTO-03: zdarzenie rozpoznane dyskryminatorem sumy kontrolnej stoi
        # poza lista zdarzen protokolu i poza kazdym findingiem - narzedzie
        # nazywa liczbe takich zdarzen, protokol i podstawe rozpoznania, oraz
        # mozliwosc falszywego dopasowania sumy kontrolnej na ruchu nie
        # bedacym Modbusem (zalozenie Z-18, zagrozenie T-3-13).
        warnings.append(
            f"{len(low_confidence_events)} zdarzenie(a) w tym zrzucie "
            f"rozpoznane sa dyskryminatorem sumy kontrolnej "
            f"{modbus_rtu_tunnel.RTU_DETECTION_BASIS} jako "
            "modbus-rtu-over-tcp, z niska pewnoscia, poza lista zdarzen "
            "protokolu i poza kazdym findingiem. Rozpoznanie niesie "
            "mozliwosc falszywego dopasowania sumy kontrolnej na ruchu nie "
            "bedacym Modbusem."
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
    low_confidence_events_section = [
        dataclasses.asdict(event) for event in low_confidence_events
    ]

    capture_section = _build_capture_section(pcap_path, packets, capture_structure)
    # Zaokraglenie do szesciu miejsc po przecinku zdejmuje szum reprezentacji
    # zmiennoprzecinkowej (roznica dwoch znacznikow czasu daje np.
    # 5.009999990463257 zamiast 5.01) - ta sama konwencja co formatowanie
    # dlugosci okna w komendzie `inspect` (zalozenie Z-15).
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
    # INGEST-04: zrzut za krotki wobec zmierzonego odstepu odpytywania
    # konczy sie ostrzezeniem niosacym obie liczby, nigdy cicha, zielona
    # odpowiedzia - ta sama dyscyplina co ostrzezenie o snaplenie wyzej.
    warnings.extend(
        coverage.coverage_warnings(cycles=polling_cycles, window_duration_s=window_duration_s)
    )

    # ASSET-02: tabela producentow OUI wczytywana DOKLADNIE RAZ na przebieg,
    # PRZED budowa inwentarza - plik ma kilkadziesiat tysiecy wierszy, a
    # odczyt na hosta zamienilby liniowa prace w kwadratowa. Niepowodzenie
    # (zalozenie Z-21) daje vendor_lookup rowne None i JAWNE ostrzezenie -
    # nigdy ciche pole nieustalone, ktore wygladaloby identycznie jak pole
    # nieustalone z powodu adresu MAC lokalnie administrowanego albo
    # nieobecnego.
    try:
        oui_table = oui.load_oui_table()
    except oui.OuiTableError:
        vendor_lookup = None
        warnings.append(
            "Tabela producentow OUI nie jest dolaczona do tego wydania "
            "narzedzia - pole producenta jest nieustalone dla kazdego "
            "hosta w tym przebiegu, niezaleznie od tego, czy jego adres "
            "MAC byl widoczny."
        )
    else:

        def vendor_lookup(mac: str) -> str | None:
            return oui.lookup_vendor(mac, oui_table)

    assets = inventory.build_assets(segments=segments, vendor_lookup=vendor_lookup)
    # Bramka prowieniencji stoi na producencie danych, PRZED serializacja
    # (T-3-04): pole inwentarza bez znacznika pochodzenia nie dochodzi do
    # `analysis.json`. Zakres bramki jest sekcja `assets`, nie cale drzewo
    # `analysis` (zalozenie Z-02) - pola z Faz 1-2 nie sa regresja.
    assert_provenance_complete(assets, path="assets")

    methodology = {
        "rubric_version": risk.RUBRIC_VERSION,
        "note": (
            "Waga findingu wynika z zapisanych kryteriow rubryki, nie z "
            "wymyslonej skali (RISK-03)."
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
        low_confidence_events=low_confidence_events_section,
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
