"""Bramka maszynowa PROTO-05: kontrakt manifestu dissectora, loader plikowy,
sortowanie deterministyczne rejestru, oraz kryterium 2 fazy (dissector probny
bez zmiany zadnego pliku rdzenia).

Testy kontraktu schematu i sortowania wolaja `discover_dissectors` na
katalogu TYMCZASOWYM (`tmp_path`) - loader oparty o `spec_from_file_location`
dziala na dowolnej sciezce, wiec te testy nigdy nie dotykaja prawdziwego
pakietu.

Test kryterium 2 fazy wpisuje dissector PROBNY do PRAWDZIWEGO katalogu
`src/wayside/protocols/dissectors/` i sprzata po sobie - dokladnie to
dowodzi, ze nowy protokol wchodzi bez zmiany zadnego pliku rdzenia (ten sam
wzorzec co
`tests/test_check_engine.py::test_new_check_discovered_without_engine_change`).
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from wayside.protocols import registry

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"
FIXTURE_RTU_RELATIVE = "tests/fixtures/pcap/modbus_rtu_over_tcp.pcap"

# --- Wzorzec pol domyslnych do budowy dissectorow probnych na tmp_path ------

DEFAULT_MANIFEST: dict = {
    "id": "probe-protocol",
    "confidence": "high",
    "dissector": "probe_dissector:dissect",
}

DEFAULT_DISSECTOR_SOURCE = textwrap.dedent(
    """
    from __future__ import annotations

    def dissect(segments):
        return [{"packet_number": 1, "session_id": 1} for _ in segments]
    """
).lstrip()

NO_DISSECT_FUNCTION_SOURCE = textwrap.dedent(
    """
    from __future__ import annotations

    def not_dissect(segments):
        return []
    """
).lstrip()


def _write_dissector(
    root: Path,
    *,
    subdir: str,
    manifest_overrides: dict | None = None,
    remove_fields: list[str] | None = None,
    dissector_filename: str = "probe_dissector",
    dissector_source: str = DEFAULT_DISSECTOR_SOURCE,
    write_dissector: bool = True,
) -> Path:
    """Zapisuje jeden dissector (`manifest.yaml` plus siostrzany `.py`) pod
    `root/subdir`. Wydzielona wspolna logika, wzorzec `_write_check` z
    `tests/test_check_engine.py`. Zwraca sciezke do `manifest.yaml`."""
    target_dir = root / subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    manifest = dict(DEFAULT_MANIFEST)
    if manifest_overrides:
        manifest.update(manifest_overrides)
    if remove_fields:
        for field in remove_fields:
            manifest.pop(field, None)

    manifest_path = target_dir / "manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

    if write_dissector:
        (target_dir / f"{dissector_filename}.py").write_text(
            dissector_source, encoding="utf-8"
        )

    return manifest_path


def _spec(*, dissector_id: str, confidence: str, dissect) -> registry.DissectorSpec:
    """Buduje `DissectorSpec` w pamieci, bez zapisu na dysk - wystarczajace
    dla testow `run_dissectors`, ktore nie zaleza od loadera plikowego."""
    return registry.DissectorSpec(
        path=Path(f"/fake/{dissector_id}/manifest.yaml"),
        spec={"id": dissector_id, "confidence": confidence, "dissector": "fake:dissect"},
        dissect=dissect,
    )


def _run_analyze(fixture_relative: str, out_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            fixture_relative,
            "--out-dir",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


# --- discover_dissectors: katalog pusty/nieistniejacy, przypadek pozytywny -


def test_discover_dissectors_on_missing_directory_returns_empty_list(tmp_path):
    assert registry.discover_dissectors(dissectors_root=tmp_path / "nope") == []


def test_discover_dissectors_on_empty_directory_returns_empty_list(tmp_path):
    assert registry.discover_dissectors(dissectors_root=tmp_path) == []


def test_discover_dissectors_with_one_manifest_returns_one_spec(tmp_path):
    _write_dissector(tmp_path, subdir="probe")

    specs = registry.discover_dissectors(dissectors_root=tmp_path)

    assert len(specs) == 1
    assert specs[0].spec["id"] == "probe-protocol"


# --- Kontrakt schematu: pole wymagane brakujace lub puste -------------------


def test_discover_dissectors_rejects_missing_or_empty_required_fields(tmp_path):
    for field in registry.REQUIRED_DISSECTOR_FIELDS:
        missing_subdir = f"missing_{field}"
        _write_dissector(tmp_path, subdir=missing_subdir, remove_fields=[field])
        with pytest.raises(registry.DissectorSchemaError):
            registry.discover_dissectors(dissectors_root=tmp_path / missing_subdir)

        empty_subdir = f"empty_{field}"
        _write_dissector(tmp_path, subdir=empty_subdir, manifest_overrides={field: ""})
        with pytest.raises(registry.DissectorSchemaError):
            registry.discover_dissectors(dissectors_root=tmp_path / empty_subdir)


def test_discover_dissectors_rejects_confidence_outside_allowed_values(tmp_path):
    _write_dissector(
        tmp_path, subdir="bad_confidence", manifest_overrides={"confidence": "medium"}
    )
    with pytest.raises(registry.DissectorSchemaError):
        registry.discover_dissectors(dissectors_root=tmp_path / "bad_confidence")


# --- Ksztalt pola `dissector`: brak dwukropka, pusta nazwa modulu/funkcji ---


def test_discover_dissectors_rejects_malformed_dissector_field(tmp_path):
    bad_values = ("no_colon_here", ":dissect", "probe_dissector:")
    for i, bad_value in enumerate(bad_values):
        subdir = f"bad_shape_{i}"
        _write_dissector(tmp_path, subdir=subdir, manifest_overrides={"dissector": bad_value})
        with pytest.raises(registry.DissectorSchemaError):
            registry.discover_dissectors(dissectors_root=tmp_path / subdir)


def test_discover_dissectors_rejects_module_name_with_path_separator_or_dot(tmp_path):
    bad_module_names = ("sub/dir", "sub\\dir", "..")
    for i, bad_module_name in enumerate(bad_module_names):
        subdir = f"bad_module_{i}"
        _write_dissector(
            tmp_path,
            subdir=subdir,
            manifest_overrides={"dissector": f"{bad_module_name}:dissect"},
            write_dissector=False,
        )
        with pytest.raises(registry.DissectorSchemaError):
            registry.discover_dissectors(dissectors_root=tmp_path / subdir)
        assert f"wayside._protocols.{bad_module_name}" not in sys.modules


def test_discover_dissectors_rejects_nonexistent_module_file(tmp_path):
    _write_dissector(tmp_path, subdir="missing_module", write_dissector=False)
    with pytest.raises(registry.DissectorSchemaError):
        registry.discover_dissectors(dissectors_root=tmp_path / "missing_module")


def test_discover_dissectors_rejects_missing_function_in_module(tmp_path):
    _write_dissector(
        tmp_path, subdir="missing_func", dissector_source=NO_DISSECT_FUNCTION_SOURCE
    )
    with pytest.raises(registry.DissectorSchemaError):
        registry.discover_dissectors(dissectors_root=tmp_path / "missing_func")


# --- Duplikat identyfikatora -------------------------------------------------


def test_discover_dissectors_rejects_duplicate_id(tmp_path):
    _write_dissector(tmp_path, subdir="a", manifest_overrides={"id": "dup-protocol"})
    _write_dissector(tmp_path, subdir="b", manifest_overrides={"id": "dup-protocol"})

    with pytest.raises(registry.DissectorSchemaError) as excinfo:
        registry.discover_dissectors(dissectors_root=tmp_path)

    message = str(excinfo.value)
    assert str(tmp_path / "a" / "manifest.yaml") in message
    assert str(tmp_path / "b" / "manifest.yaml") in message


# --- Kolejnosc posortowanych sciezek, niezalezna od kolejnosci tworzenia ----


def test_discover_dissectors_orders_by_sorted_path(tmp_path):
    _write_dissector(tmp_path, subdir="charlie", manifest_overrides={"id": "protocol-charlie"})
    _write_dissector(tmp_path, subdir="alfa", manifest_overrides={"id": "protocol-alfa"})
    _write_dissector(tmp_path, subdir="bravo", manifest_overrides={"id": "protocol-bravo"})

    specs = registry.discover_dissectors(dissectors_root=tmp_path)
    ids = [s.spec["id"] for s in specs]

    assert ids == ["protocol-alfa", "protocol-bravo", "protocol-charlie"]
    assert [s.path for s in specs] == sorted(s.path for s in specs)


# --- run_dissectors: katalog pusty, wstrzykiwanie pol, rozdzial, sortowanie -


def test_run_dissectors_on_empty_segments_returns_two_empty_lists():
    spec = _spec(dissector_id="probe-protocol", confidence="high", dissect=lambda segments: [])

    protocol_events, low_confidence_events = registry.run_dissectors([], [spec])

    assert protocol_events == []
    assert low_confidence_events == []


def test_run_dissectors_injects_protocol_field_from_manifest():
    spec = _spec(
        dissector_id="probe-protocol",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1, "session_id": 1}],
    )

    protocol_events, _ = registry.run_dissectors(["segment"], [spec])

    assert protocol_events[0]["protocol"] == "probe-protocol"


def test_run_dissectors_injects_confidence_field_overwriting_existing_value():
    spec = _spec(
        dissector_id="probe-protocol",
        confidence="high",
        dissect=lambda segments: [
            {"packet_number": 1, "session_id": 1, "confidence": "low"}
        ],
    )

    protocol_events, _ = registry.run_dissectors(["segment"], [spec])

    assert protocol_events[0]["confidence"] == "high"


def test_run_dissectors_rejects_event_missing_packet_number():
    spec = _spec(
        dissector_id="probe-protocol",
        confidence="high",
        dissect=lambda segments: [{"session_id": 1}],
    )

    with pytest.raises(registry.DissectorSchemaError):
        registry.run_dissectors(["segment"], [spec])


def test_run_dissectors_rejects_event_missing_session_id():
    spec = _spec(
        dissector_id="probe-protocol",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1}],
    )

    with pytest.raises(registry.DissectorSchemaError):
        registry.run_dissectors(["segment"], [spec])


def test_run_dissectors_rejects_event_with_conflicting_protocol_field():
    spec = _spec(
        dissector_id="probe-protocol",
        confidence="high",
        dissect=lambda segments: [
            {"packet_number": 1, "session_id": 1, "protocol": "other-protocol"}
        ],
    )

    with pytest.raises(registry.DissectorSchemaError):
        registry.run_dissectors(["segment"], [spec])


def test_run_dissectors_splits_events_by_manifest_confidence():
    high_spec = _spec(
        dissector_id="protocol-high",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1, "session_id": 1}],
    )
    low_spec = _spec(
        dissector_id="protocol-low",
        confidence="low",
        dissect=lambda segments: [{"packet_number": 2, "session_id": 2}],
    )

    protocol_events, low_confidence_events = registry.run_dissectors(
        ["segment"], [high_spec, low_spec]
    )

    assert [e["protocol"] for e in protocol_events] == ["protocol-high"]
    assert [e["protocol"] for e in low_confidence_events] == ["protocol-low"]


def test_run_dissectors_sorts_result_by_packet_number_session_id_protocol():
    spec_a = _spec(
        dissector_id="protocol-a",
        confidence="high",
        dissect=lambda segments: [
            {"packet_number": 2, "session_id": 1},
            {"packet_number": 1, "session_id": 5},
        ],
    )
    spec_b = _spec(
        dissector_id="protocol-b",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1, "session_id": 1}],
    )

    protocol_events, _ = registry.run_dissectors(["segment"], [spec_a, spec_b])

    ordered = [(e["packet_number"], e["session_id"], e["protocol"]) for e in protocol_events]
    assert ordered == sorted(ordered)


def test_run_dissectors_result_independent_of_discovery_order():
    spec_a = _spec(
        dissector_id="protocol-a",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1, "session_id": 1}],
    )
    spec_b = _spec(
        dissector_id="protocol-b",
        confidence="high",
        dissect=lambda segments: [{"packet_number": 1, "session_id": 1}],
    )

    forward, _ = registry.run_dissectors(["segment"], [spec_a, spec_b])
    backward, _ = registry.run_dissectors(["segment"], [spec_b, spec_a])

    assert forward == backward


# --- Integracja: wayside analyze nad prawdziwymi dissectorami Modbusa ------


def test_baseline_fixture_gives_two_high_confidence_modbus_tcp_events(tmp_path):
    result = _run_analyze(FIXTURE_RELATIVE, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    protocol_events = analysis["protocol_events"]

    assert len(protocol_events) == 2
    for event in protocol_events:
        assert event["protocol"] == "modbus-tcp"
        assert event["confidence"] == "high"


def test_rtu_over_tcp_fixture_gives_empty_protocol_events_and_two_low_confidence(tmp_path):
    result = _run_analyze(FIXTURE_RTU_RELATIVE, tmp_path)
    assert result.returncode == 0, result.stderr

    analysis = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))

    assert analysis["protocol_events"] == []
    low_confidence_events = analysis["low_confidence_events"]
    assert len(low_confidence_events) == 2
    for event in low_confidence_events:
        assert event["protocol"] == "modbus-rtu-over-tcp"
