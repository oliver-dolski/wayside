"""Bramka maszynowa REPORT-06/REPORT-04: determinizm miedzy-przebiegowy
`analysis.json` (plan 02-05).

`test_analysis_json_byte_identical` jest nazwa z kontraktu wymaganie-na-test
z `02-VALIDATION.md` - nie jest zmieniana. Kryterium 5 fazy i D-02 wymagaja
wyjscia bajtowo identycznego w dwoch przebiegach, porownanego BEZ zadnej
maski i bez pomijania zadnego pola - `Path.read_bytes()` i rownosc, nigdy
normalizacja ani diff strukturalny.

Trzy wymiary niedeterminizmu nazwane z gory przez badanie (02-RESEARCH.md,
Pitfall 5) maja kazdy osobny test: ziarno hashowania procesu
(`PYTHONHASHSEED`), katalog uruchomienia (`cwd`) i kolejnosc systemu plikow
(posrednio - dwa przebiegi wystarczaja, gdy odkrywanie jest posortowane).

Nie zestawiamy przebiegu z plikiem zacommitowanym w repozytorium: `*
text=auto` w `.gitattributes` przepuszcza pliki tekstowe przez normalizacje
konca linii przy checkoucie, wiec takie porownanie zestawialoby dwie rzeczy,
z ktorych jedna przeszla przez gita, a nie dwa swiezo wygenerowane artefakty.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

FIXTURE_WRITE = REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_write_single_register.pcap"
FIXTURE_EMPTY = REPO_ROOT / "tests" / "fixtures" / "pcap" / "empty_valid_header.pcap"
FIXTURE_PCAPNG = REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_write_single_register.pcapng"
FIXTURE_RTU_OVER_TCP = REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_rtu_over_tcp.pcap"
FIXTURE_GATEWAY = (
    REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_gateway_multi_unit_id.pcap"
)
FIXTURE_HANDSHAKE = REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_tcp_handshake.pcap"
FIXTURE_SNAPLEN = (
    REPO_ROOT / "tests" / "fixtures" / "pcap" / "snaplen_truncated_frames.pcap"
)

FIXTURES: dict[str, Path] = {
    "write": FIXTURE_WRITE,
    "empty": FIXTURE_EMPTY,
    "pcapng": FIXTURE_PCAPNG,
    "rtu_over_tcp": FIXTURE_RTU_OVER_TCP,
    # Fixture bramy wchodzi tu jako pierwszy z fazy 3 nie dlatego, ze jest
    # nowy, tylko dlatego, ze jako jedyny buduje zbior `unit_ids` - a zbior
    # jest ta struktura, ktora rozjezdza sie miedzy przebiegami najlatwiej.
    # Reszta fazy przechodzi przez te sama sciezke serializacji, wiec bez
    # tych trzech pozycji bramka determinizmu pilnowala kodu z fazy 2.
    "gateway": FIXTURE_GATEWAY,
    "handshake": FIXTURE_HANDSHAKE,
    "snaplen": FIXTURE_SNAPLEN,
}

# Linia znacznika czasu wygenerowania raportu (D-02) - jedyna dopuszczalna
# roznica miedzy dwoma przebiegami `report.md`.
_GENERATED_AT_LINE_PATTERN = re.compile(r"^Wygenerowano:.*$", flags=re.MULTILINE)

# Sekwencja escape JSON dla znaku spoza ASCII (`\uXXXX`) - jej brak w
# bajtach `analysis.json` dowodzi, ze `ensure_ascii=False` faktycznie
# dziala, nie tylko jest ustawione w kodzie.
_UNICODE_ESCAPE_PATTERN = re.compile(rb"\\u[0-9a-fA-F]{4}")

# Kilka polskich znakow diakrytycznych z parafrazy katalogu norm
# (`src/wayside/standards/iec62443-3-3/catalog.yaml`) - obecnosc w
# odczytanym tekscie dowodzi, ze tresc naprawde przeszla przez potok, a
# test kodowania nie jest pusty (D-02/STD-01, edge: encoding).
_POLISH_DIACRITICS = ("ą", "ę", "ł", "ż", "ó", "ś", "ń", "ć")


def _run_analyze(
    fixture: Path,
    out_dir: Path,
    *,
    env_overrides: dict[str, str | None] | None = None,
    cwd: Path | None = None,
) -> tuple[Path, Path]:
    """Uruchamia `wayside analyze` w podprocesie i zwraca sciezki obu
    artefaktow. `fixture` i `out_dir` sa zawsze bezwzgledne, zeby wynik nie
    zalezal od `cwd` przekazanego wywolujacemu - to WLASNIE `cwd` jest tu
    zmienna niezalezna w testach katalogu roboczego."""
    assert fixture.is_absolute()
    assert out_dir.is_absolute()

    env = dict(os.environ)
    for key, value in (env_overrides or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            str(fixture),
            "--out-dir",
            str(out_dir),
        ],
        cwd=str(cwd) if cwd is not None else str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, (
        f"wayside analyze nie zwrocilo kodu 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    return out_dir / "analysis.json", out_dir / "report.md"


def _strip_generated_at_line(report_text: str) -> str:
    return _GENERATED_AT_LINE_PATTERN.sub("", report_text)


# --- Kontrakt wymaganie-na-test: nazwa z 02-VALIDATION.md, bez masek -----------


def test_analysis_json_byte_identical(tmp_path):
    """Dwa przebiegi na tym samym zrzucie, do dwoch roznych katalogow
    wyjsciowych, daja `analysis.json` o identycznych bajtach - porownanie
    idzie przez `Path.read_bytes()` i rownosc, bez zadnej normalizacji."""
    analysis_a, _ = _run_analyze(FIXTURE_WRITE, tmp_path / "run_a")
    analysis_b, _ = _run_analyze(FIXTURE_WRITE, tmp_path / "run_b")

    assert analysis_a.read_bytes() == analysis_b.read_bytes()


# --- To samo dla zrzutu bez pakietow i dla formatu pcapng ----------------------


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_analysis_json_byte_identical_across_fixtures(fixture_name, tmp_path):
    fixture = FIXTURES[fixture_name]
    analysis_a, _ = _run_analyze(fixture, tmp_path / "run_a")
    analysis_b, _ = _run_analyze(fixture, tmp_path / "run_b")

    assert analysis_a.read_bytes() == analysis_b.read_bytes()


# --- Ziarno hashowania procesu (02-RESEARCH.md, Pitfall 5) ---------------------


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_analysis_json_byte_identical_across_pythonhashseed(fixture_name, tmp_path):
    fixture = FIXTURES[fixture_name]
    analysis_a, _ = _run_analyze(
        fixture, tmp_path / "seed_0", env_overrides={"PYTHONHASHSEED": "0"}
    )
    analysis_b, _ = _run_analyze(
        fixture, tmp_path / "seed_1337", env_overrides={"PYTHONHASHSEED": "1337"}
    )

    assert analysis_a.read_bytes() == analysis_b.read_bytes()


# --- Katalog uruchomienia -------------------------------------------------------


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_analysis_json_byte_identical_across_working_directory(fixture_name, tmp_path):
    """Dowodzi, ze `checks.engine.CHECKS_ROOT` i `standards.mapper.CATALOG_ROOT`
    sa rozwiazywane wobec pakietu, nie wobec `cwd` procesu - `cwd_a` jest
    korzeniem repo (jak w kazdym innym tescie), `cwd_b` jest katalogiem
    tymczasowym niepowiazanym z repo."""
    fixture = FIXTURES[fixture_name]
    cwd_a = REPO_ROOT
    cwd_b = tmp_path / "elsewhere"
    cwd_b.mkdir()

    analysis_a, _ = _run_analyze(fixture, tmp_path / "cwd_a", cwd=cwd_a)
    analysis_b, _ = _run_analyze(fixture, tmp_path / "cwd_b", cwd=cwd_b)

    bytes_a = analysis_a.read_bytes()
    bytes_b = analysis_b.read_bytes()
    assert bytes_a == bytes_b

    # Sekcja `capture` nie niesie pola zaleznego od katalogu uruchomienia:
    # ani sciezka katalogu tymczasowego `cwd_b`, ani `cwd_a` nie pojawiaja
    # sie nigdzie w tresci - jedynym identyfikatorem pliku jest nazwa i
    # suma sha256.
    text_a = bytes_a.decode("utf-8")
    assert str(cwd_b) not in text_a
    assert str(tmp_path) not in text_a

    capture = json.loads(text_a)["capture"]
    assert capture["filename"] == fixture.name
    assert os.sep not in capture["filename"]


# --- Zrzut strukturalnie pusty: JSON poprawny, nie plik zerowej dlugosci ------


def test_empty_fixture_analysis_json_is_nonzero_length_with_empty_lists(tmp_path):
    analysis_path, _ = _run_analyze(FIXTURE_EMPTY, tmp_path)

    raw = analysis_path.read_bytes()
    assert len(raw) > 0

    analysis = json.loads(raw.decode("utf-8"))
    assert analysis["conversations"] == []
    assert analysis["protocol_events"] == []
    assert analysis["findings"] == []


# --- Kodowanie: brak escape spoza ASCII, polskie znaki obecne w tekscie -------


def test_analysis_json_has_no_ascii_escape_and_decodes_with_polish_diacritics(tmp_path):
    analysis_path, _ = _run_analyze(FIXTURE_WRITE, tmp_path)
    raw = analysis_path.read_bytes()

    assert _UNICODE_ESCAPE_PATTERN.search(raw) is None

    text = raw.decode("utf-8")
    assert any(letter in text for letter in _POLISH_DIACRITICS)


# --- Asymetria D-02: report.md rozni sie WYLACZNIE linia znacznika czasu -----


def test_report_markdown_differs_only_by_generated_at_line(tmp_path):
    _, report_a = _run_analyze(FIXTURE_WRITE, tmp_path / "run_a")
    _, report_b = _run_analyze(FIXTURE_WRITE, tmp_path / "run_b")

    text_a = report_a.read_text(encoding="utf-8")
    text_b = report_b.read_text(encoding="utf-8")

    # Same tresci - dwa przebiegi z domyslnym `generated_at=datetime.now()`
    # praktycznie nigdy nie beda mialy identycznej linii znacznika czasu -
    # ten test istnieje wlasnie po to, zeby udowodnic, ze to JEDYNA roznica.
    assert text_a != text_b

    assert _strip_generated_at_line(text_a) == _strip_generated_at_line(text_b)
