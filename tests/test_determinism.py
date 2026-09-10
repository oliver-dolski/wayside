"""Machine gate REPORT-06/REPORT-04: cross-run determinism of
`analysis.json` (plan 02-05).

`test_analysis_json_byte_identical` is a name from the requirement-to-test
contract of `02-VALIDATION.md` - it does not change. Criterion 5 of the phase
and D-02 demand output that is byte identical across two runs, compared
WITHOUT any mask and without skipping any field - `Path.read_bytes()` and
equality, never normalization nor a structural diff.

The three dimensions of non-determinism named up front by the research
(02-RESEARCH.md, Pitfall 5) each get their own test: the process hash seed
(`PYTHONHASHSEED`), the working directory (`cwd`) and file system order
(indirectly - two runs suffice once discovery is sorted).

We do not compare a run against a file committed to the repository: `*
text=auto` in `.gitattributes` puts text files through line ending
normalization at checkout, so such a comparison would put two things side by
side where one went through git, rather than two freshly generated artifacts.
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
FIXTURE_CLEARTEXT = (
    REPO_ROOT / "tests" / "fixtures" / "pcap" / "cleartext_telnet_ftp_http.pcap"
)
FIXTURE_READ_ONLY_SESSION = (
    REPO_ROOT / "tests" / "fixtures" / "pcap" / "modbus_read_only_session.pcap"
)

FIXTURES: dict[str, Path] = {
    "write": FIXTURE_WRITE,
    "empty": FIXTURE_EMPTY,
    "pcapng": FIXTURE_PCAPNG,
    "rtu_over_tcp": FIXTURE_RTU_OVER_TCP,
    # The gateway fixture enters here as the first one from phase 3 not
    # because it is new, but because it is the only one that builds the
    # `unit_ids` set - and a set is the structure that drifts between runs
    # most easily. The rest of the phase goes through the same serialization
    # path, so without these three entries the determinism gate was guarding
    # phase 2 code.
    "gateway": FIXTURE_GATEWAY,
    "handshake": FIXTURE_HANDSHAKE,
    "snaplen": FIXTURE_SNAPLEN,
    # The cleartext fixture (plan 04-02): the three dissectors new in this
    # phase go through the same protocol event serialization path as Modbus -
    # without this entry the determinism gate guards the code of earlier
    # phases rather than the code of Phase 4 (gap W-2 of the Phase 3
    # verification).
    "cleartext": FIXTURE_CLEARTEXT,
    # The read-only session fixture (plan 04-04): the case that separates
    # CHECK-05 from CHECK-04, going through the same Modbus protocol event
    # serialization path as the base fixture.
    "read_only_session": FIXTURE_READ_ONLY_SESSION,
}

# The report generation timestamp line (D-02) - the only difference allowed
# between two runs of `report.md`.
_GENERATED_AT_LINE_PATTERN = re.compile(r"^Generated:.*$", flags=re.MULTILINE)

# The JSON escape sequence for a character outside ASCII (`\uXXXX`) - its
# absence from the bytes of `analysis.json` proves `ensure_ascii=False` really
# works rather than merely being set in the code.
_UNICODE_ESCAPE_PATTERN = re.compile(rb"\\u[0-9a-fA-F]{4}")

# A probe carrying characters outside ASCII, in the shape the pipeline
# actually meets them: vendor names from the IEEE OUI registry. It is a
# constant of this test rather than a value read from a fixture, because
# what is under test is the SERIALISATION setting (`ensure_ascii=False`),
# not whether a given capture happens to resolve a vendor.
_NON_ASCII_PROBE = "Pruftechnik Buro Satron \u00fc\u00f6\u00e4"


def _run_analyze(
    fixture: Path,
    out_dir: Path,
    *,
    env_overrides: dict[str, str | None] | None = None,
    cwd: Path | None = None,
) -> tuple[Path, Path]:
    """Runs `wayside analyze` in a subprocess and returns the paths of both
    artifacts. `fixture` and `out_dir` are always absolute, so that the result
    does not depend on the `cwd` passed by the caller - `cwd` is PRECISELY the
    independent variable in the working directory tests."""
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
        f"wayside analyze did not return code 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    return out_dir / "analysis.json", out_dir / "report.md"


def _strip_generated_at_line(report_text: str) -> str:
    return _GENERATED_AT_LINE_PATTERN.sub("", report_text)


# --- The requirement-to-test contract: the name from 02-VALIDATION.md, no masks ---


def test_analysis_json_byte_identical(tmp_path):
    """Two runs over the same capture, into two different output directories,
    yield an `analysis.json` with identical bytes - the comparison goes through
    `Path.read_bytes()` and equality, without any normalization."""
    analysis_a, _ = _run_analyze(FIXTURE_WRITE, tmp_path / "run_a")
    analysis_b, _ = _run_analyze(FIXTURE_WRITE, tmp_path / "run_b")

    assert analysis_a.read_bytes() == analysis_b.read_bytes()


# --- The same for a capture without packets and for the pcapng format ------


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_analysis_json_byte_identical_across_fixtures(fixture_name, tmp_path):
    fixture = FIXTURES[fixture_name]
    analysis_a, _ = _run_analyze(fixture, tmp_path / "run_a")
    analysis_b, _ = _run_analyze(fixture, tmp_path / "run_b")

    assert analysis_a.read_bytes() == analysis_b.read_bytes()


# --- The process hash seed (02-RESEARCH.md, Pitfall 5) ---------------------


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


# --- The working directory -------------------------------------------------


@pytest.mark.parametrize("fixture_name", sorted(FIXTURES))
def test_analysis_json_byte_identical_across_working_directory(fixture_name, tmp_path):
    """Proves that `checks.engine.CHECKS_ROOT` and
    `standards.mapper.CATALOG_ROOT` are resolved against the package rather
    than against the process's `cwd` - `cwd_a` is the repository root (as in
    every other test), `cwd_b` is a temporary directory unrelated to the
    repository."""
    fixture = FIXTURES[fixture_name]
    cwd_a = REPO_ROOT
    cwd_b = tmp_path / "elsewhere"
    cwd_b.mkdir()

    analysis_a, _ = _run_analyze(fixture, tmp_path / "cwd_a", cwd=cwd_a)
    analysis_b, _ = _run_analyze(fixture, tmp_path / "cwd_b", cwd=cwd_b)

    bytes_a = analysis_a.read_bytes()
    bytes_b = analysis_b.read_bytes()
    assert bytes_a == bytes_b

    # The `capture` section carries no field dependent on the working
    # directory: neither the path of the temporary `cwd_b` nor `cwd_a` appears
    # anywhere in the content - the only identifier of the file is its name
    # and its sha256 sum.
    text_a = bytes_a.decode("utf-8")
    assert str(cwd_b) not in text_a
    assert str(tmp_path) not in text_a

    capture = json.loads(text_a)["capture"]
    assert capture["filename"] == fixture.name
    assert os.sep not in capture["filename"]


# --- A structurally empty capture: valid JSON, not a zero-length file ------


def test_empty_fixture_analysis_json_is_nonzero_length_with_empty_lists(tmp_path):
    analysis_path, _ = _run_analyze(FIXTURE_EMPTY, tmp_path)

    raw = analysis_path.read_bytes()
    assert len(raw) > 0

    analysis = json.loads(raw.decode("utf-8"))
    assert analysis["conversations"] == []
    assert analysis["protocol_events"] == []
    assert analysis["findings"] == []


# --- Encoding: no escape sequence outside ASCII in the artifact ------------


def test_analysis_json_carries_no_unicode_escape_sequence(tmp_path):
    analysis_path, _ = _run_analyze(FIXTURE_WRITE, tmp_path)
    raw = analysis_path.read_bytes()

    assert _UNICODE_ESCAPE_PATTERN.search(raw) is None


def test_dump_deterministic_writes_non_ascii_as_characters_not_escapes():
    """The other half of the rule above, on a probe rather than on a fixture.

    The gate above proves the artifact of THIS capture carries no escape
    sequence - but a capture whose every value happens to be ASCII would pass
    it with the serialisation setting broken. This test drives a character
    outside ASCII through `dump_deterministic` directly, so the
    `ensure_ascii=False` setting has a gate that does not depend on the
    contents of any capture.
    """
    from wayside.model import dump_deterministic

    text = dump_deterministic({"vendor": _NON_ASCII_PROBE})

    assert _NON_ASCII_PROBE in text
    assert "\\u" not in text


# --- The D-02 asymmetry: report.md differs ONLY by the timestamp line ------


def test_report_markdown_differs_only_by_generated_at_line(tmp_path):
    _, report_a = _run_analyze(FIXTURE_WRITE, tmp_path / "run_a")
    _, report_b = _run_analyze(FIXTURE_WRITE, tmp_path / "run_b")

    text_a = report_a.read_text(encoding="utf-8")
    text_b = report_b.read_text(encoding="utf-8")

    # The contents themselves - two runs with the default
    # `generated_at=datetime.now()` will practically never carry an identical
    # timestamp line, and this test exists precisely to prove that is the ONLY
    # difference.
    assert text_a != text_b

    assert _strip_generated_at_line(text_a) == _strip_generated_at_line(text_b)
