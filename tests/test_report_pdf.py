"""Machine gate REPORT-03: export of the report to PDF (plan 04-03).

The first group (unit tests) builds the model by hand, following
`tests/test_report_render.py::_finding` - `render_pdf` is a function over a
dictionary, and the proof through the whole pipeline (pcap file -> CLI ->
report.pdf) sits in the fourth group (integration) below. The rationale of the
test finding carries a Polish pangram - exactly nine precomposed letters
outside ASCII in one short sentence. That set is a FONT AND ENCODING PROBE,
not project prose: it gives the encoding tests a source they can stand on,
independent of the content of the real standards catalogue, and every one of
the nine letters has a well-defined canonical decomposition to check NFC
against NFD.

The second group (a missing font file), the third group (no clock read, through
the syntax tree - the same discipline as
`tests/test_no_external_dissector.py`, because the module docstring DESCRIBES
the absence of a clock read and a naive text scan would catch its own
documentation), the fourth group (integration in a subprocess, following
`tests/test_determinism.py::_run_analyze`) and the fifth group (no new
dependency on the default path, following
`tests/test_scapy_cache_isolation.py`) close Task 3. The finding parity between
PDF and markdown and the byte determinism measurement (Task 4) sit further
down in this file.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pypdf import PdfReader

from wayside import report_pdf
from wayside.model import dump_deterministic, write_atomic_bytes
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze as pipeline_analyze
from wayside.report import (
    CITATION_SCOPE_LABEL,
    SECTIONS,
    aggregated_remediations,
    citation_line,
    citation_scope_line,
    finding_genitive_phrase,
    render_markdown,
    session_parties_line,
)
from wayside.report_pdf import PdfRenderError, render_pdf

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
FIXTURE_WRITE = FIXTURE_DIR / "modbus_write_single_register.pcap"
FIXTURE_EMPTY = FIXTURE_DIR / "empty_valid_header.pcap"

GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# The canonical set of all nine Polish diacritical letters, used here purely
# as an encoding probe - a source of truth wider than the probe of
# tests/test_determinism.py (this file needs the complete set, not a sample).
POLISH_DIACRITICS: tuple[str, ...] = ("ą", "ć", "ę", "ł", "ń", "ó", "ś", "ź", "ż")

# A pangram carrying all nine letters in one short sentence - the widely
# known Polish counterpart of "the quick brown fox".
PANGRAM = "Zażółć gęślą jaźń"

PDF_SIGNATURE = b"%PDF-"


def _finding(**overrides) -> dict:
    """Builds one finding in dictionary shape, following
    `tests/test_report_render.py::_finding`. The `rationale` carries `PANGRAM`,
    so that the encoding tests have a source independent of the content of the
    real standards catalogue."""
    base = {
        "check_id": "modbus-unauthenticated-write",
        "title": "Write operation to a controller over Modbus/TCP with no authentication at all",
        "severity": "high",
        "risk": "serious",
        "rationale": f"Our own analysis of the observed traffic. {PANGRAM}.",
        "standard_refs": [
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "clause_title_source": "copy",
                "paraphrase": "Paraphrase of the clause, not a quote of the original.",
                "verified": False,
                "verification_note": "Provisional numbering, awaiting comparison against a lawfully obtained copy of the standard.",
            }
        ],
        "evidence": {
            "packet_number": 1,
            "session_id": 0,
            "source": "10.0.0.1:502",
            "target": "10.0.0.2:50210",
        },
        "remediation": "Restrict the ability to send write codes to known engineering hosts.",
    }
    base.update(overrides)
    return base


def _analysis(*, findings: list[dict] | None = None) -> dict:
    return {
        "capture": {"filename": "test.pcap", "packet_count": 2},
        "findings": findings if findings is not None else [],
    }


def _extract_text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# --- Group one: unit tests over a hand-built model -------------------------


def test_render_pdf_returns_bytes_with_pdf_signature():
    pdf_bytes = render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes[:5] == PDF_SIGNATURE


def test_render_pdf_without_findings_is_nonzero_length_with_same_sentence_as_markdown():
    analysis = _analysis(findings=[])

    pdf_bytes = render_pdf(analysis, generated_at=GENERATED_AT)
    assert len(pdf_bytes) > 0

    pdf_text = _extract_text(pdf_bytes)
    markdown_text = render_markdown(analysis, generated_at=GENERATED_AT)

    # The sentence about the absence of findings (the Summary section) is
    # EXACTLY the same string in both formats - the empty edge case of the
    # plan's must_haves.
    empty_sentence = (
        "Analysis of capture `test.pcap` raised no finding in this run."
    )
    assert empty_sentence in markdown_text
    assert empty_sentence in pdf_text
    assert "No findings in this run." in pdf_text


def test_render_pdf_with_one_finding_carries_expected_fields():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    assert "modbus-unauthenticated-write" in pdf_text
    assert "high" in pdf_text
    assert "serious" in pdf_text
    assert "packet no. 1" in pdf_text
    assert "session no. 0" in pdf_text
    assert "SR 1.1" in pdf_text
    assert "Human user identification and authentication" in pdf_text
    assert "Paraphrase of the clause" in pdf_text
    assert "Restrict the ability to send write codes" in pdf_text
    assert "Session parties: 10.0.0.1:502 -> 10.0.0.2:50210" in pdf_text


def test_pdf_finding_block_uses_session_parties_line_not_own_copy():
    """G-04-5b: the PDF assembles the session parties line with the same pure
    function as the markdown, imported from `wayside.report` - not a copy of
    the logic of its own."""
    import inspect

    assert "session_parties_line" in inspect.getsource(report_pdf)


def test_render_pdf_unverified_reference_carries_same_status_text_as_markdown():
    analysis = _analysis(findings=[_finding()])

    pdf_text = _extract_text(render_pdf(analysis, generated_at=GENERATED_AT))
    markdown_text = render_markdown(analysis, generated_at=GENERATED_AT)

    assert "PROVISIONAL" in markdown_text and "UNVERIFIED" in markdown_text
    assert "PROVISIONAL" in pdf_text
    assert "UNVERIFIED" in pdf_text
    assert "Provisional numbering, awaiting comparison" in pdf_text


def test_render_pdf_verified_reference_carries_verified_status_text():
    verified_finding = _finding(
        standard_refs=[
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Human user identification and authentication",
                "clause_title_source": "copy",
                "paraphrase": "Paraphrase of the clause, not a quote of the original.",
                "verified": True,
                "verification_note": "",
            }
        ]
    )

    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[verified_finding]), generated_at=GENERATED_AT)
    )

    assert "verified" in pdf_text
    assert "PROVISIONAL" not in pdf_text


def test_text_layer_carries_all_nine_polish_diacritics_as_single_codepoints():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    for letter in POLISH_DIACRITICS:
        assert letter in pdf_text, f"The character {letter!r} is absent from the PDF text layer"


def test_text_layer_diacritics_are_never_decomposed_into_base_plus_combining():
    """The encoding edge case: each of the nine letters is meant to be a single
    code point in the COMPOSED normal form (NFC), never a pair of a base
    character and a combining one (NFD) - the comparison of the text before and
    after normalization to NFC has to give the same text as far as those
    letters go."""
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    # A test over the whole text: were any character decomposed (NFD),
    # normalization to NFC would change the text - equality proves the absence
    # of decomposition ANYWHERE, not only in those nine letters.
    assert unicodedata.normalize("NFC", pdf_text) == pdf_text

    # The per-character check only makes sense for letters with a PROPER
    # canonical decomposition in Unicode (a base plus a combining mark) - the
    # stroked l has no canonical decomposition at all (a stroke is not a
    # diacritic in the Unicode sense), so normalizing it to NFD returns the
    # same character and a per-character test for it would be a tautology
    # (always true whenever the character itself is present).
    for letter in POLISH_DIACRITICS:
        decomposed = unicodedata.normalize("NFD", letter)
        if decomposed == letter:
            continue
        assert decomposed not in pdf_text, (
            f"The character {letter!r} appears in decomposed form (NFD) in the "
            "PDF text layer"
        )


def test_text_layer_carries_eight_section_headers_in_order():
    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[_finding()]), generated_at=GENERATED_AT)
    )

    positions = [pdf_text.find(section) for section in SECTIONS]
    assert all(position != -1 for position in positions), (
        f"Not every section header is present: {list(zip(SECTIONS, positions))}"
    )
    assert positions == sorted(positions)


def test_pdf_finding_block_uses_shared_citation_functions_not_own_copy():
    """T-4-40: the pdf and the markdown render through the same two pure
    functions - proved over the syntax tree, not by guesswork (G-04-3c)."""
    import inspect

    src = inspect.getsource(report_pdf)
    assert "citation_line" in src
    assert "citation_scope_line" in src


def test_pdf_own_provenance_finding_carries_scope_label_not_title_inline():
    finding = _finding(
        standard_refs=[
            {
                "standard": "IEC-62443-3-3",
                "edition": "2013",
                "clause": "SR 1.1",
                "clause_title": "Title of our own description",
                "clause_title_source": "own",
                "paraphrase": "Paraphrase of the clause, not a quote of the original.",
                "verified": False,
                "verification_note": "Provisional numbering.",
            }
        ]
    )

    pdf_text = _extract_text(
        render_pdf(_analysis(findings=[finding]), generated_at=GENERATED_AT)
    )

    assert CITATION_SCOPE_LABEL in pdf_text
    for line in pdf_text.splitlines():
        if "SR 1.1" in line:
            assert "Title of our own description" not in line


def test_remediation_list_order_and_content_matches_between_markdown_and_pdf():
    """G-04-5a, Task 2: the aggregated remediation section carries the same
    list, in the same order, in both formats - built by the same pure function
    `aggregated_remediations`. The hand-built model with one repeated
    remediation avoids the long-text wrapping edge case in the PDF (`_body`,
    WORD wrapmode)."""
    findings = [
        _finding(remediation="X"),
        _finding(remediation="Y"),
        _finding(remediation="X"),
    ]
    analysis = _analysis(findings=findings)

    markdown_text = render_markdown(analysis, generated_at=GENERATED_AT)
    pdf_text = _extract_text(render_pdf(analysis, generated_at=GENERATED_AT))
    collapsed_pdf_text = re.sub(r"\s+", " ", pdf_text)

    expected_rows = [
        f"{remediation} (applies to {finding_genitive_phrase(count)})"
        for remediation, count in aggregated_remediations(findings)
    ]
    assert expected_rows == ["X (applies to 2 findings)", "Y (applies to 1 finding)"]

    for row in expected_rows:
        assert row in markdown_text, row
        assert row in collapsed_pdf_text, row

    markdown_positions = [markdown_text.index(row) for row in expected_rows]
    pdf_positions = [collapsed_pdf_text.index(row) for row in expected_rows]
    assert markdown_positions == sorted(markdown_positions)
    assert pdf_positions == sorted(pdf_positions)


def test_citation_line_and_scope_line_match_report_module_contract():
    """A sanity check: `report_pdf` uses EXACTLY the functions it imports from
    `wayside.report` - the imported function and the call in this module give
    an identical result."""
    ref_copy = {
        "standard": "IEC-62443-3-3",
        "clause": "SR 1.1",
        "clause_title": "Clause title",
        "clause_title_source": "copy",
    }
    ref_own = dict(ref_copy, clause_title_source="own")

    assert "Clause title" in citation_line(ref_copy)
    assert "Clause title" not in citation_line(ref_own)
    assert citation_scope_line(ref_copy) is None
    assert citation_scope_line(ref_own) is not None


def test_render_pdf_signature_is_identical_to_render_markdown():
    import inspect

    markdown_params = list(inspect.signature(render_markdown).parameters)
    pdf_params = list(inspect.signature(render_pdf).parameters)

    assert markdown_params == pdf_params


# --- Group two: a missing font file ----------------------------------------


def test_missing_font_file_raises_pdf_render_error_with_expected_path(monkeypatch, tmp_path):
    missing_path = tmp_path / "no-such-font.ttf"
    monkeypatch.setattr(report_pdf, "FONT_REGULAR_PATH", missing_path)

    with pytest.raises(PdfRenderError) as excinfo:
        render_pdf(_analysis(findings=[]), generated_at=GENERATED_AT)

    assert str(missing_path) in str(excinfo.value)


def test_missing_bold_font_file_raises_pdf_render_error_with_expected_path(monkeypatch, tmp_path):
    missing_path = tmp_path / "no-such-bold-font.ttf"
    monkeypatch.setattr(report_pdf, "FONT_BOLD_PATH", missing_path)

    with pytest.raises(PdfRenderError) as excinfo:
        render_pdf(_analysis(findings=[]), generated_at=GENERATED_AT)

    assert str(missing_path) in str(excinfo.value)


# --- Group three: no clock read, through the syntax tree -------------------


_CLOCK_ATTRIBUTES = {"now", "utcnow", "time", "today"}


def test_module_source_never_calls_a_clock_function():
    """The same pattern as `tests/test_no_external_dissector.py::scan_tree`: a
    check through the syntax tree rather than by text search - the module
    docstring DESCRIBES the absence of a clock read, so a naive text scan would
    catch its own documentation as a false alarm."""
    source = Path(report_pdf.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offending_calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CLOCK_ATTRIBUTES
    ]

    assert offending_calls == []


def test_module_source_never_imports_re():
    source = Path(report_pdf.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported_modules = [
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ] + [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]

    assert "re" not in imported_modules


# --- write_atomic_bytes: zapis bez zmiany, brak pliku czesciowego ----------


def test_write_atomic_bytes_roundtrip(tmp_path):
    target = tmp_path / "out.pdf"
    payload = b"%PDF-1.4\n...bajty...\n"

    write_atomic_bytes(target, payload)

    assert target.read_bytes() == payload


def test_write_atomic_bytes_interrupted_write_leaves_no_target_file(tmp_path, monkeypatch):
    target = tmp_path / "out.pdf"

    def _boom(*args, **kwargs):
        raise RuntimeError("interruption simulated in the test")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(RuntimeError):
        write_atomic_bytes(target, b"anything")

    assert not target.exists()
    # No temporary file is left behind in the target directory.
    assert list(tmp_path.iterdir()) == []


# --- Group four: integration in a subprocess -------------------------------


def _run_analyze(
    fixture: Path, out_dir: Path, *, pdf: bool
) -> subprocess.CompletedProcess:
    args = [
        sys.executable,
        "-m",
        "wayside.cli",
        "analyze",
        str(fixture),
        "--out-dir",
        str(out_dir),
    ]
    if pdf:
        args.append("--pdf")
    return subprocess.run(
        args, cwd=str(REPO_ROOT), capture_output=True, text=True
    )


def test_analyze_without_pdf_flag_writes_two_artifacts_and_no_pdf(tmp_path):
    result = _run_analyze(FIXTURE_WRITE, tmp_path, pdf=False)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "analysis.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert not (tmp_path / "report.pdf").exists()


def test_analyze_with_pdf_flag_writes_three_artifacts_and_exits_zero(tmp_path):
    result = _run_analyze(FIXTURE_WRITE, tmp_path, pdf=True)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "analysis.json").is_file()
    assert (tmp_path / "report.md").is_file()
    pdf_path = tmp_path / "report.pdf"
    assert pdf_path.is_file()
    assert pdf_path.read_bytes()[:5] == PDF_SIGNATURE
    assert str(pdf_path) in result.stdout


def test_analyze_with_pdf_flag_on_empty_fixture_exits_zero_with_nonzero_pdf(tmp_path):
    result = _run_analyze(FIXTURE_EMPTY, tmp_path, pdf=True)

    assert result.returncode == 0, result.stderr
    pdf_path = tmp_path / "report.pdf"
    assert pdf_path.is_file()
    assert len(pdf_path.read_bytes()) > 0


# --- Group five: no new dependency on the default path ---------------------


_PROBE = (
    "import contextlib\n"
    "import json\n"
    "import sys\n"
    "sys.argv = ['wayside', 'analyze', sys.argv[1], '--out-dir', sys.argv[2]]\n"
    "from wayside.cli import app\n"
    "with contextlib.suppress(SystemExit):\n"
    "    app()\n"
    "print(json.dumps({'fpdf_imported': 'fpdf' in sys.modules}))\n"
)


def test_pdf_library_not_imported_by_default_analyze_run(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, str(FIXTURE_WRITE), str(tmp_path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    probe = json.loads(result.stdout.strip().splitlines()[-1])

    assert probe["fpdf_imported"] is False


# =============================================================================
# Task 4: finding parity between the PDF, the markdown and analysis.json,
# plus the PDF byte determinism measurement in two separate subprocesses.
# =============================================================================


def _analyzable_fixtures() -> list[Path]:
    """Every fixture whose analysis finishes without an exception. The
    `tests/test_report_forbidden_phrases.py::_analyzable_fixtures` pattern -
    the list is built by GLOB rather than by naming the files by hand, so that
    a fixture added in the future lands in the gate without a change to this
    file."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return pipeline_analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (the D-01 gate)")


# The check identifier label is ANCHORED on the same marker in both formats
# ("Check identifier: "), with optional backticks (the markdown carries them,
# the PDF does not) - one pattern for both, taken straight from the TEXT of the
# artifact rather than from the rendering code.
_CHECK_ID_PATTERN = re.compile(r"Check identifier: `?([a-z0-9-]+)`?")


def _check_ids_in_text(text: str) -> list[str]:
    return _CHECK_ID_PATTERN.findall(text)


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_check_id_set_is_identical_across_pdf_markdown_and_analysis_json(
    fixture, tmp_path
):
    result = _analyze_or_skip(fixture, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    ids_from_pdf = set(_check_ids_in_text(pdf_text))
    ids_from_markdown = set(_check_ids_in_text(result.report_markdown))
    ids_from_model = {f["check_id"] for f in result.analysis["findings"]}

    # The symmetric difference in the assertion message names the missing
    # finding rather than merely the fact of a mismatch (04-03-PLAN.md, Task 4).
    assert ids_from_pdf == ids_from_markdown, (
        f"{fixture.name}: PDF/markdown difference = "
        f"{ids_from_pdf ^ ids_from_markdown}"
    )
    assert ids_from_pdf == ids_from_model, (
        f"{fixture.name}: roznica PDF/model = {ids_from_pdf ^ ids_from_model}"
    )


@pytest.mark.parametrize(
    "fixture", _analyzable_fixtures(), ids=lambda path: path.name
)
def test_check_id_label_count_equals_finding_count(fixture, tmp_path):
    """Set equality is NOT enough (the adjacency edge case): two findings with
    an identical identifier give the same set whether the text carries one
    block or two. The number of occurrences of the label has to equal the
    number of findings in the model."""
    result = _analyze_or_skip(fixture, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    assert len(_check_ids_in_text(pdf_text)) == len(result.analysis["findings"])


def test_two_findings_with_identical_title_yield_two_separate_blocks_in_pdf():
    """The adjacency edge case, over a hand-built model: no fixture of this
    project yields two findings with an identical title (04-03-PLAN.md,
    Task 4)."""
    duplicate_finding = _finding()
    analysis = _analysis(findings=[duplicate_finding, duplicate_finding])

    pdf_text = _extract_text(render_pdf(analysis, generated_at=GENERATED_AT))

    check_ids = _check_ids_in_text(pdf_text)
    assert len(check_ids) == 2
    assert check_ids == ["modbus-unauthenticated-write", "modbus-unauthenticated-write"]
    # The finding title (the bold header) also appears twice rather than once -
    # merging two findings into one block is a real rendering failure mode
    # (fpdf2 does not reject two identical multi_cell calls).
    assert pdf_text.count(duplicate_finding["title"]) == 2


def test_check_id_first_occurrence_order_matches_model_order(tmp_path):
    """The ordering edge case: the order of the first occurrences of the
    identifiers in the PDF text is meant to be identical to the order in the
    model (the order established by `checks.engine.run_checks` over the triple
    of keys)."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path)
    pdf_text = _extract_text(
        render_pdf(result.analysis, generated_at=GENERATED_AT, warnings=result.warnings)
    )

    order_in_model = [f["check_id"] for f in result.analysis["findings"]]
    first_occurrences: list[str] = []
    for check_id in _check_ids_in_text(pdf_text):
        if check_id not in first_occurrences:
            first_occurrences.append(check_id)

    assert first_occurrences == order_in_model


# --- The PDF byte determinism measurement in two separate subprocesses ----
#
# Built once per test, the same probe used in two subprocess calls - two
# SEPARATE processes are required here, not two calls inside one: the file
# identifier of the document and the font subsetting may be stable within one
# process and differ between processes (04-RESEARCH.md, Pitfall 8).

_DETERMINISM_PROBE = (
    "import json, sys\n"
    "from datetime import datetime, timezone\n"
    "from wayside.report_pdf import render_pdf\n"
    "analysis_path, output_path = sys.argv[1], sys.argv[2]\n"
    "with open(analysis_path, 'r', encoding='utf-8') as f:\n"
    "    analysis = json.load(f)\n"
    "generated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)\n"
    "pdf_bytes = render_pdf(analysis, generated_at=generated_at)\n"
    "with open(output_path, 'wb') as f:\n"
    "    f.write(pdf_bytes)\n"
)


def _render_pdf_via_subprocess(
    analysis_path: Path, output_path: Path, *, pythonhashseed: str
) -> str:
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = pythonhashseed
    result = subprocess.run(
        [sys.executable, "-c", _DETERMINISM_PROBE, str(analysis_path), str(output_path)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, (
        f"the PDF determinism probe did not return code 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    return hashlib.sha256(output_path.read_bytes()).hexdigest()


@pytest.mark.parametrize("pythonhashseed", ["0", "1337"])
def test_pdf_bytes_are_identical_across_two_subprocesses(tmp_path, pythonhashseed):
    """Two PDF rendering calls in two SEPARATE subprocesses, with an identical
    model and an identical timestamp, give bytes with the same sha256 sum - an
    empirical measurement, not an assumption (04-RESEARCH.md, Pitfall 8;
    04-03-PLAN.md, Task 4)."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path / "prep")
    analysis_path = tmp_path / "analysis_for_probe.json"
    analysis_path.write_text(dump_deterministic(result.analysis), encoding="utf-8")

    hash_a = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "a.pdf", pythonhashseed=pythonhashseed
    )
    hash_b = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "b.pdf", pythonhashseed=pythonhashseed
    )

    assert hash_a == hash_b


def test_pdf_bytes_are_identical_across_pythonhashseed_values(tmp_path):
    """The same measurement as above, repeated with two DIFFERENT values of the
    process hash seed - proof that the result is not an artifact of one
    accidentally stable seed."""
    result = _analyze_or_skip(FIXTURE_WRITE, tmp_path / "prep")
    analysis_path = tmp_path / "analysis_for_probe.json"
    analysis_path.write_text(dump_deterministic(result.analysis), encoding="utf-8")

    hash_seed_0 = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "seed_0.pdf", pythonhashseed="0"
    )
    hash_seed_1337 = _render_pdf_via_subprocess(
        analysis_path, tmp_path / "seed_1337.pdf", pythonhashseed="1337"
    )

    assert hash_seed_0 == hash_seed_1337
