"""One orthography for the text going into the document (REPORT-03,
G-04-4).

The convention: every piece of text landing in `report.md` or in
`report.pdf` is written in English, in ASCII, in NFC normalised form. This
file used to be the mirror image of that rule - it guarded the presence of
Polish diacritics, because the document text was Polish. The project moved
its whole public surface to English, so the gate did not disappear: it
reversed direction and now guards the ABSENCE of that alphabet in the
author's own text.

Three gates, each covering a different surface, and what EACH of them does
NOT catch.

1. **YAML fields** (the standards catalogue, the check files). No threshold
   and no exceptions - every one of these fields is a long English sentence
   written by the author, so a character outside ASCII is always a mistake
   in this corpus. Does NOT catch: fields outside
   `DOCUMENT_TEXT_YAML_FIELDS` (e.g. `standard`, `clause`, `verified`) -
   those are data identifiers, not prose.

2. **Prose in code** (`DOCUMENT_TEXT_MODULES`). Parses every module with a
   syntax tree, collects every string constant (the literal parts of
   f-strings included) and excludes docstrings. Unlike the Polish original
   this gate has NO length threshold: a short label was exactly the place
   the old gate had to hand over to a third gate, and in ASCII there is
   nothing to weigh - one character outside the set decides. Does NOT
   catch: text assembled at runtime from data (see gate 3).

3. **The rendering result** (every analysable fixture, plus the committed
   `examples/4sics/report.md` and the text layer of
   `examples/4sics/report.pdf`). A line carrying a character outside ASCII
   is a violation UNLESS every such character comes from a value the model
   marks with the OUI lookup provenance - vendor names from the IEEE
   registry carry letters from across Europe and Asia, they are external
   DATA rather than the author's text, and demanding ASCII of them would
   mean falsifying the registry.

   **Residual risk, named rather than promised:** the exception is granted
   per line, not per character. A line carrying both a vendor name and a
   non-ASCII character written by the author passes this gate. Gates 1 and
   2 cover the author's text at its source, so a character would have to
   enter through data interpolated into a template to slip through here.
"""

from __future__ import annotations

import ast
import unicodedata
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import pytest
import yaml
from pypdf import PdfReader

from wayside.assets.oui import PROVENANCE_METHOD_OUI
from wayside.checks import engine
from wayside.model import iter_observed_fields
from wayside.pcap import CaptureFormatError, CaptureTruncatedError
from wayside.pipeline import analyze
from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "pcap"
EXAMPLE_DIR = REPO_ROOT / "examples" / "4sics"
EXAMPLE_REPORT_MD = EXAMPLE_DIR / "report.md"
EXAMPLE_REPORT_PDF = EXAMPLE_DIR / "report.pdf"
GENERATED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)

# The provenance marker of a field whose value comes from the IEEE OUI
# registry rather than from the author's keyboard. Built from the constant
# in the production module, never from a literal repeated here - one source
# of truth for the marker shape.
OUI_PROVENANCE = f"inferred:{PROVENANCE_METHOD_OUI}"

# Modules producing document text. A MANUAL list, not automatic discovery
# (unlike `discover_checks` or `load_catalog`) - a module emitting document
# text added later has to be added here by hand, otherwise gates two and
# three quietly stop covering it.
DOCUMENT_TEXT_MODULES: tuple[Path, ...] = (
    REPO_ROOT / "src" / "wayside" / "report.py",
    REPO_ROOT / "src" / "wayside" / "report_pdf.py",
    REPO_ROOT / "src" / "wayside" / "flow.py",
    REPO_ROOT / "src" / "wayside" / "risk.py",
    REPO_ROOT / "src" / "wayside" / "coverage.py",
    REPO_ROOT / "src" / "wayside" / "assets" / "inventory.py",
    REPO_ROOT / "src" / "wayside" / "pipeline.py",
)

# A mapping of document field names onto the YAML file type.
DOCUMENT_TEXT_YAML_FIELDS: dict[str, tuple[str, ...]] = {
    "check": ("title", "rationale", "remediation"),
    "catalog": ("clause_title", "paraphrase", "verification_note", "paraphrase_note"),
}

# The exception list, shared by gates two and three. It starts EMPTY
# (assumption Z-88) and grows only by entries carrying a comment stating the
# reason - a list laid down in advance is a way of passing a gate without
# fixing anything.
ORTHOGRAPHY_ALLOWLIST: tuple[str, ...] = ()


def _non_ascii_chars(text: str) -> set[str]:
    return {ch for ch in text if ord(ch) > 127}


# The public name of the predicate above, shared with the README and
# SECURITY.md gates (`tests/test_readme_claims.py`,
# `tests/test_security_md.py`). Those two files used to import the set of
# eighteen Polish letters from here and assert its absence; the rule they
# express is unchanged - the author's text in this repository is written in
# ASCII - only its formulation moved from one alphabet to the whole range
# above ASCII.
non_ascii_chars = _non_ascii_chars


def _check_specs() -> list[dict]:
    """The raw dictionaries read from every YAML file under the checks
    directory - the `tests/test_standards_catalog.py::check_specs`
    pattern."""
    return [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(engine.CHECKS_ROOT.rglob("*.yaml"))
    ]


def _analyzable_fixtures() -> list[Path]:
    """Every fixture in the directory that finishes analysis without an
    exception - the `tests/test_report_forbidden_phrases.py::_analyzable_fixtures`
    pattern."""
    return sorted(FIXTURE_DIR.glob("*.pcap")) + sorted(FIXTURE_DIR.glob("*.pcapng"))


def _analyze_or_skip(fixture: Path, out_dir: Path):
    try:
        return analyze(fixture, out_dir=out_dir, generated_at=GENERATED_AT)
    except (CaptureTruncatedError, CaptureFormatError):
        pytest.skip(f"fixture {fixture.name} produces no artifacts (gate D-01)")


def _docstring_constant_ids(tree: ast.AST) -> set[int]:
    """Collects the `id()` of `Constant` nodes that are the docstring of a
    module, class or function - the first statement of a body, when it is
    `Expr(Constant(str))`. Docstrings are text for the developer, not for
    the reader of the report, and stand outside gates two and three."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            ids.add(id(first.value))
    return ids


def _string_constants(module_path: Path) -> list[tuple[int, str]]:
    """Every string constant of a module (the literal parts of f-strings
    included), with its line number, skipping docstrings."""
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(module_path))
    docstring_ids = _docstring_constant_ids(tree)
    results: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstring_ids:
                continue
            results.append((node.lineno, node.value))
    return results


@lru_cache(maxsize=1)
def _oui_values_from_every_fixture() -> frozenset[str]:
    """Every vendor name that any analysable fixture puts into the model
    under the OUI lookup provenance.

    Collected from the model rather than from the OUI table file: the gate
    then grants its exception to exactly the values that actually reached a
    report, and adding a row to the table does not silently widen it."""
    import tempfile

    values: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp:
        for fixture in _analyzable_fixtures():
            try:
                result = analyze(
                    fixture, out_dir=Path(tmp), generated_at=GENERATED_AT
                )
            except (CaptureTruncatedError, CaptureFormatError):
                continue
            for entry in result.analysis.get("assets", []):
                for _path, field in iter_observed_fields(entry):
                    if field["provenance"] != OUI_PROVENANCE:
                        continue
                    if isinstance(field["value"], str):
                        values.add(field["value"])
    return frozenset(values)


def _non_ascii_violations(text: str) -> list[tuple[int, str]]:
    """Lines of `text` carrying a character outside ASCII that no vendor
    name on the same line accounts for."""
    vendor_values = [value for value in _oui_values_from_every_fixture() if value]
    violations: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not _non_ascii_chars(line):
            continue
        if line in ORTHOGRAPHY_ALLOWLIST:
            continue
        remainder = line
        for value in vendor_values:
            if value in remainder:
                remainder = remainder.replace(value, "")
        if _non_ascii_chars(remainder):
            violations.append((lineno, line))
    return violations


# --- The ASCII predicate: unit tests on cases outside the corpus, so that a
# --- gate failure can be told apart from a failure of its own mechanics. ---


def test_non_ascii_detector_flags_letters_outside_ascii():
    assert _non_ascii_chars("zolc") == set()
    assert _non_ascii_chars("zazolc") == set()
    assert _non_ascii_chars("Societe Generale") == set()
    assert _non_ascii_chars("Société") == {"é"}


def test_non_ascii_detector_flags_the_stroke_letter():
    """The stroke letter has no canonical decomposition in Unicode, so a
    detector built on `NFKD` alone would miss it - this one is built on the
    code point value, which has no such gap."""
    assert unicodedata.normalize("NFKD", "l") == "l"
    assert _non_ascii_chars("l") == set()
    assert _non_ascii_chars("ł") == {"ł"}


def test_non_ascii_detector_flags_every_letter_of_the_previous_alphabet():
    """The eighteen letters this gate used to require are now exactly the
    eighteen it rejects."""
    previous_alphabet = "ąćęłńóśźż"
    for letter in previous_alphabet + previous_alphabet.upper():
        assert _non_ascii_chars(letter) == {letter}


# --- Gate one: YAML document fields - no threshold, no exceptions --------


def test_catalog_document_fields_are_ascii():
    catalog = mapper.load_catalog()
    failures: list[str] = []
    for (standard, clause), entry in catalog.items():
        for field in DOCUMENT_TEXT_YAML_FIELDS["catalog"]:
            if field not in entry:
                continue
            found = _non_ascii_chars(entry[field])
            if found:
                failures.append(f"{standard} {clause}: field {field}: {sorted(found)}")
    assert failures == [], failures


def test_check_document_fields_are_ascii():
    failures: list[str] = []
    for spec in _check_specs():
        for field in DOCUMENT_TEXT_YAML_FIELDS["check"]:
            found = _non_ascii_chars(spec[field])
            if found:
                failures.append(f"{spec['id']}: field {field}: {sorted(found)}")
    assert failures == [], failures


# --- Gate two: prose in the document text modules -----------------------


def test_document_text_modules_are_ascii_or_allowlisted():
    failures: list[str] = []
    for module_path in DOCUMENT_TEXT_MODULES:
        for lineno, text in _string_constants(module_path):
            if text in ORTHOGRAPHY_ALLOWLIST:
                continue
            found = _non_ascii_chars(text)
            if found:
                failures.append(f"{module_path}:{lineno}: {sorted(found)} in {text!r}")
    assert failures == [], "\n".join(failures)


# --- Gate three: the rendering result -----------------------------------


@pytest.mark.parametrize("fixture", _analyzable_fixtures(), ids=lambda p: p.name)
def test_rendered_report_is_ascii_apart_from_vendor_names(fixture, tmp_path):
    result = _analyze_or_skip(fixture, tmp_path)
    hits = _non_ascii_violations(result.report_markdown)
    assert hits == [], f"{fixture.name}: {hits}"


def test_committed_example_report_markdown_is_ascii_apart_from_vendor_names():
    text = EXAMPLE_REPORT_MD.read_text(encoding="utf-8")
    hits = _non_ascii_violations(text)
    assert hits == [], hits


def test_committed_example_report_pdf_text_layer_is_ascii_apart_from_vendor_names():
    reader = PdfReader(str(EXAMPLE_REPORT_PDF))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    hits = _non_ascii_violations(text)
    assert hits == [], hits


# --- NFC normalisation ---------------------------------------------------


def test_rendered_report_is_nfc_normalized(tmp_path):
    fixture = FIXTURE_DIR / "modbus_write_single_register.pcap"
    result = analyze(fixture, out_dir=tmp_path, generated_at=GENERATED_AT)
    text = result.report_markdown
    assert unicodedata.normalize("NFC", text) == text
