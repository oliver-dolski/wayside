"""Generation of the example report from a slice of the 4SICS capture (REPORT-05).

Usage:
    uv run python scripts/gen_example_report.py
        Runs the full analysis on the slice file built by
        `scripts/fetch_4sics_sample.py` and writes three artifacts under
        `examples/4sics/`: `analysis.json`, `report.md`, `report.pdf`.

    uv run python scripts/gen_example_report.py --slice path/to/slice.pcap
        Overrides the path of the slice file.

    uv run python scripts/gen_example_report.py --output-dir output/path
        Overrides the output directory - useful when comparing the result
        against the files already committed to the repository
        (reproducibility test).

Two properties this script carries that MUST stay true:

1. The generation timestamp is a CONSTANT (`FIXED_GENERATED_AT`), never a
   read of the system clock - two runs at different moments therefore
   produce the same file (04-RESEARCH.md, Pitfall 7; D-02 from Phase 2).
2. The three artifacts in that directory are compared byte for byte against
   freshly generated files (reproducibility test,
   tests/test_example_report.py). That is why `examples/4sics/report.md` and
   `examples/4sics/analysis.json` are excluded from line-ending
   normalization in `.gitattributes` (assumption Z-72): without that
   exclusion the committed file would pass through git normalization on
   checkout while the freshly generated one would not, and the byte
   comparison would be putting two different things side by side.

This script is a DEVELOPER operation. `wayside analyze` never calls it.
Its reproducibility is limited to a slice file sitting on disk under the
same path and with the same content - build it first with
`scripts/fetch_4sics_sample.py` if you do not have it.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from fetch_4sics_sample import DATASET_DIR, SLICE_FILENAME  # noqa: E402

from wayside.model import write_atomic_bytes  # noqa: E402
from wayside.pipeline import analyze  # noqa: E402
from wayside.report_pdf import render_pdf  # noqa: E402

__all__ = ["FIXED_GENERATED_AT", "EXAMPLE_DIR", "generate", "main"]

# Date of decision record `0005` (the one that settled the 4SICS capture as
# the source of the example report), in universal time - an arbitrary
# constant would be a value nobody could justify at the first correction;
# this date ties the artifact to the decision that called it into being
# (assumption Z-74).
FIXED_GENERATED_AT = datetime(2026, 9, 4, tzinfo=timezone.utc)

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "4sics"

DEFAULT_SLICE_PATH = DATASET_DIR / SLICE_FILENAME


def generate(slice_path: Path, output_dir: Path = EXAMPLE_DIR) -> tuple[Path, Path, Path]:
    """Generates the three example report artifacts under `output_dir` from
    the slice file `slice_path`. Returns the triple of paths
    (analysis_path, report_path, pdf_path).

    Calls `wayside.pipeline.analyze` with `FIXED_GENERATED_AT` - that
    function writes the first two artifacts (`analysis.json`, `report.md`)
    itself, so this script does not write them a second time. `render_pdf`
    is called DIRECTLY on THE SAME model dictionary, with THE SAME timestamp
    and THE SAME warnings the analysis returned - never through a subprocess
    running the CLI command (04-RESEARCH.md, Open Question 2: the CLI
    command takes its timestamp from the clock, and this script needs a
    constant)."""
    result = analyze(Path(slice_path), out_dir=Path(output_dir), generated_at=FIXED_GENERATED_AT)

    pdf_bytes = render_pdf(
        result.analysis, generated_at=FIXED_GENERATED_AT, warnings=result.warnings
    )
    pdf_path = Path(output_dir) / "report.pdf"
    write_atomic_bytes(pdf_path, pdf_bytes)

    return result.analysis_path, result.report_path, pdf_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slice",
        type=Path,
        default=DEFAULT_SLICE_PATH,
        help=f"Path of the slice file (default {DEFAULT_SLICE_PATH}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=EXAMPLE_DIR,
        help=f"Output directory (default {EXAMPLE_DIR}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if not args.slice.is_file():
        print(
            f"The slice file {args.slice} does not exist. Build it first: "
            "uv run python scripts/fetch_4sics_sample.py",
            file=sys.stderr,
        )
        return 1

    analysis_path, report_path, pdf_path = generate(args.slice, args.output_dir)
    print(f"Written: {analysis_path}")
    print(f"Written: {report_path}")
    print(f"Written: {pdf_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
