"""CLI entrypoint of the Wayside tool: the `inspect` command and the
`--version` flag.

The tool is passive: no command here opens a network interface, captures
live traffic or sends packets. Phase 1 does not open that surface.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from importlib.metadata import version as get_version
from pathlib import Path

import typer

from wayside.pcap import (
    CaptureCorruptError,
    CaptureFormatError,
    CaptureTruncatedError,
    summarize,
)
from wayside.pipeline import analyze as run_analyze

app = typer.Typer(add_completion=False)

# Exit codes of the `analyze` command, distinguishable for every failure
# mode (D-01) - never one generic code for everything. `EXIT_UNREADABLE`
# equal to 2 is kept deliberately: `tests/test_cli_output_snapshot.py` and
# the Phase 1 contract of the `inspect` command stand on it.
EXIT_OK = 0
EXIT_UNREADABLE = 2
EXIT_TRUNCATED = 3
EXIT_UNSUPPORTED_FORMAT = 4
# A structurally corrupt capture - a structure inconsistent with itself at
# the file's full length, distinct from a truncated stream (EXIT_TRUNCATED).
# Criterion 2 of phase 3 names three failure modes as three separate words,
# so each gets its own exit code (assumption Z-12).
EXIT_CORRUPT = 5


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(get_version("wayside"))
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the tool version and exit.",
    ),
) -> None:
    """Wayside - passive OT network security assessment from a pcap file."""


@app.command()
def inspect(
    path: Path = typer.Argument(..., help="Path to the pcap capture file."),
) -> None:
    """Reads a pcap capture and prints its summary."""
    try:
        summary = summarize(path)
    except FileNotFoundError:
        typer.echo(f"Capture file not found: {path}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None
    except Exception as exc:
        # `read_capture` only checks that the path exists, and `Path.exists()`
        # is true for a directory too. Beyond that, an existing but corrupt or
        # truncated pcap raises from `rdpcap` an exception of the
        # `Scapy_Exception`/`struct.error` family, which cannot be enumerated
        # here by name without binding the CLI to scapy's internal types. The
        # user of the tool is to get a message and code 2, not a raw
        # traceback.
        typer.echo(f"Failed to read capture {path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None

    typer.echo(f"File: {summary.path}")
    typer.echo(f"Packet count: {summary.packet_count}")
    first = summary.first_timestamp.isoformat() if summary.first_timestamp else "-"
    last = summary.last_timestamp.isoformat() if summary.last_timestamp else "-"
    typer.echo(f"First timestamp: {first}")
    typer.echo(f"Last timestamp: {last}")
    # Rounding lives in the formatting, not in `CaptureSummary` - the
    # difference of two float timestamps carries representation noise (0.01 s
    # comes out as 0.009999990463256836), and future API consumers are to get
    # the value untouched.
    typer.echo(f"Window length (s): {summary.duration_s:.6f}")


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Path to the pcap capture file."),
    out_dir: Path = typer.Option(
        Path("wayside-out"),
        "--out-dir",
        help="Output directory for analysis.json and report.md.",
    ),
    export_pdf: bool = typer.Option(
        False,
        "--pdf/--no-pdf",
        help="Add a third artifact, report.pdf, with an embedded Unicode font.",
    ),
) -> None:
    """Runs the full analysis pipeline: from a pcap file to two or three
    artifacts (REPORT-03: `--pdf`, which adds report.pdf, is opt-in and off
    by default - assumption Z-51)."""
    # The generation timestamp goes into a local variable BEFORE the pipeline
    # call and the same value later enters PDF rendering - two separate clock
    # reads would give markdown and PDF different timestamps from the same
    # run (04-03-PLAN.md, Task 3).
    generated_at = datetime.now(timezone.utc)
    try:
        result = run_analyze(path, out_dir=out_dir, generated_at=generated_at)
    except FileNotFoundError:
        typer.echo(f"Capture file not found: {path}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None
    except CaptureCorruptError as exc:
        # `CaptureCorruptError` is a subclass of `CaptureTruncatedError`
        # (Z-11), so this block MUST stand BEFORE `except
        # CaptureTruncatedError` - the reverse order would give code 3
        # instead of 5 in every case.
        typer.echo(f"Structurally corrupt capture: {exc}", err=True)
        raise typer.Exit(code=EXIT_CORRUPT) from None
    except CaptureTruncatedError as exc:
        # D-01: truncation detected structurally by `audit_capture_structure`
        # BEFORE any write - `out_dir` is left without a single file.
        typer.echo(f"Truncated capture: {exc}", err=True)
        raise typer.Exit(code=EXIT_TRUNCATED) from None
    except CaptureFormatError as exc:
        typer.echo(f"Unsupported capture format: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNSUPPORTED_FORMAT) from None
    except Exception as exc:
        # The same skeleton as `inspect`: the user is to get a readable
        # message and code 2, not a raw traceback tied to the internal types
        # of scapy or of the check engine.
        typer.echo(f"Failed to analyse capture {path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None

    typer.echo(f"Written: {result.analysis_path}")
    typer.echo(f"Written: {result.report_path}")
    typer.echo(f"Finding count: {len(result.analysis['findings'])}")
    for warning in result.warnings:
        typer.echo(f"Warning: {warning}", err=True)

    if export_pdf:
        # The import lives INSIDE the branch handling the flag, not at the
        # top of the file - without that, every run of the analyze command
        # (including dozens of subprocess tests without the flag) would pull
        # the PDF generation library into the tool's default path (FOUND-01,
        # 04-03-PLAN.md Task 3).
        from wayside.model import write_atomic_bytes
        from wayside.report_pdf import PdfRenderError, render_pdf

        try:
            pdf_bytes = render_pdf(
                result.analysis, generated_at=generated_at, warnings=result.warnings
            )
        except PdfRenderError as exc:
            typer.echo(f"Failed to render the PDF file: {exc}", err=True)
            raise typer.Exit(code=EXIT_UNREADABLE) from None
        pdf_path = out_dir / "report.pdf"
        write_atomic_bytes(pdf_path, pdf_bytes)
        typer.echo(f"Written: {pdf_path}")


def _force_utf8_output() -> None:
    """Forces UTF-8 on the process output.

    Python sets `sys.stderr.errors` to `backslashreplace`, so on a machine
    whose default encoding does not carry a character the tool prints (cp1252
    on English Windows, and on the CI runner too), a character outside that
    encoding comes out as `\\u0142` instead of the character itself. Vendor
    names read from the OUI table are the routine case: they carry letters
    from across Europe and Asia, and they land in warnings and in the report.
    A warning the user cannot read is not a warning - and the `README`
    promises the tool works on Windows 11 with no extra configuration step.

    The same fault was already fixed once on the read side in
    `tests/test_history_audit.py::_run_git`; here it is fixed on the write
    side, that is at the source.

    `reconfigure` exists only on `TextIOWrapper`, so a stream replaced by
    another object (output capture in a test) is skipped without an error.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def run() -> None:
    """Process entrypoint: `python -m wayside.cli`."""
    _force_utf8_output()
    app()


if __name__ == "__main__":
    run()
