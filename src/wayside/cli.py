"""Entrypoint CLI narzedzia Wayside: komenda `inspect` oraz flaga `--version`.

Narzedzie jest pasywne: zadna komenda tutaj nie otwiera interfejsu sieciowego,
nie przechwytuje ruchu na zywo i nie wysyla pakietow. Faza 1 nie otwiera tej
powierzchni.
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

# Kody wyjscia komendy `analyze`, rozroznialne dla kazdego trybu porazki
# (D-01) - nigdy jeden ogolny kod na wszystko. `EXIT_UNREADABLE` rowne 2
# jest zachowane swiadomie: `tests/test_cli_output_snapshot.py` i kontrakt
# komendy `inspect` z Fazy 1 na niej stoja.
EXIT_OK = 0
EXIT_UNREADABLE = 2
EXIT_TRUNCATED = 3
EXIT_UNSUPPORTED_FORMAT = 4
# Zrzut uszkodzony strukturalnie - struktura niespojna sama ze soba przy
# pelnej dlugosci pliku, rozne od obciecia strumienia (EXIT_TRUNCATED).
# Kryterium 2 fazy 3 wymienia trzy tryby porazki jako trzy osobne slowa,
# wiec kazdy dostaje wlasny kod wyjscia (zalozenie Z-12).
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
        help="Wypisz wersje narzedzia i zakoncz.",
    ),
) -> None:
    """Wayside - pasywna ocena bezpieczenstwa sieci OT ze zrzutu pcap."""


@app.command()
def inspect(
    path: Path = typer.Argument(..., help="Sciezka do pliku zrzutu pcap."),
) -> None:
    """Wczytuje zrzut pcap i wypisuje jego podsumowanie."""
    try:
        summary = summarize(path)
    except FileNotFoundError:
        typer.echo(f"Nie znaleziono pliku zrzutu: {path}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None
    except Exception as exc:
        # `read_capture` sprawdza tylko istnienie sciezki, a `Path.exists()`
        # jest prawdziwe takze dla katalogu. Poza tym istniejacy, ale
        # uszkodzony albo obciety pcap podnosi z `rdpcap` wyjatek z rodziny
        # `Scapy_Exception`/`struct.error`, ktorej nie da sie tu wyliczyc
        # z nazwy bez wiazania CLI z wewnetrznymi typami scapy. Uzytkownik
        # narzedzia ma dostac komunikat i kod 2, nie surowy traceback.
        typer.echo(f"Nie udalo sie odczytac zrzutu {path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None

    typer.echo(f"Plik: {summary.path}")
    typer.echo(f"Liczba pakietow: {summary.packet_count}")
    first = summary.first_timestamp.isoformat() if summary.first_timestamp else "-"
    last = summary.last_timestamp.isoformat() if summary.last_timestamp else "-"
    typer.echo(f"Pierwszy znacznik czasu: {first}")
    typer.echo(f"Ostatni znacznik czasu: {last}")
    # Zaokraglenie jest w formatowaniu, nie w `CaptureSummary` - roznica
    # znacznikow czasu w float niesie szum reprezentacji (0.01 s wychodzi
    # jako 0.009999990463256836), a przyszli konsumenci API maja dostac
    # wartosc nietkniata.
    typer.echo(f"Dlugosc okna (s): {summary.duration_s:.6f}")


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Sciezka do pliku zrzutu pcap."),
    out_dir: Path = typer.Option(
        Path("wayside-out"),
        "--out-dir",
        help="Katalog wyjsciowy na analysis.json i report.md.",
    ),
    export_pdf: bool = typer.Option(
        False,
        "--pdf/--no-pdf",
        help="Doloz trzeci artefakt, report.pdf, z osadzonym fontem Unicode.",
    ),
) -> None:
    """Uruchamia pelny potok analizy: od pliku pcap do dwoch albo trzech
    artefaktow (REPORT-03: `--pdf` dokladajac report.pdf jest opcja
    wlaczana, domyslnie wylaczona - zalozenie Z-51)."""
    # Znacznik czasu wygenerowania idzie do zmiennej lokalnej PRZED
    # wywolaniem potoku i ta sama wartosc wchodzi pozniej do renderowania
    # PDF - dwa osobne odczyty zegara dalyby markdown i PDF z roznymi
    # znacznikami z tego samego przebiegu (04-03-PLAN.md, Task 3).
    generated_at = datetime.now(timezone.utc)
    try:
        result = run_analyze(path, out_dir=out_dir, generated_at=generated_at)
    except FileNotFoundError:
        typer.echo(f"Nie znaleziono pliku zrzutu: {path}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None
    except CaptureCorruptError as exc:
        # `CaptureCorruptError` jest podklasa `CaptureTruncatedError` (Z-11),
        # wiec ten blok MUSI stac PRZED `except CaptureTruncatedError` -
        # odwrotna kolejnosc dawalaby kod 3 zamiast 5 dla kazdego przypadku.
        typer.echo(f"Zrzut uszkodzony strukturalnie: {exc}", err=True)
        raise typer.Exit(code=EXIT_CORRUPT) from None
    except CaptureTruncatedError as exc:
        # D-01: obciecie wykryte strukturalnie przez `audit_capture_structure`
        # PRZED jakimkolwiek zapisem - `out_dir` zostaje bez zadnego pliku.
        typer.echo(f"Zrzut obciety: {exc}", err=True)
        raise typer.Exit(code=EXIT_TRUNCATED) from None
    except CaptureFormatError as exc:
        typer.echo(f"Format zrzutu nieobslugiwany: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNSUPPORTED_FORMAT) from None
    except Exception as exc:
        # Ten sam szkielet co `inspect`: uzytkownik ma dostac czytelny
        # komunikat i kod 2, nie surowy traceback zwiazany z wewnetrznymi
        # typami scapy albo silnika checkow.
        typer.echo(f"Nie udalo sie przeanalizowac zrzutu {path}: {exc}", err=True)
        raise typer.Exit(code=EXIT_UNREADABLE) from None

    typer.echo(f"Zapisano: {result.analysis_path}")
    typer.echo(f"Zapisano: {result.report_path}")
    typer.echo(f"Liczba findingow: {len(result.analysis['findings'])}")
    for warning in result.warnings:
        typer.echo(f"Ostrzezenie: {warning}", err=True)

    if export_pdf:
        # Import WEWNATRZ galezi obslugujacej flage, nie na gorze pliku -
        # bez tego kazdy przebieg komendy analizy (takze dziesiatki testow
        # w podprocesie bez flagi) wciagalby biblioteke generowania PDF do
        # domyslnej sciezki narzedzia (FOUND-01, 04-03-PLAN.md Task 3).
        from wayside.model import write_atomic_bytes
        from wayside.report_pdf import PdfRenderError, render_pdf

        try:
            pdf_bytes = render_pdf(
                result.analysis, generated_at=generated_at, warnings=result.warnings
            )
        except PdfRenderError as exc:
            typer.echo(f"Nie udalo sie wyrenderowac pliku PDF: {exc}", err=True)
            raise typer.Exit(code=EXIT_UNREADABLE) from None
        pdf_path = out_dir / "report.pdf"
        write_atomic_bytes(pdf_path, pdf_bytes)
        typer.echo(f"Zapisano: {pdf_path}")


def _force_utf8_output() -> None:
    """Wymusza UTF-8 na wyjsciu procesu.

    Python ustawia `sys.stderr.errors` na `backslashreplace`, wiec na maszynie,
    ktorej kodowanie domyslne nie niesie polskich znakow (cp1252 na
    anglojezycznym Windows, a takze na runnerze CI), polska litera w ostrzezeniu
    narzedzia wychodzi jako `\\u0142` zamiast znaku. Ostrzezenie, ktorego
    uzytkownik nie przeczyta, nie jest ostrzezeniem - a `README` obiecuje
    dzialanie na Windows 11 bez zadnego dodatkowego kroku konfiguracyjnego.

    Ten sam blad zostal juz raz naprawiony po stronie odczytu w
    `tests/test_history_audit.py::_run_git`; tutaj jest naprawiony po stronie
    zapisu, czyli u zrodla.

    `reconfigure` istnieje wylacznie na `TextIOWrapper`, wiec strumien
    podmieniony na inny obiekt (przechwycenie wyjscia w tescie) jest pomijany
    bez bledu.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


def run() -> None:
    """Wejscie procesu: `python -m wayside.cli`."""
    _force_utf8_output()
    app()


if __name__ == "__main__":
    run()
