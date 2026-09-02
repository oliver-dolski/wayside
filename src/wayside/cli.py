"""Entrypoint CLI narzedzia Wayside: komenda `inspect` oraz flaga `--version`.

Narzedzie jest pasywne: zadna komenda tutaj nie otwiera interfejsu sieciowego,
nie przechwytuje ruchu na zywo i nie wysyla pakietow. Faza 1 nie otwiera tej
powierzchni.
"""

from __future__ import annotations

import sys
from importlib.metadata import version as get_version
from pathlib import Path

import typer

from wayside.pcap import summarize

app = typer.Typer(add_completion=False)


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
        raise typer.Exit(code=2) from None

    typer.echo(f"Plik: {summary.path}")
    typer.echo(f"Liczba pakietow: {summary.packet_count}")
    first = summary.first_timestamp.isoformat() if summary.first_timestamp else "-"
    last = summary.last_timestamp.isoformat() if summary.last_timestamp else "-"
    typer.echo(f"Pierwszy znacznik czasu: {first}")
    typer.echo(f"Ostatni znacznik czasu: {last}")
    typer.echo(f"Dlugosc okna (s): {summary.duration_s}")


def run() -> None:
    """Wejscie procesu: `python -m wayside.cli`."""
    app()


if __name__ == "__main__":
    run()
