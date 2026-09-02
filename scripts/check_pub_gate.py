"""Bramka ksztaltu rekordu PUB-01 (`compliance/pre-publication-review.md`).

Ten modul jest zaleznosciowo izolowany od reszty pakietu `wayside` i uzywa
WYLACZNIE biblioteki standardowej Pythona. To jest warunek, nie preferencja:
bramka ma dzialac jako krok wstepny przed kazdym publicznym pushem, takze na
maszynie bez zsynchronizowanego srodowiska projektu (bez `uv sync`).

Ten skrypt sprawdza WYLACZNIE ksztalt rekordu - obecnosc wymaganych pol,
parsowalnosc daty, brak cytatu blokowego w tresci i regule pola `reviewer`.
Nie sprawdza i nie moze sprawdzic, czy zapisane rozstrzygniecie odpowiada
temu, co czlowiek faktycznie powiedzial - to jest przedmiot weryfikacji
`backstop` w PLAN.md, nie kod.

Frontmatter jest parsowany wlasnym, prostym czytnikiem par `klucz: wartosc`
miedzy dwiema liniami separatora `---`, bez zadnej biblioteki YAML.

Kody wyjscia (czesc kontraktu, musza byc rozroznialne):
    0 - rekord kompletny z jawnym rozstrzygnieciem (`go` albo `no-go`)
    1 - rozstrzygniecie `no-go` przy podanej fladze `--require-go`
    3 - brak pliku rekordu
    4 - rekord niekompletny albo naruszajacy regule tresci
    5 - rozstrzygniecie wciaz `pending`
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

__all__ = ["load_record", "validate_record", "main"]

DEFAULT_RECORD_PATH = "compliance/pre-publication-review.md"

REQUIRED_KEYS: tuple[str, ...] = (
    "requirement",
    "scope",
    "reviewed_on",
    "reviewer",
    "verdict",
)

VALID_VERDICTS: frozenset[str] = frozenset({"go", "no-go", "pending"})

# Jedyna kontrola przeciw sfabrykowaniu rozstrzygniecia, jaka da sie zapisac
# w kodzie: pole `reviewer` nie moze nalezec do listy nazw agentowych. Nie
# wykrywa czlowieka podszywajacego sie pod samego siebie ani agenta
# wpisujacego prawdziwe imie autora - zgodnosc zapisu z wypowiedziana
# decyzja pozostaje predykatem typu backstop (patrz PLAN.md, must_haves).
AGENT_REVIEWER_NAMES: frozenset[str] = frozenset(
    {"claude", "agent", "automated", "bot", "gsd"}
)

EXIT_OK = 0
EXIT_REQUIRE_GO_FAILED = 1
EXIT_MISSING_FILE = 3
EXIT_INVALID_SHAPE = 4
EXIT_PENDING = 5


class RecordShapeError(ValueError):
    """Frontmatter zle uformowany (brak separatorow, linia bez dwukropka)."""


def load_record(path: Path) -> tuple[dict[str, str], str]:
    """Wczytuje rekord: frontmatter jako pary klucz-wartosc oraz tresc.

    Podnosi `FileNotFoundError`, gdy plik nie istnieje, i `RecordShapeError`,
    gdy frontmatter nie jest zamkniety miedzy dwiema liniami `---`. Puste
    linie i linie zaczynajace sie od `#` wewnatrz frontmatteru sa pomijane.
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    if not lines or lines[0].strip() != "---":
        raise RecordShapeError(
            f"Rekord {path} nie zaczyna sie od separatora frontmatteru '---'."
        )

    fields: dict[str, str] = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip() != "---":
        raw_line = lines[idx]
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            if ":" not in raw_line:
                raise RecordShapeError(
                    f"Rekord {path}, linia {idx + 1}: brak dwukropka we "
                    f"frontmatterze ({raw_line!r})."
                )
            key, _, value = raw_line.partition(":")
            fields[key.strip()] = value.strip()
        idx += 1

    if idx >= len(lines):
        raise RecordShapeError(
            f"Rekord {path} nie ma zamykajacego separatora frontmatteru '---'."
        )

    body = "\n".join(lines[idx + 1 :])
    return fields, body


def _reviewer_is_invalid(reviewer: str) -> bool:
    """Sprawdza pole `reviewer`: puste, wartosc zastepcza albo nazwa agenta."""
    if not reviewer:
        return True
    if "<" in reviewer or ">" in reviewer:
        return True
    if "tbd" in reviewer.lower():
        return True
    tokens = {tok.strip(".,;:").lower() for tok in reviewer.split()}
    if tokens & AGENT_REVIEWER_NAMES:
        return True
    return False


def _body_has_blockquote(body: str) -> int | None:
    """Zwraca numer pierwszej linii tresci zaczynajacej sie od cytatu

    blokowego markdown (`>`), albo `None`, gdy tresc jest czysta.
    """
    for line_no, line in enumerate(body.splitlines(), start=1):
        if line.strip().startswith(">"):
            return line_no
    return None


def validate_record(fields: dict[str, str], body: str) -> tuple[int, str]:
    """Sprawdza ksztalt rekordu i zwraca (kod_wyjscia, komunikat).

    Kolejnosc sprawdzen ma znaczenie: brak pola i naruszenie regoly tresci
    (cytat blokowy) sa naruszeniami ksztaltu i wygrywaja zawsze, takze na
    rekordzie jeszcze nierozstrzygnietym (`pending`). Rozstrzygniecie
    `pending` jest sprawdzane PRZED regulami pol `reviewer`/`reviewed_on`,
    bo te pola sa w stanie poczatkowym celowo puste - to nie jest naruszenie
    ksztaltu, to jest stan "jeszcze nie zdecydowano".
    """
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        return (
            EXIT_INVALID_SHAPE,
            f"Rekord niekompletny: brak pol {', '.join(missing)}.",
        )

    blockquote_line = _body_has_blockquote(body)
    if blockquote_line is not None:
        return (
            EXIT_INVALID_SHAPE,
            f"Rekord zawiera cytat blokowy w linii {blockquote_line} tresci: "
            f"rekord nie moze cytowac ani parafrazowac umowy.",
        )

    verdict = fields["verdict"].strip()
    if verdict not in VALID_VERDICTS:
        return (
            EXIT_INVALID_SHAPE,
            f"Pole verdict ma niedozwolona wartosc: {verdict!r}.",
        )

    if verdict == "pending":
        return (
            EXIT_PENDING,
            "Rozstrzygniecie bramki PUB-01 jeszcze nie zapadlo (verdict=pending).",
        )

    reviewer = fields["reviewer"].strip()
    if _reviewer_is_invalid(reviewer):
        return (
            EXIT_INVALID_SHAPE,
            "Pole reviewer jest puste, jest wartoscia zastepcza albo "
            "wskazuje na agenta zamiast na czlowieka.",
        )

    reviewed_on = fields["reviewed_on"].strip()
    if not reviewed_on:
        return (EXIT_INVALID_SHAPE, "Pole reviewed_on jest puste.")
    try:
        datetime.date.fromisoformat(reviewed_on)
    except ValueError:
        return (
            EXIT_INVALID_SHAPE,
            f"Pole reviewed_on nie jest poprawna data ISO (YYYY-MM-DD): "
            f"{reviewed_on!r}.",
        )

    return (EXIT_OK, f"verdict={verdict}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_pub_gate",
        description=(
            "Bramka ksztaltu rekordu PUB-01: sprawdza, czy przeglad umowy "
            "o prace jest zapisany w postaci maszynowo czytelnej."
        ),
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Sciezka do rekordu (domyslnie {DEFAULT_RECORD_PATH}).",
    )
    parser.add_argument(
        "--require-go",
        action="store_true",
        help=(
            "Wymus verdict=go: rekord z verdict=no-go konczy sie wtedy "
            "kodem 1 zamiast 0."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    record_path = Path(args.record_path)

    try:
        fields, body = load_record(record_path)
    except FileNotFoundError:
        print(f"Brak pliku rekordu: {record_path}", file=sys.stderr)
        return EXIT_MISSING_FILE
    except RecordShapeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_SHAPE

    code, message = validate_record(fields, body)

    if code == EXIT_OK:
        verdict = fields["verdict"].strip()
        print(f"verdict={verdict}")
        if args.require_go and verdict != "go":
            print(
                "Wymagano verdict=go (flaga --require-go), a rekord niesie "
                f"rozstrzygniecie {verdict!r}.",
                file=sys.stderr,
            )
            return EXIT_REQUIRE_GO_FAILED
        return EXIT_OK

    print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
