"""Bramka ksztaltu rekordu audytu historii (`compliance/history-audit.md`).

Ten modul jest zaleznosciowo izolowany od reszty pakietu `wayside` i uzywa
WYLACZNIE biblioteki standardowej Pythona plus modulu siostrzanej bramki
(`check_pub_gate`) z TEGO SAMEGO katalogu. To jest warunek, nie preferencja:
bramka ma dzialac jako krok wstepny przed kazdym publicznym pushem, takze na
maszynie bez zsynchronizowanego srodowiska projektu (bez `uv sync`) -
dokladnie ten sam powod, ktory stoi w docstringu `check_pub_gate.py`.

Ten skrypt sprawdza WYLACZNIE ksztalt rekordu i jego aktualnosc wobec
biezacego HEAD - nigdy to, czy skan trzech powierzchni FAKTYCZNIE sie odbyl.
To sprawdza test ze znacznikiem wolnym (`tests/test_history_audit.py`),
uruchamiany osobno (lokalnie na zadanie, w CI jawnym krokiem). Rekord i skan
sa dwoma polowami tego samego rozstrzygniecia (D-21): rekord bez powtorzenia
skanu jest podpisem bez tresci, a skan bez rekordu jest wynikiem bez sladu.

Frontmatter jest parsowany CZYTNIKIEM SIOSTRZANEJ BRAMKI (`check_pub_gate.load_record`)
- ten sam ksztalt (pary `klucz: wartosc` miedzy dwiema liniami `---`), zeby
dwie bramki rekordow tego repozytorium nie mialy dwoch czytnikow, ktore sie
rozjada.

Import `check_pub_gate` dziala w OBU kontekstach wywolania tego skryptu:
uruchomionego wprost sciezka do pliku (`python scripts/check_history_audit_gate.py`
- Python automatycznie dopisuje katalog skryptu jako pierwszy wpis
`sys.path`) oraz zaimportowanego z testu, ktory jawnie dopisuje katalog
`scripts/` do `sys.path` (`tests/test_check_history_audit_gate.py`, wzorem
`tests/test_check_pub_gate.py`).

Kody wyjscia (czesc kontraktu, musza byc rozroznialne, SZESC pozycji):
    0 - rekord kompletny, podpisany przez czlowieka, aktualny (jesli
        zadana flaga aktualnosci), z jawnym wynikiem
    1 - wynik `hits-outside-exceptions` przy podanej fladze `--require-clean`
    3 - brak pliku rekordu
    4 - rekord niekompletny albo naruszajacy regule ksztaltu (w tym pole
        `author` nalezace do zbioru nazw agentowych)
    5 - rekord CZEKA na podpis czlowieka (pole `author` albo `confirmed_on`
        puste) - stan OCZEKUJACY, NIE blad ksztaltu (rozstrzygniecie R-8):
        wykonawca planu nie ma jak podpisac sie za czlowieka, a odroznienie
        rekordu niedokonczonego od rekordu zlego jest tym, co pozwala tej
        bramce byc uzyteczna w obu momentach
    6 - pole `head_sha` rozne od biezacego HEAD, WYLACZNIE przy podanej
        fladze `--require-current` (zalozenie Z-100: bez tej flagi roznica
        nie jest bledem - rekord starzeje sie z kazdym nastepnym commitem,
        a aktualnosci wymaga sie w JEDNYM miejscu, w ktorym ma to znaczenie:
        w bramce przed publicznym pushem, czyli w checkpoincie zadania 3)
"""

from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

import check_pub_gate

__all__ = [
    "DEFAULT_RECORD_PATH",
    "REQUIRED_KEYS",
    "VALID_RESULTS",
    "REQUIRED_SURFACES",
    "REQUIRED_RULES",
    "EXIT_OK",
    "EXIT_REQUIRE_CLEAN_FAILED",
    "EXIT_MISSING_FILE",
    "EXIT_INVALID_SHAPE",
    "EXIT_PENDING",
    "EXIT_STALE_HEAD",
    "validate_record",
    "main",
]

DEFAULT_RECORD_PATH = "compliance/history-audit.md"

REQUIRED_KEYS: tuple[str, ...] = (
    "requirement",
    "scope",
    "audited_on",
    "head_sha",
    "surfaces",
    "rules_checked",
    "exceptions_file",
    "result",
    "author",
    "confirmed_on",
)

VALID_RESULTS: frozenset[str] = frozenset({"clean", "hits-outside-exceptions", "pending"})

# Trzy powierzchnie z zadania 1 (`tests/test_history_audit.py::HISTORY_SURFACES`).
# Nie importowane stamtad wprost: modul testowy nie jest zaleznoscia, ktora
# ten skrypt (biblioteka standardowa + siostrzana bramka, patrz test izolacji
# po drzewie skladniowym) moze niesc. Wartosci sa jednak IDENTYCZNE - to jest
# jedyne miejsce, w ktorym rekord jest zestawiany z rzeczywistym zakresem
# skanu, wiec rozszerzenie powierzchni skanu wymaga rozszerzenia tej krotki
# w OBU miejscach, inaczej rekord twierdzi wiecej, niz skan sprawdzil.
REQUIRED_SURFACES: tuple[str, str, str] = ("tree-content", "commit-message", "file-name")

# Cztery reguly KSZTALTU warstwy tozsamosciowej (`IDENTITY_RULE_IDS[:-1]` w
# `scripts/confidentiality_guard.py` i w `tests/test_history_audit.py`) -
# NIE piata, lokalna (`identity-local-literal`), bo ta dziala WYLACZNIE
# lokalnie z pliku gitignorowanego i audyt historii (ktory ma dzialac w CI)
# nie ma z czego jej sprawdzic. Ta sama uwaga o jednym miejscu zestawienia
# jak wyzej przy `REQUIRED_SURFACES` dotyczy i tej krotki.
REQUIRED_RULES: tuple[str, ...] = (
    "identity-private-ipv4",
    "identity-mac-address",
    "identity-device-name",
    "identity-project-name",
)

EXIT_OK = 0
EXIT_REQUIRE_CLEAN_FAILED = 1
EXIT_MISSING_FILE = 3
EXIT_INVALID_SHAPE = 4
EXIT_PENDING = 5
EXIT_STALE_HEAD = 6


def _current_head_sha() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def validate_record(fields: dict[str, str], body: str) -> list[str]:
    """Sprawdza WYLACZNIE ksztalt rekordu (obecnosc kluczy, dozwolone
    wartosci, parsowalnosc dat, regula pola `author`) i zwraca liste bledow
    - PUSTA lista znaczy ksztalt poprawny.

    Pole `author` PUSTE i pole `confirmed_on` PUSTE NIE sa bledami ksztaltu
    tutaj (rozstrzygniecie R-8) - to jest odrebny stan (OCZEKUJACY),
    rozpoznawany przez `main()` PO tym, jak ta funkcja zwroci pusta liste.
    Pole `author` NIEPUSTE, ktore nalezy do zbioru nazw agentowych, JEST
    bledem ksztaltu - wykonawca planu nie ma jak podpisac sie za czlowieka,
    a proba zrobienia tego (albo wpisania oczywistej wartosci zastepczej)
    ma zapalic te sama bramke, ktora siostrzana bramka stosuje do pola
    `reviewer`.
    """
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        return [f"Rekord niekompletny: brak pol {', '.join(missing)}."]

    errors: list[str] = []

    result = fields["result"].strip()
    if result not in VALID_RESULTS:
        errors.append(
            f"Pole result ma niedozwolona wartosc: {result!r} (dozwolone: "
            f"{sorted(VALID_RESULTS)})."
        )

    surfaces = {s.strip() for s in fields["surfaces"].split(",") if s.strip()}
    if surfaces != set(REQUIRED_SURFACES):
        errors.append(
            f"Pole surfaces niesie niepelna albo niewlasciwa liste "
            f"powierzchni: {fields['surfaces']!r} (wymagane: "
            f"{sorted(REQUIRED_SURFACES)})."
        )

    rules = {r.strip() for r in fields["rules_checked"].split(",") if r.strip()}
    if rules != set(REQUIRED_RULES):
        errors.append(
            f"Pole rules_checked niesie niepelna albo niewlasciwa liste "
            f"regul: {fields['rules_checked']!r} (wymagane: "
            f"{sorted(REQUIRED_RULES)})."
        )

    audited_on = fields["audited_on"].strip()
    try:
        datetime.date.fromisoformat(audited_on)
    except ValueError:
        errors.append(
            f"Pole audited_on nie jest poprawna data ISO (YYYY-MM-DD): "
            f"{audited_on!r}."
        )

    author = fields["author"].strip()
    if author and check_pub_gate.reviewer_is_invalid(author):
        errors.append(
            "Pole author jest wartoscia zastepcza albo wskazuje na agenta "
            "zamiast na czlowieka."
        )

    confirmed_on = fields["confirmed_on"].strip()
    if confirmed_on:
        try:
            datetime.date.fromisoformat(confirmed_on)
        except ValueError:
            errors.append(
                f"Pole confirmed_on nie jest poprawna data ISO (YYYY-MM-DD): "
                f"{confirmed_on!r}."
            )

    return errors


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_history_audit_gate",
        description=(
            "Bramka ksztaltu rekordu audytu trzech powierzchni calej "
            "historii repozytorium (PUB-05): sprawdza WYLACZNIE ksztalt "
            "i aktualnosc rekordu, nigdy to, czy skan faktycznie sie odbyl."
        ),
    )
    parser.add_argument(
        "--record",
        default=DEFAULT_RECORD_PATH,
        help=f"Sciezka do rekordu (domyslnie {DEFAULT_RECORD_PATH}).",
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help=(
            "Wymus result=clean: rekord z wynikiem hits-outside-exceptions "
            "konczy sie wtedy kodem 1 zamiast 0."
        ),
    )
    parser.add_argument(
        "--require-current",
        action="store_true",
        help=(
            "Wymus rownosc pola head_sha z biezacym HEAD: rekord "
            "wskazujacy inny skrot konczy sie wtedy kodem 6. Bez tej flagi "
            "roznica nie jest bledem (zalozenie Z-100)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    record_path = Path(args.record)

    try:
        fields, body = check_pub_gate.load_record(record_path)
    except FileNotFoundError:
        print(f"Brak pliku rekordu: {record_path}", file=sys.stderr)
        return EXIT_MISSING_FILE
    except check_pub_gate.RecordShapeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_SHAPE

    shape_errors = validate_record(fields, body)
    if shape_errors:
        for error in shape_errors:
            print(error, file=sys.stderr)
        return EXIT_INVALID_SHAPE

    author = fields["author"].strip()
    confirmed_on = fields["confirmed_on"].strip()
    if not author or not confirmed_on:
        print(
            "Rekord audytu czeka na podpis czlowieka (pole author albo "
            "confirmed_on jest puste) - to jest stan oczekiwany, nie blad.",
            file=sys.stderr,
        )
        return EXIT_PENDING

    if args.require_current:
        current_head = _current_head_sha()
        record_head = fields["head_sha"].strip()
        if record_head != current_head:
            print(
                f"Rekord wskazuje skrot HEAD {record_head!r}, biezacy HEAD "
                f"to {current_head!r} - wymagany ponowny audyt przed "
                "publicznym pushem.",
                file=sys.stderr,
            )
            return EXIT_STALE_HEAD

    result = fields["result"].strip()
    print(f"result={result}")
    if args.require_clean and result != "clean":
        print(
            "Wymagano result=clean (flaga --require-clean), a rekord "
            f"niesie wynik {result!r}.",
            file=sys.stderr,
        )
        return EXIT_REQUIRE_CLEAN_FAILED

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
