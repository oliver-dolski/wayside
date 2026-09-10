"""Bramka tresci pliku `LICENSE` (PUB-04, D-02, D-03, zalozenia Z-88, Z-89).

Ta bramka sprawdza TRESC pliku licencji, nie jej skutek prawny. Ocena skutku
prawnego wybranej licencji nie jest zagrozeniem technicznym i nie jest
przedmiotem zadnego testu w tym module - rekord decyzji
`docs/decisions/0007-apache-2-0-license.md` nazywa ryzyko rezydualne wprost,
a porady prawnej nie udziela ani ten plik, ani ten rekord.

**Porownanie idzie po normalizacji koncow linii do pojedynczego znaku
(zalozenie Z-89), nie bajt w bajt.** Powod jest zmierzony przy planowaniu:
`.gitattributes` niesie `* text=auto`, a lokalna konfiguracja gita ma
wlaczona konwersje przy checkoucie, wiec plik tekstowy w drzewie roboczym na
tej maszynie ma konce linii dwuznakowe. Porownanie bajtowe dawaloby wynik
zalezny od platformy i od lokalnej konfiguracji gita - bramke, ktora
czerwieni sie u kogos innego bez zadnej zmiany w tresci.

**Roznica wobec tekstu kanonicznego jest DOKLADNIE jedna linia (zalozenie
Z-88):** wiersz praw autorskich w bloku koncowym, z zastapionymi obiema
wartosciami w nawiasach kwadratowych. Test skrotu buduje tresc z podstawionym
z powrotem wierszem wzorcowym i porownuje skrot sha256 z wartoscia zmierzona
przy planowaniu (pobranie 2026-09-09 z
`https://www.apache.org/licenses/LICENSE-2.0.txt`, konce linii jako
pojedynczy znak nowej linii). Test markerow strukturalnych sprawdza obecnosc
kazdego z dziewieciu numerowanych punktow i linii konca warunkow OSOBNO, zeby
komunikat porazki wskazywal brakujacy punkt po nazwie, nigdy fragmentem
tresci licencji.

Test niezmienionej nazwy projektu (D-03) sprawdza pole nazwy pakietu i wpis
komendy wiersza polecen w `pyproject.toml` wobec stalych `PACKAGE_NAME`
i `CLI_ENTRY_POINT` - rozstrzygniecie o nazwie zostalo potwierdzone, a nie
pominiete, wiec zostawia slad maszynowy, ktory zaczerwieni sie przy cichej
zmianie.

Modul nie zapisuje i nie zmienia zadnego pliku w drzewie repozytorium -
przypadki negatywne budowane sa na tekscie w pamieci, nigdy przez zapis do
`LICENSE` (patrz `test_module_source_contains_no_file_write_calls` na koncu
pliku, wzorzec `tests/test_readme_claims.py`).
"""

from __future__ import annotations

import hashlib
import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

LICENSE_PATH = REPO_ROOT / "LICENSE"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# Skrot sha256 tekstu kanonicznego (pobranie 2026-09-09, konce linii jako
# pojedynczy znak nowej linii) - zmierzony przy planowaniu, zapisany w
# 05-02-PLAN.md, tabela "Fakty zmierzone przy planowaniu".
CANONICAL_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

# Liczba linii tekstu kanonicznego po normalizacji koncow linii - zmierzona
# przy planowaniu tym samym pobraniem co skrot powyzej.
CANONICAL_LINE_COUNT = 202

# Wiersz wzorcowy z bloku koncowego tekstu kanonicznego, dokladnie taki, jaki
# wystepuje w pobranym tekscie - jedyna linia, ktora ten plik podmienia.
CANONICAL_PLACEHOLDER_LINE = "Copyright [yyyy] [name of copyright owner]"

# Wiersz po podstawieniu, D-02: rok 2026 i imie oraz nazwisko autora.
COPYRIGHT_LINE = "Copyright 2026 Oliver Dolski"

# Dziewiec numerowanych punktow tekstu kanonicznego plus linia konca
# warunkow - sprawdzane OSOBNO, zeby komunikat porazki wskazywal brakujacy
# punkt po nazwie, nigdy fragmentem tresci licencji skopiowanym do komunikatu.
REQUIRED_SECTION_MARKERS: tuple[str, ...] = (
    "1. Definitions.",
    "2. Grant of Copyright License.",
    "3. Grant of Patent License.",
    "4. Redistribution.",
    "5. Submission of Contributions.",
    "6. Trademarks.",
    "7. Disclaimer of Warranty.",
    "8. Limitation of Liability.",
    "9. Accepting Warranty or Additional Liability.",
    "END OF TERMS AND CONDITIONS",
)

# D-03: nazwa pakietu i wpis komendy wiersza polecen, potwierdzone bez zmiany.
PACKAGE_NAME = 'name = "wayside"'
CLI_ENTRY_POINT = 'wayside = "wayside.cli:app"'


def _license_text_lf() -> str:
    """Tresc `LICENSE` po normalizacji koncow linii do pojedynczego znaku
    (zalozenie Z-89) - wejscie kazdego testu tego modulu ponizej."""
    raw = LICENSE_PATH.read_text(encoding="utf-8")
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def _license_with_placeholder_restored() -> str:
    """Tresc `LICENSE` (znormalizowana) z wierszem `COPYRIGHT_LINE`
    zastapionym z powrotem wierszem wzorcowym `CANONICAL_PLACEHOLDER_LINE` -
    wejscie testu skrotu sha256 wobec tekstu kanonicznego."""
    return _license_text_lf().replace(COPYRIGHT_LINE, CANONICAL_PLACEHOLDER_LINE)


# --- Plik istnieje i ma tyle linii, ile tekst kanoniczny -------------------


def test_license_file_exists():
    assert LICENSE_PATH.is_file(), f"{LICENSE_PATH} nie istnieje."


def test_license_line_count_matches_canonical():
    actual_count = len(_license_text_lf().splitlines())
    matches = actual_count == CANONICAL_LINE_COUNT
    assert matches, (
        f"LICENSE niesie {actual_count} linii po normalizacji koncow linii, "
        f"oczekiwano {CANONICAL_LINE_COUNT} (tyle, ile tekst kanoniczny). "
        "Komunikat niesie wylacznie liczby linii, nigdy tresc."
    )


# --- Markery strukturalne: dziewiec numerowanych punktow plus END ----------


def test_required_section_markers_constant_has_at_least_ten_entries():
    assert len(REQUIRED_SECTION_MARKERS) >= 10


def test_license_carries_every_required_section_marker():
    text = _license_text_lf()
    missing = [marker for marker in REQUIRED_SECTION_MARKERS if marker not in text]
    assert missing == [], f"LICENSE nie niesie markerow: {missing}"


def test_missing_single_marker_in_sample_text_is_detected_by_name():
    """Test przeciwny: bramka wskazuje BRAKUJACY marker po nazwie, nie tylko
    stwierdza porazke - komunikat testu wyzej musi dac sie odroznic po tym,
    ktory marker znikl."""
    sample = _license_text_lf().replace("6. Trademarks.", "6. Something Else.")
    missing = [marker for marker in REQUIRED_SECTION_MARKERS if marker not in sample]
    assert missing == ["6. Trademarks."]


# --- Wiersz praw autorskich: obecny podstawiony, nieobecny wzorcowy --------


def test_license_carries_substituted_copyright_line():
    assert COPYRIGHT_LINE in _license_text_lf()


def test_license_does_not_carry_canonical_placeholder_line():
    assert CANONICAL_PLACEHOLDER_LINE not in _license_text_lf()


# --- Skrot sha256 po podstawieniu wiersza wzorcowego z powrotem ------------


def test_license_with_placeholder_restored_matches_canonical_sha256():
    restored = _license_with_placeholder_restored()
    digest = hashlib.sha256(restored.encode("utf-8")).hexdigest()
    assert digest == CANONICAL_SHA256, (
        f"Skrot tresci LICENSE z podstawionym wierszem wzorcowym to {digest}, "
        f"oczekiwano {CANONICAL_SHA256} (skrot tekstu kanonicznego). Komunikat "
        "niesie wylacznie skroty i liczbe linii, nigdy fragment tresci."
    )


def test_restoring_placeholder_does_not_change_line_count():
    restored_count = len(_license_with_placeholder_restored().splitlines())
    matches = restored_count == CANONICAL_LINE_COUNT
    assert matches, (
        f"LICENSE z podstawionym wierszem wzorcowym ma {restored_count} linii, "
        f"oczekiwano {CANONICAL_LINE_COUNT}. Komunikat niesie wylacznie liczby linii."
    )


# --- D-03: nazwa pakietu, komenda CLI i katalog zrodel niezmienione --------


def test_package_name_unchanged():
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert PACKAGE_NAME in text, (
        f"{PYPROJECT_PATH} nie niesie {PACKAGE_NAME!r} - D-03 wymaga nazwy "
        "pakietu niezmienionej przez ten plan."
    )


def test_cli_entry_point_unchanged():
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert CLI_ENTRY_POINT in text, (
        f"{PYPROJECT_PATH} nie niesie {CLI_ENTRY_POINT!r} - D-03 wymaga wpisu "
        "komendy wiersza polecen niezmienionego przez ten plan."
    )


def test_source_directory_unchanged():
    assert (REPO_ROOT / "src" / "wayside").is_dir(), (
        "Katalog zrodel src/wayside nie istnieje - D-03 wymaga niezmienionej "
        "nazwy katalogu zrodel."
    )


# --- Test: bramka nie zapisuje niczego w drzewie ---------------------------


def test_module_source_contains_no_file_write_calls():
    """Sprawdzenie PO ZRODLE modulu, ten sam wzorzec co
    `tests/test_readme_claims.py::test_module_source_contains_no_file_write_calls`
    - alternatywa (porownanie stanu drzewa przed i po) zapala sie takze na
    pracy rownoleglej sesji w tym samym drzewie."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"Modul niesie wzorzec zapisu do pliku: {hits}"
