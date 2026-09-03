"""Bramka katalogu norm: parafraza, brak tekstu doslownego, wpis prowizoryczny
(STD-01, STD-02).

Zaden test w tym pliku nie zawiera fragmentu tekstu normy - testy badaja
ksztalt i pola, nigdy tresc. Linia naruszajaca, potrzebna do dowiedzenia,
ze `scan_text_structural` w ogole ma zeby, jest SKLEJONA w czasie dzialania
z osobnych zmiennych (numer klauzuli, termin modalny wzięty z
`guard.NORMATIVE_MODAL_TERMS`, dopelnienie dlugosci) - zaden pojedynczy
wiersz ZRODLA tego pliku nie niesie jednoczesnie kropkowanego numeru i
modalnosci normatywnej, wiec bramka poufnosci nie zapala sie na SAMYM
PLIKU TESTOWYM i nie trzeba dopisywac go do `.confidentiality-allow`
(ten plik ostrzega, ze wpis na cala sciezke zdejmuje warstwe strukturalna
z CALEGO pliku, takze z tresci dopisanej pozniej).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from wayside.standards import mapper

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import confidentiality_guard as guard  # noqa: E402

CATALOG_PATH = REPO_ROOT / "src" / "wayside" / "standards" / "iec62443-3-3" / "catalog.yaml"
FIXTURE_RELATIVE = "tests/fixtures/pcap/modbus_write_single_register.pcap"

POLISH_DIACRITICS = "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ"

DEFAULT_ENTRY: dict = {
    "standard": "TEST-STANDARD",
    "edition": "2020",
    "clause": "T 1.1",
    "clause_title": "Tytul testowy",
    "paraphrase": "Testowa parafraza, nigdy cytat normy.",
    "verified": False,
    "verification_note": "Uwaga testowa, wpis prowizoryczny.",
}


def _write_catalog(
    catalog_root: Path,
    *,
    overrides: dict | None = None,
    remove_fields: list[str] | None = None,
) -> Path:
    """Zapisuje jeden `catalog.yaml` z jednym wpisem pod `catalog_root`.
    Wydzielona wspolna logika, zeby przypadek brakujacego i pustego pola
    wolal ta sama funkcje pomocnicza, wzorzec `tests/test_fixture_manifest.py`."""
    entry = dict(DEFAULT_ENTRY)
    if overrides:
        entry.update(overrides)
    if remove_fields:
        for field in remove_fields:
            entry.pop(field, None)

    catalog_root.mkdir(parents=True, exist_ok=True)
    catalog_path = catalog_root / "catalog.yaml"
    catalog_path.write_text(
        yaml.safe_dump({"entries": [entry]}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return catalog_path


# --- Warstwa strukturalna bramki poufnosci wolana na tresci katalogu -------


def test_scan_text_structural_returns_empty_list_for_catalog_content():
    text = CATALOG_PATH.read_text(encoding="utf-8")
    assert guard.scan_text_structural(text, str(CATALOG_PATH)) == []


def test_scan_text_structural_flags_composed_clause_and_modal_line():
    # Sklejone z osobnych zmiennych - patrz docstring modulu. Zaden z tych
    # przypisan nie niesie jednoczesnie numeru i modalnosci na jednej linii.
    clause_prefix = "12"
    clause_suffix = "3.4"
    clause_number = f"{clause_prefix}.{clause_suffix}"
    modal_term = guard.NORMATIVE_MODAL_TERMS[0]
    padding = "x" * guard.MIN_STRUCTURAL_FRAGMENT_LENGTH
    composed_line = clause_number + " " + modal_term + " " + padding

    violations = guard.scan_text_structural(composed_line, "composed-test-line")

    assert len(violations) == 1
    assert violations[0].rule_id == guard.RULE_STRUCTURAL_CLAUSE_MODAL


# --- Ksztalt wpisu w prawdziwym katalogu ------------------------------------


def test_catalog_entries_have_required_nonempty_fields():
    catalog = mapper.load_catalog()
    assert catalog
    for entry in catalog.values():
        for field in mapper.REQUIRED_CATALOG_FIELDS:
            assert field in entry, f"Brak pola {field} w {entry}"
            if field != "verified":
                assert entry[field], f"Puste pole {field} w {entry}"


def test_catalog_entries_are_provisional_with_nonempty_verification_note():
    catalog = mapper.load_catalog()
    for entry in catalog.values():
        assert entry["verified"] is False
        assert entry.get("verification_note")


def test_catalog_edition_and_clause_are_strings_not_numbers():
    catalog = mapper.load_catalog()
    for entry in catalog.values():
        assert isinstance(entry["edition"], str)
        assert isinstance(entry["clause"], str)


# --- Kontrakt schematu na katalogu tymczasowym: pole brakujace i puste -----


def test_load_catalog_rejects_missing_required_field(tmp_path):
    for field in mapper.REQUIRED_CATALOG_FIELDS:
        sub = tmp_path / f"missing_{field}"
        _write_catalog(sub, remove_fields=[field])
        with pytest.raises(mapper.StandardsError):
            mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_empty_paraphrase(tmp_path):
    sub = tmp_path / "empty_paraphrase"
    _write_catalog(sub, overrides={"paraphrase": ""})
    with pytest.raises(mapper.StandardsError):
        mapper.load_catalog(catalog_root=sub)


def test_load_catalog_rejects_empty_string_field_same_as_missing(tmp_path):
    for field in mapper.REQUIRED_CATALOG_FIELDS:
        if field == "verified":
            # verified=False jest legalna, jedyna poprawna wartosc wpisu
            # prowizorycznego - nie moze byc traktowane jak brak pola.
            continue
        sub = tmp_path / f"empty_{field}"
        _write_catalog(sub, overrides={field: ""})
        with pytest.raises(mapper.StandardsError):
            mapper.load_catalog(catalog_root=sub)


def test_load_catalog_accepts_verified_false_without_raising(tmp_path):
    sub = tmp_path / "provisional"
    _write_catalog(sub, overrides={"verified": False})
    catalog = mapper.load_catalog(catalog_root=sub)
    assert catalog[("TEST-STANDARD", "T 1.1")]["verified"] is False


# --- Encoding: polskie znaki z parafrazy przechodza bez escapowania --------


def test_analysis_json_carries_polish_diacritics_without_escaping(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "wayside.cli",
            "analyze",
            FIXTURE_RELATIVE,
            "--out-dir",
            str(tmp_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    raw_text = (tmp_path / "analysis.json").read_text(encoding="utf-8")
    assert "\\u" not in raw_text, "analysis.json niesie escapowana sekwencje \\uXXXX"
    assert any(ch in raw_text for ch in POLISH_DIACRITICS), (
        "analysis.json nie niesie ani jednego polskiego znaku diakrytycznego "
        "z parafrazy katalogu norm"
    )
