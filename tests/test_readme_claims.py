"""Bramka katalogu obietnic README (PUB-03, PUB-04).

Ktore rozstrzygniecie realizuje kazda asercja:

- D-14: `compliance/readme-claims.yaml` jest artefaktem sprawdzanym maszynowo,
  nie jednorazowym przegladem w markdown.
- D-15: ksztalt wpisu katalogu (`id`, `claim`, `readme_anchor`, `evidence`,
  `reason`, `status`).
- D-16: bramka ma TRZY asercje - (a) kazdy wpis ma niepuste `evidence`,
  (b) kazdy `evidence` niebedacy dowodem recznym jest obecny w kolekcji
  pytest zbieranej przez `--collect-only`, (c) kazdy naglowek `##` README ma
  wpis albo jawne wylaczenie w tym samym pliku. **W TYM zadaniu (05-01
  Task 1) wchodza wylacznie asercje (a) i (b)**, razem z bramka ksztaltu
  sekcji `## Intended Use` (D-10, D-11, D-12) - asercja (c) dochodzi
  w zadaniu 2.
- D-17: dowod reczny (`evidence == MANUAL_EVIDENCE`) jest dopuszczalny
  wylacznie z niepustym polem `reason`.

Wyrazenie naglowka drugiego poziomu (`_HEADER_LINE_RE`) skopiowane doslownie
z `tests/test_standard_designation_gate.py` - jeden zapis tej reguly
w repozytorium, nie dwa.

Modul nie zapisuje i nie zmienia zadnego pliku w drzewie repozytorium -
przypadki negatywne katalogu i sekcji budowane sa w pamieci, nigdy przez
zapis do pliku w tym drzewie (patrz `test_module_source_contains_no_file_write_calls`
na koncu pliku).
"""

from __future__ import annotations

import inspect
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

CATALOG_PATH = REPO_ROOT / "compliance" / "readme-claims.yaml"
README_PATH = REPO_ROOT / "README.md"

MANUAL_EVIDENCE = "manual"
ALLOWED_STATUS: frozenset[str] = frozenset({"active", "retired"})

INTENDED_USE_HEADER = "## Intended Use"
REQUIRED_INTENDED_USE_SUBSECTIONS: tuple[str, ...] = (
    "### Do czego",
    "### Do czego nie",
    "### Warunek uzycia",
)
PASSIVITY_EVIDENCE_NODE_ID = (
    "tests/test_oui.py::test_no_network_module_imports_under_src_wayside"
)

# Zdania graniczne z D-11 i D-12, skopiowane doslownie do tresci README -
# jeden zapis obu regul, uzyty jednoczesnie jako tresc dokumentu i jako
# kryterium bramki ksztaltu.
PASSIVITY_BOUNDARY_MARKER = (
    "bramka pilnuje importow w kodzie zrodlowym, a nie faktycznego braku "
    "ruchu w czasie dzialania"
)
NETWORK_OWNER_CONSENT_MARKER = "wolno analizowac wylacznie za zgoda wlasciciela tej sieci"
NETWORK_OWNER_NO_CHECK_MARKER = "narzedzie tej zgody nie sprawdza ani sprawdzic nie moze"

# Skopiowane doslownie z tests/test_standard_designation_gate.py.
_HEADER_LINE_RE = re.compile(r"^## .+$", re.MULTILINE)


# --- Funkcje pomocnicze wspolne (blok <interfaces> planu 05-01) ------------


def _load_catalog() -> dict:
    """Wczytuje katalog obietnic bezpiecznym parserem YAML. Brak klucza
    `entries` albo lista pusta konczy sie porazka asercji z komunikatem
    nazywajacym plik i brakujacy klucz - nie cichym zwrotem pustej listy,
    po ktorym kazda petla przechodzi trywialnie (wiersz E-08 sondy
    krawedziowej: pusty katalog nie jest zielonym przebiegiem)."""
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
    entries = raw.get("entries")
    assert entries, (
        f"{CATALOG_PATH} nie niesie klucza 'entries' albo lista jest pusta."
    )
    return raw


def _entries(*, active_only: bool = True) -> list[dict]:
    entries = _load_catalog()["entries"]
    if active_only:
        return [e for e in entries if e.get("status") == "active"]
    return list(entries)


def _readme_text() -> str:
    return README_PATH.read_text(encoding="utf-8")


def _section_body(text: str, header: str) -> str:
    """Tresc sekcji `header` w `text`, od konca linii naglowka do poczatku
    nastepnego naglowka drugiego poziomu (albo konca tekstu). Dziala na
    DOWOLNYM tekscie, nie tylko na README - przypadki negatywne budowane
    w pamieci przekazuja tu tekst probny, nigdy plik na dysku."""
    headers = list(_HEADER_LINE_RE.finditer(text))
    for index, match in enumerate(headers):
        if match.group(0).strip() != header:
            continue
        start = match.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        return text[start:end]
    raise AssertionError(f"Tekst nie ma sekcji '{header}'")


def _readme_section_body(header: str) -> str:
    return _section_body(_readme_text(), header)


_collected_test_ids_cache: frozenset[str] | None = None


def _collected_test_ids() -> frozenset[str]:
    """Zbiera identyfikatory testow z `pytest --collect-only` w podprocesie
    biezacego interpretera, z korzenia repozytorium.

    Dwa jawne nadpisania, kazde z powodem:

    - `-o addopts=` zeruje opcje domyslne z `pyproject.toml`. Plan `05-04`
      wprowadzi domyslny filtr znacznikow (`-m "not slow"`), ktory zmniejszy
      kolekcje - bez tego nadpisania dowod wskazujacy test ze znacznikiem
      `slow` zaczerwienilby sie bez zadnej zmiany w tresci obietnicy
      (zalozenie Z-83).
    - `-p no:cacheprovider` wylacza zapis do `.pytest_cache` z tego
      podprocesu. Ta bramka ma nie zapisywac niczego w drzewie repozytorium
      (wiersz E-06 sondy krawedziowej); dwa rownolegle przebiegi pakietu
      pisalyby inaczej do tego samego katalogu pamieci podrecznej.

    Wynik zapamietany w zmiennej modulowej po pierwszym wywolaniu. Funkcja
    NIE jest wolana na poziomie importu modulu, bo podproces kolekcji
    importuje ten sam modul - wywolanie na poziomie importu wywolaloby
    rekurencyjne wywolanie samego siebie.
    """
    global _collected_test_ids_cache
    if _collected_test_ids_cache is not None:
        return _collected_test_ids_cache

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    ids: set[str] = set()
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if "::" not in stripped:
            continue
        # Identyfikatory pytest uzywaja ukosnika, ale nie zakladamy tego -
        # normalizujemy separator sciezki, zeby wynik byl stabilny takze na
        # maszynie, ktora akurat wypisze odwrotny ukosnik.
        ids.add(stripped.replace("\\", "/"))

    _collected_test_ids_cache = frozenset(ids)
    return _collected_test_ids_cache


def _evidence_is_collected(evidence: str, collected: frozenset[str]) -> bool:
    """Prawda, gdy `evidence` jest w kolekcji doslownie, albo kolekcja niesie
    identyfikator zaczynajacy sie od `evidence` i nawiasu kwadratowego
    otwierajacego parametr (zalozenie Z-84: testy parametryzowane po
    fixture'ach pcap sa w tym repozytorium regula, a liczba przypadkow
    rosnie z kazdym nowym fixture'em, wiec zapis dowodu po pojedynczym
    przypadku starzalby sie sam)."""
    if evidence in collected:
        return True
    prefix = f"{evidence}["
    return any(cid.startswith(prefix) for cid in collected)


# --- Asercja D-16 (a) i (b), plus D-17 --------------------------------------


def _entry_errors(catalog: dict, collected: frozenset[str]) -> list[str]:
    """Lista bledow asercji (a) [niepuste `evidence`], (b) [dowod obecny
    w kolekcji] i D-17 [dowod reczny wymaga niepustego `reason`], w kolejnosci
    wystapienia wpisow w liscie `entries` (wiersz E-09 sondy krawedziowej).
    Dziala na DOWOLNYM slowniku w pamieci - przypadki negatywne katalogu NIE
    modyfikuja pliku w drzewie."""
    entries = catalog.get("entries")
    assert entries, "Katalog nie niesie wpisow (brak klucza 'entries' albo lista pusta)."

    errors: list[str] = []
    seen_ids: set[str] = set()
    for entry in entries:
        entry_id = entry.get("id", "<brak id>")
        if entry_id in seen_ids:
            errors.append(f"{entry_id}: duplikat identyfikatora wpisu.")
        seen_ids.add(entry_id)

        status = entry.get("status")
        if status not in ALLOWED_STATUS:
            errors.append(
                f"{entry_id}: status {status!r} spoza dozwolonego zbioru "
                f"{sorted(ALLOWED_STATUS)}."
            )

        evidence = entry.get("evidence")
        if not evidence:
            errors.append(f"{entry_id}: puste pole 'evidence'.")
            continue

        if evidence == MANUAL_EVIDENCE:
            if not (entry.get("reason") or "").strip():
                errors.append(f"{entry_id}: dowod reczny bez niepustego pola 'reason'.")
            continue

        if status == "retired":
            # Wpis wycofany nie jest sprawdzany wobec kolekcji (task 2).
            continue

        if not _evidence_is_collected(evidence, collected):
            errors.append(f"{entry_id}: dowod {evidence!r} nieobecny w kolekcji pytest.")

    return errors


# --- Bramka ksztaltu sekcji `## Intended Use` (D-10, D-11, D-12) -----------


def _intended_use_shape_errors(text: str) -> list[str]:
    """Lista bledow ksztaltu sekcji `## Intended Use` w podanym tekscie.
    Pusta lista znaczy ksztalt poprawny. Dziala na DOWOLNYM tekscie w
    pamieci, nie tylko na README - przypadki negatywne NIE modyfikuja pliku
    w drzewie (wymog twardy zadania 1)."""
    try:
        body = _section_body(text, INTENDED_USE_HEADER)
    except AssertionError:
        return [f"Tekst nie ma sekcji '{INTENDED_USE_HEADER}'."]

    if not body.strip():
        return [f"Sekcja '{INTENDED_USE_HEADER}' ma cialo zlozone wylacznie z bialych znakow."]

    errors: list[str] = []

    subsection_positions = [
        (name, body.find(name)) for name in REQUIRED_INTENDED_USE_SUBSECTIONS
    ]
    for name, pos in subsection_positions:
        if pos == -1:
            errors.append(f"Brakuje podsekcji '{name}'.")

    present_positions = [pos for _, pos in subsection_positions if pos != -1]
    first_subsection_pos = min(present_positions) if present_positions else len(body)
    intro = body[:first_subsection_pos]

    if PASSIVITY_EVIDENCE_NODE_ID not in intro:
        errors.append(
            "Akapit pasywnosci nie niesie doslownego identyfikatora testu "
            f"{PASSIVITY_EVIDENCE_NODE_ID!r}."
        )
    if PASSIVITY_BOUNDARY_MARKER not in intro:
        errors.append("Akapit pasywnosci nie nazywa granicy dowodu w tym samym akapicie.")

    warunek_pos = body.find("### Warunek uzycia")
    if warunek_pos != -1:
        warunek_body = body[warunek_pos:]
        if NETWORK_OWNER_CONSENT_MARKER not in warunek_body:
            errors.append(
                "Podsekcja warunku uzycia nie niesie zdania o zgodzie wlasciciela sieci."
            )
        if NETWORK_OWNER_NO_CHECK_MARKER not in warunek_body:
            errors.append(
                "Podsekcja warunku uzycia nie niesie zdania o braku sprawdzania zgody."
            )

    return errors


# --- Testy: obecnosc i ksztalt sekcji `## Intended Use` --------------------


def _sample_intended_use_text(
    *,
    subsections: tuple[str, ...] = REQUIRED_INTENDED_USE_SUBSECTIONS,
    intro: str = (
        f"Zdanie o pasywnosci z dowodem {PASSIVITY_EVIDENCE_NODE_ID}. "
        f"{PASSIVITY_BOUNDARY_MARKER}."
    ),
    warunek_body: str = (
        f"Zdanie: {NETWORK_OWNER_CONSENT_MARKER}. {NETWORK_OWNER_NO_CHECK_MARKER}."
    ),
) -> str:
    """Buduje probny dokument w pamieci z sekcja Intended Use o podanym
    ksztalcie. Uzywany wylacznie przez testy negatywne ponizej - README na
    dysku nie jest modyfikowany."""
    lines = [INTENDED_USE_HEADER, "", intro, ""]
    for name in subsections:
        lines.append(name)
        lines.append(warunek_body if name == "### Warunek uzycia" else "Tresc podsekcji.")
        lines.append("")
    return "\n".join(lines)


def test_readme_has_intended_use_header():
    assert INTENDED_USE_HEADER in _readme_text()


def test_readme_intended_use_section_shape_is_valid():
    assert _intended_use_shape_errors(_readme_text()) == []


def test_missing_subsection_fails_shape_gate():
    text = _sample_intended_use_text(subsections=("### Do czego", "### Warunek uzycia"))
    errors = _intended_use_shape_errors(text)
    assert any("Do czego nie" in e for e in errors)


def test_extra_subsection_does_not_fail_shape_gate():
    text = _sample_intended_use_text(
        subsections=REQUIRED_INTENDED_USE_SUBSECTIONS + ("### Dodatkowa",)
    )
    assert _intended_use_shape_errors(text) == []


def test_header_present_with_blank_body_fails_shape_gate():
    text = f"{INTENDED_USE_HEADER}\n\n   \n\n## Kolejny naglowek\ntresc\n"
    assert _intended_use_shape_errors(text) != []


def test_header_absent_fails_shape_gate():
    text = "## Inna sekcja\n\ntresc\n"
    assert _intended_use_shape_errors(text) != []


def test_passivity_paragraph_carries_evidence_node_id_in_readme():
    body = _readme_section_body(INTENDED_USE_HEADER)
    first_pos = body.find(REQUIRED_INTENDED_USE_SUBSECTIONS[0])
    intro = body[:first_pos]
    assert PASSIVITY_EVIDENCE_NODE_ID in intro


def test_missing_evidence_id_in_intro_fails_shape_gate():
    text = _sample_intended_use_text(intro="Zdanie bez dowodu i bez granicy.")
    errors = _intended_use_shape_errors(text)
    assert any("identyfikatora testu" in e for e in errors)


def test_missing_boundary_marker_fails_shape_gate():
    text = _sample_intended_use_text(
        intro=f"Zdanie z dowodem {PASSIVITY_EVIDENCE_NODE_ID}, bez zdania o granicy."
    )
    errors = _intended_use_shape_errors(text)
    assert any("granicy" in e for e in errors)


def test_warunek_missing_consent_sentence_fails_shape_gate():
    text = _sample_intended_use_text(warunek_body="Zdanie bez zgody i bez sprawdzania.")
    errors = _intended_use_shape_errors(text)
    assert any("zgodzie" in e for e in errors) and any(
        "sprawdzania" in e for e in errors
    )


# --- Testy: katalog obietnic, asercje (a) i (b) D-16, D-17 -----------------


def test_catalog_loads_with_entries_and_excluded_anchors_keys():
    catalog = _load_catalog()
    assert isinstance(catalog["entries"], list) and len(catalog["entries"]) >= 1
    assert "excluded_anchors" in catalog


def test_catalog_with_missing_entries_key_fails():
    with pytest.raises(AssertionError):
        _entry_errors({}, frozenset())


def test_catalog_with_empty_entries_list_fails():
    with pytest.raises(AssertionError):
        _entry_errors({"entries": []}, frozenset())


def test_active_catalog_entries_are_covered_by_real_collection():
    errors = _entry_errors(_load_catalog(), _collected_test_ids())
    assert errors == []


def test_passivity_evidence_is_present_in_real_collection():
    assert PASSIVITY_EVIDENCE_NODE_ID in _collected_test_ids()


def test_real_collection_has_a_meaningful_number_of_tests():
    assert len(_collected_test_ids()) > 300


def test_entry_with_empty_evidence_fails():
    catalog = {
        "entries": [
            {"id": "x", "claim": "c", "readme_anchor": "A", "evidence": "", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert any("x" in e and "evidence" in e for e in errors)


def test_entry_with_manual_evidence_and_empty_reason_fails():
    catalog = {
        "entries": [
            {
                "id": "y",
                "claim": "c",
                "readme_anchor": "A",
                "evidence": MANUAL_EVIDENCE,
                "reason": "   ",
                "status": "active",
            }
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert any("y" in e for e in errors)


def test_entry_with_manual_evidence_and_reason_passes():
    catalog = {
        "entries": [
            {
                "id": "z",
                "claim": "c",
                "readme_anchor": "A",
                "evidence": MANUAL_EVIDENCE,
                "reason": "twierdzenie o srodowisku, nie o kodzie",
                "status": "active",
            }
        ]
    }
    assert _entry_errors(catalog, frozenset()) == []


def test_entry_with_status_outside_allowed_set_fails():
    catalog = {
        "entries": [
            {"id": "w", "claim": "c", "readme_anchor": "A", "evidence": "tests/x.py::y", "status": "draft"}
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::y"}))
    assert any("w" in e for e in errors)


def test_duplicate_entry_ids_fail():
    catalog = {
        "entries": [
            {"id": "dup", "claim": "c1", "readme_anchor": "A", "evidence": "tests/x.py::a", "status": "active"},
            {"id": "dup", "claim": "c2", "readme_anchor": "B", "evidence": "tests/x.py::b", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a", "tests/x.py::b"}))
    assert any("dup" in e and "duplikat" in e for e in errors)


def test_two_entries_same_readme_anchor_is_not_a_collision():
    catalog = {
        "entries": [
            {"id": "one", "claim": "c1", "readme_anchor": "A", "evidence": "tests/x.py::a", "status": "active"},
            {"id": "two", "claim": "c2", "readme_anchor": "A", "evidence": "tests/x.py::b", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a", "tests/x.py::b"}))
    assert errors == []


def test_evidence_pointing_to_nonexistent_test_fails():
    catalog = {
        "entries": [
            {"id": "ghost", "claim": "c", "readme_anchor": "A", "evidence": "tests/x.py::nope", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset({"tests/x.py::a"}))
    assert any("ghost" in e and "nope" in e for e in errors)


def test_entry_errors_reports_in_file_order():
    catalog = {
        "entries": [
            {"id": "first", "claim": "c", "readme_anchor": "A", "evidence": "", "status": "active"},
            {"id": "second", "claim": "c", "readme_anchor": "B", "evidence": "", "status": "active"},
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    first_pos = next(i for i, e in enumerate(errors) if "first" in e)
    second_pos = next(i for i, e in enumerate(errors) if "second" in e)
    assert first_pos < second_pos


def test_failure_message_never_carries_claim_text():
    claim_text = "TAJNE-TWIERDZENIE-NIE-POWTORZ"
    catalog = {
        "entries": [
            {"id": "secretive", "claim": claim_text, "readme_anchor": "A", "evidence": "", "status": "active"}
        ]
    }
    errors = _entry_errors(catalog, frozenset())
    assert errors, "test wymaga co najmniej jednego bledu do sprawdzenia"
    assert all(claim_text not in e for e in errors)


# --- Testy: `_evidence_is_collected` ----------------------------------------


def test_evidence_is_collected_literal_match():
    collected = frozenset({"tests/t.py::test_a"})
    assert _evidence_is_collected("tests/t.py::test_a", collected)


def test_evidence_is_collected_parametrized_prefix_match():
    collected = frozenset({"tests/t.py::test_a[fixture-1]"})
    assert _evidence_is_collected("tests/t.py::test_a", collected)


def test_evidence_is_collected_returns_false_for_missing():
    collected = frozenset({"tests/t.py::test_a[fixture-1]"})
    assert not _evidence_is_collected("tests/t.py::test_b", collected)


# --- Test: bramka nie zapisuje niczego w drzewie ----------------------------


def test_module_source_contains_no_file_write_calls():
    """Sprawdzenie PO ZRODLE modulu, nie po stanie drzewa przed i po -
    alternatywa (porownanie stanu drzewa) zapala sie takze na pracy innej
    rownoleglej sesji w tym samym drzewie i nie odroznia jej od zapisu tego
    modulu. Wzorce sklejone z dwoch czesci, zeby to sprawdzenie nie zlapalo
    WLASNEGO zrodla (ponizszej listy) jako falszywego trafienia."""
    source = inspect.getsource(sys.modules[__name__])
    forbidden = (
        "open" + "(",
        "write" + "_text(",
        "write" + "_bytes(",
        "." + "write(",
    )
    hits = [pat for pat in forbidden if pat in source]
    assert hits == [], f"Modul niesie wzorzec zapisu do pliku: {hits}"
