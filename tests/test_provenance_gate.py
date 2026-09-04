"""Bramka maszynowa ASSET-03: pole inwentarza bez znacznika pochodzenia jest
odrzucane maszynowo (plan 03-01, Task 2).

Dane testowe jako stale modulowe, nie literaly rozsiane po asercjach - ten
sam styl co `VERDICT_WORDS` w `tests/test_report_render.py`. Kazdy test
odrzucenia sprawdza dwie rzeczy naraz: typ wyjatku ORAZ obecnosc sciezki
naruszajacego pola w komunikacie - sam typ wyjatku bez sciezki nie daje sie
uzyc do naprawy przy dziesieciu polach hosta.

Ten plik jest w calosci jednostkowy: bez subprocessu i bez pliku pcap -
`assert_provenance_complete` i `iter_observed_fields` sa czyste funkcje nad
struktura juz zserializowana do slownikow i list.
"""

from __future__ import annotations

import pytest

from wayside.model import (
    ObservedField,
    ProvenanceError,
    assert_provenance_complete,
    inferred,
    iter_observed_fields,
)

VALID_ASSETS: list[dict] = [
    {
        "ip": {"value": "192.0.2.10", "provenance": "observed"},
        "mac": {"value": "02:00:00:00:00:01", "provenance": "observed"},
    },
]

# Slownik `analysis` w ksztalcie odziedziczonym z Fazy 2, bez zadnego pola
# opakowanego w nosnik prowieniencji - dokladnie taki, jaki bramka NIE MA
# przepuszczac, gdyby ktos rozszerzyl jej zakres poza sekcje `assets`
# (zalozenie Z-02).
ANALYSIS_FROM_PHASE_2: dict = {
    "capture": {"filename": "x.pcap", "packet_count": 2},
    "conversations": [
        {"session_id": 0, "endpoints": ["192.0.2.10:1", "192.0.2.20:2"], "packet_count": 2}
    ],
    "protocol_events": [{"function_code": 6, "kind": "write"}],
    "zones": [{"provisional": True}],
    "findings": [],
}


# --- Przepuszczanie poprawnych ksztaltow -------------------------------------


def test_gate_passes_list_of_valid_fields():
    assert_provenance_complete(VALID_ASSETS, path="assets")


def test_gate_passes_field_with_null_value_and_not_derivable_marker():
    node = [{"mac": {"value": None, "provenance": "not-derivable-passively"}}]
    assert_provenance_complete(node, path="assets")


def test_gate_passes_empty_list_and_empty_dict():
    assert_provenance_complete([], path="assets")
    assert_provenance_complete({}, path="assets")


# --- Odrzucenie: konstrukcja ObservedField -----------------------------------


def test_observed_field_rejects_unknown_provenance():
    with pytest.raises(ValueError):
        ObservedField(value=1, provenance="wymyslone")


# --- Odrzucenie: surowa wartosc zamiast pola, sciezka w komunikacie ---------


def test_gate_reports_path_of_field_without_marker():
    node = [{"ip": {"value": "a", "provenance": "observed"}, "mac": "surowa-wartosc"}]
    with pytest.raises(ProvenanceError) as excinfo:
        assert_provenance_complete(node, path="assets")
    assert "mac" in str(excinfo.value)


def test_gate_rejects_raw_scalar_nested_inside_list():
    node = [{"tags": ["surowa-wartosc-w-liscie"]}]
    with pytest.raises(ProvenanceError) as excinfo:
        assert_provenance_complete(node, path="assets")
    assert "tags" in str(excinfo.value)


# --- Odrzucenie: znacznik spoza PROVENANCE_PATTERN --------------------------


def test_gate_rejects_field_with_provenance_outside_pattern():
    node = [{"mac": {"value": "x", "provenance": "guessed"}}]
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(node, path="assets")


def test_gate_rejects_inferred_without_method():
    node = [{"mac": {"value": "x", "provenance": "inferred:"}}]
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(node, path="assets")


# --- Fabryka inferred(): metoda malymi literami przechodzi, WIELKIMI nie ---


def test_inferred_factory_accepts_lowercase_method_names():
    inferred("Acme", "oui-lookup")
    inferred("192.0.2.10", "first-observed-sender")


def test_inferred_factory_rejects_uppercase_method_name():
    with pytest.raises(ValueError):
        inferred("Acme", "OUI")


# --- iter_observed_fields: brak podwojnego liczenia -------------------------


def test_iter_observed_fields_does_not_descend_into_recognized_field_value():
    # `value` tego pola jest SAM slownikiem o ksztalcie {"value","provenance"} -
    # generator ma oddac zewnetrzny slownik raz i NIE zejsc w jego "value".
    nested_field = {
        "value": {"value": "deep", "provenance": "observed"},
        "provenance": "observed",
    }
    node = {"x": nested_field}

    results = list(iter_observed_fields(node))

    assert len(results) == 1
    assert results[0][0] == "x"
    assert results[0][1] is nested_field


# --- Kontrakt zakresu bramki (zalozenie Z-02): sekcja assets, NIE cale drzewo ---


def test_gate_on_assets_section_passes_but_on_full_phase_2_analysis_raises():
    assert_provenance_complete(VALID_ASSETS, path="assets")
    with pytest.raises(ProvenanceError):
        assert_provenance_complete(ANALYSIS_FROM_PHASE_2, path="analysis")
