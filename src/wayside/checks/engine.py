"""Silnik checkow: skan katalogu w czasie dzialania, bez rejestru (D-06).

Nowy check to nowy plik YAML plus plik siostrzany `.py` w podkatalogu
`checks/<kategoria>/` - ten modul sie nie zmienia, bo `discover_checks`
odkrywa pliki fizycznie przez `sorted(checks_root.rglob("*.yaml"))`, nie
przez liste zaimportowanych modulow (CHECK-01).

`evaluator` jest rozwiazywany jako plik SIOSTRZANY wobec YAML, przez
`importlib.util.spec_from_file_location`, nigdy przez
`importlib.import_module` na dowolnej sciezce z kropkami - to zamyka
zagrozenie T-2-04 (import dowolnego modulu wskazanego przez plik danych).
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

__all__ = [
    "CHECKS_ROOT",
    "REQUIRED_CHECK_FIELDS",
    "ENDPOINT_UNKNOWN",
    "CheckSchemaError",
    "CheckSpec",
    "discover_checks",
    "run_checks",
]

CHECKS_ROOT = Path(__file__).resolve().parent

# Wartosc zastepcza punktu koncowego (G-04-5b, zalozenie Z-92): finding
# sesji, ktora nie ma wiersza w macierzy komunikacji. Na sciezce prawdziwego
# potoku ten przypadek dzis nie zachodzi (finding powstaje ze zdarzenia
# protokolu, a zdarzenie protokolu z segmentu z ladunkiem, ktory wiersz
# macierzy ma); zachodzi natomiast w modelach probnych testow tego modulu.
ENDPOINT_UNKNOWN = "nieustalony"

REQUIRED_CHECK_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "applies_to",
    "severity",
    "rationale",
    "standards",
    "evaluator",
    "remediation",
)


class CheckSchemaError(Exception):
    """Plik checka nie ma poprawnego ksztaltu albo `evaluator` wskazuje na
    niedozwolony modul."""


@dataclass(frozen=True)
class CheckSpec:
    path: Path
    spec: dict
    evaluate: Callable[[dict], list[dict]]


def _validate_fields(spec: dict, yaml_path: Path) -> None:
    missing = [field for field in REQUIRED_CHECK_FIELDS if not spec.get(field)]
    if missing:
        raise CheckSchemaError(
            f"Check {yaml_path} niekompletny: brak albo puste pola {missing}."
        )


def _load_evaluator(spec: dict, yaml_path: Path) -> Callable[[dict], list[dict]]:
    evaluator_ref = spec["evaluator"]
    module_name, sep, func_name = evaluator_ref.partition(":")
    if not sep or not module_name or not func_name:
        raise CheckSchemaError(
            f"Check {yaml_path}: pole evaluator ma niepoprawny ksztalt "
            f"{evaluator_ref!r}, oczekiwano 'modul:funkcja'."
        )
    if any(token in module_name for token in ("/", "\\", ".")):
        raise CheckSchemaError(
            f"Check {yaml_path}: nazwa modulu evaluatora {module_name!r} nie "
            "moze zawierac separatora sciezki ani kropki (zagrozenie T-2-04)."
        )

    module_path = yaml_path.parent / f"{module_name}.py"
    if not module_path.is_file():
        raise CheckSchemaError(
            f"Check {yaml_path}: plik evaluatora nie istnieje: {module_path}."
        )

    module_spec = importlib.util.spec_from_file_location(
        f"wayside._checks.{module_name}", module_path
    )
    if module_spec is None or module_spec.loader is None:
        raise CheckSchemaError(
            f"Check {yaml_path}: nie udalo sie zaladowac modulu evaluatora "
            f"{module_path}."
        )
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)

    evaluate = getattr(module, func_name, None)
    if not callable(evaluate):
        raise CheckSchemaError(
            f"Check {yaml_path}: funkcja {func_name!r} nie istnieje w "
            f"{module_path}."
        )
    return evaluate


def discover_checks(checks_root: Path = CHECKS_ROOT) -> list[CheckSpec]:
    """Skanuje `checks_root` w poszukiwaniu plikow `*.yaml`, w kolejnosci
    posortowanej (kolejnosc systemu plikow nie jest gwarantowana miedzy
    maszynami). Dwa pliki o identycznym `id` koncza sie `CheckSchemaError`,
    nigdy cichym nadpisaniem."""
    checks: list[CheckSpec] = []
    seen_ids: dict[str, Path] = {}

    for yaml_path in sorted(checks_root.rglob("*.yaml")):
        spec = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        _validate_fields(spec, yaml_path)

        check_id = spec["id"]
        if check_id in seen_ids:
            raise CheckSchemaError(
                f"Zduplikowany identyfikator checka {check_id!r}: "
                f"{seen_ids[check_id]} oraz {yaml_path}."
            )
        seen_ids[check_id] = yaml_path

        evaluate = _load_evaluator(spec, yaml_path)
        checks.append(CheckSpec(path=yaml_path, spec=spec, evaluate=evaluate))

    return checks


def _dedupe_standards(standards: list[dict]) -> list[dict]:
    """Usuwa powtorzone powolania po parze (standard, clause), zachowujac
    PIERWSZE wystapienie - kolejnosc z pliku YAML pozostaje nietknieta
    (CHECK-02, edge: adjacency/ordering)."""
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for entry in standards:
        key = (entry["standard"], entry["clause"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def _endpoints_by_session(analysis: dict) -> dict[int, tuple[str, str]]:
    """Odwzorowanie identyfikatora sesji na pare punktow koncowych (zrodlo,
    cel), zbudowane z macierzy komunikacji TEGO SAMEGO modelu (G-04-5b).
    Wzorem `_dedupe_standards` powyzej: funkcja prywatna, czysta, jedna
    pozycja na wiersz macierzy.

    Dostep do klucza `comm_matrix` jest tolerancyjny na jego brak (zalozenie
    Z-92) - model probny testow tego modulu nie ma macierzy komunikacji, a
    wyjatek przewrocilby je bez zysku. Kazdy wiersz macierzy jest polem
    obserwowanym opakowanym w slownik `{"value": ..., "provenance": ...}`,
    wiec odwzorowanie siega do wartosci pola, nie do samego pola."""
    mapping: dict[int, tuple[str, str]] = {}
    for row in analysis.get("comm_matrix") or []:
        session_id = row["session_id"]["value"]
        source = row["source"]["value"]
        target = row["target"]["value"]
        mapping[session_id] = (source, target)
    return mapping


def run_checks(analysis: dict, checks: list[CheckSpec]) -> list[dict]:
    """Uruchamia kazdy check nad `analysis`, zbiera wyniki do jednej
    plaskiej listy (wzorzec `scan_files`) - zaden check nie przerywa petli.
    Wynik jest posortowany po trojce (check_id, session_id, packet_number).

    Kazdy finding dostaje pare adresow sesji (G-04-5b), dopisana z
    odwzorowania zbudowanego RAZ przed petla po checkach, a nie raz na
    finding. Slownik dowodu zwrocony przez evaluator NIE jest mutowany
    (zalozenie Z-91): silnik sklada NOWY slownik z jego zawartosci i dwoch
    nowych kluczy - evaluator moze zwrocic slownik wspoldzielony albo
    zbudowany na zdarzeniu modelu, a testy wolajace evaluator wprost
    sprawdzaja rownosc pelnego slownika dowodu."""
    findings: list[dict] = []
    endpoints_by_session = _endpoints_by_session(analysis)

    for check in checks:
        standards = _dedupe_standards(check.spec["standards"])
        for result in check.evaluate(analysis):
            finding = {
                "check_id": check.spec["id"],
                "title": check.spec["title"],
                "severity": check.spec["severity"],
                "rationale": check.spec["rationale"],
                "standards": standards,
                "remediation": check.spec["remediation"],
            }
            finding.update(result)
            # Brak klucza dowodu albo brak identyfikatora sesji w wyniku
            # evaluatora ma nadal konczyc sie bledem klucza - to jest sygnal
            # niepoprawnego ksztaltu wyniku checka, a nie legalny brak danych.
            session_id = finding["evidence"]["session_id"]
            source, target = endpoints_by_session.get(
                session_id, (ENDPOINT_UNKNOWN, ENDPOINT_UNKNOWN)
            )
            finding["evidence"] = {
                **finding["evidence"],
                "source": source,
                "target": target,
            }
            findings.append(finding)

    findings.sort(
        key=lambda f: (
            f["check_id"],
            f["evidence"]["session_id"],
            f["evidence"]["packet_number"],
        )
    )
    return findings
