"""Testy jednostkowe FOUND-05: pochodzenie kazdego fixture'a pcap jest egzekwowane maszynowo.

Katalog fixture'ow jest wyznaczany wzgledem `__file__`, nie wzgledem katalogu
biezacego procesu, zeby test dzialal identycznie niezaleznie od miejsca
uruchomienia `pytest`. Manifest jest parsowany wylacznie przez
`yaml.safe_load` - nie ma tu ani jednej zaleznosci wymagajacej `yaml.load`
z jawnym `Loader`, wiec cala klasa ryzyka deserializacji jest zdejmowana
z automatu.

Logika sprawdzajaca (`orphaned_fixture_files`, `orphaned_manifest_entries`)
jest wydzielona do funkcji modulowych, zeby przypadek negatywny mogl wolac
te sama logike na katalogu tymczasowym zamiast dublowac ja w assercie.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "pcap"
MANIFEST_NAME = "manifest.yaml"

REQUIRED_NONEMPTY_FIELDS = ("path", "sha256", "source", "license", "description", "protocol")


def load_manifest(fixture_dir: Path) -> dict:
    """Wczytuje manifest z `fixture_dir` wylacznie przez `yaml.safe_load`."""
    manifest_path = fixture_dir / MANIFEST_NAME
    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))


def orphaned_fixture_files(fixture_dir: Path, manifest: dict) -> set[str]:
    """Zwraca nazwy plikow `*.pcap*` w `fixture_dir` bez wpisu w `manifest`."""
    manifest_paths = {entry["path"] for entry in manifest["fixtures"]}
    actual_files = {p.name for p in fixture_dir.glob("*.pcap*")}
    return actual_files - manifest_paths


def orphaned_manifest_entries(fixture_dir: Path, manifest: dict) -> set[str]:
    """Zwraca sciezki z `manifest`, ktorych plik nie istnieje w `fixture_dir`."""
    return {
        entry["path"]
        for entry in manifest["fixtures"]
        if not (fixture_dir / entry["path"]).exists()
    }


# --- Kompletnosc manifestu wobec faktycznego katalogu ------------------------


def test_every_fixture_file_has_manifest_entry():
    manifest = load_manifest(FIXTURE_DIR)
    orphaned = orphaned_fixture_files(FIXTURE_DIR, manifest)
    assert not orphaned, f"Fixture bez wpisu w manifescie: {orphaned}"


def test_every_manifest_entry_points_to_existing_file():
    manifest = load_manifest(FIXTURE_DIR)
    orphaned = orphaned_manifest_entries(FIXTURE_DIR, manifest)
    assert not orphaned, f"Wpis manifestu bez odpowiadajacego pliku: {orphaned}"


# --- Ksztalt kazdego wpisu ----------------------------------------------------


def test_manifest_entries_have_required_nonempty_fields():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        for field in REQUIRED_NONEMPTY_FIELDS:
            assert entry.get(field), f"Pole '{field}' puste albo brakujace dla {entry.get('path')}"


def test_synthetic_entries_have_generator_pointing_to_existing_script():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        if entry["source"] != "synthetic":
            continue
        generator = entry.get("generator")
        assert generator, f"Wpis syntetyczny bez pola 'generator': {entry['path']}"
        script_path = generator.split("::", 1)[0]
        assert (REPO_ROOT / script_path).exists(), (
            f"Skrypt generatora nie istnieje: {script_path} (wpis {entry['path']})"
        )


def test_non_synthetic_entries_require_url_and_license():
    # W fazie 1 wszystkie fixture'y sa syntetyczne, wiec ta galaz nie ma
    # jeszcze danych - wymaganie ma stac w tescie zanim faza 4 zacznie
    # pobierac publiczne zbiory, bo wtedy jest tanio, a potem juz nie.
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        if entry["source"] == "synthetic":
            continue
        assert entry.get("url"), f"Wpis niesyntetyczny bez pola 'url': {entry['path']}"
        assert entry.get("license"), f"Wpis niesyntetyczny bez pola 'license': {entry['path']}"


# --- Zgodnosc sum kontrolnych --------------------------------------------------


def test_manifest_checksums_match_actual_files():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        actual = hashlib.sha256((FIXTURE_DIR / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"Checksum niezgodny dla {entry['path']}"


# --- Przypadek negatywny: plik bez wpisu lamie bramke, na katalogu tymczasowym --


def test_orphaned_fixture_file_is_detected_without_touching_real_fixtures(tmp_path):
    tmp_fixture_dir = tmp_path / "pcap"
    tmp_fixture_dir.mkdir()
    shutil.copy2(FIXTURE_DIR / MANIFEST_NAME, tmp_fixture_dir / MANIFEST_NAME)
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        shutil.copy2(FIXTURE_DIR / entry["path"], tmp_fixture_dir / entry["path"])

    tmp_manifest = load_manifest(tmp_fixture_dir)
    assert orphaned_fixture_files(tmp_fixture_dir, tmp_manifest) == set()

    orphan_name = "unexpected_capture.pcap"
    (tmp_fixture_dir / orphan_name).write_bytes(b"nie prawdziwy pcap, tylko bajty do testu")

    orphaned = orphaned_fixture_files(tmp_fixture_dir, tmp_manifest)
    assert orphaned == {orphan_name}

    # `tmp_path` sprzata sie samo po tescie; ten test nigdy nie zapisuje
    # niczego do prawdziwego `tests/fixtures/pcap/`.
    assert not (FIXTURE_DIR / orphan_name).exists()


# --- Determinizm generatora ----------------------------------------------------


def test_gen_fixtures_check_exits_zero():
    result = subprocess.run(
        [sys.executable, "scripts/gen_fixtures.py", "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"gen_fixtures.py --check nie zwrocil kodu 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
