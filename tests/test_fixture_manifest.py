"""Unit tests FOUND-05: the provenance of every pcap fixture is enforced mechanically.

The fixture directory is derived relative to `__file__`, not relative to the
process's current directory, so that the test behaves identically no matter
where `pytest` was started from. The manifest is parsed solely by
`yaml.safe_load` - there is not one dependency here requiring `yaml.load` with
an explicit `Loader`, so the whole class of deserialization risk is lifted
by construction.

The checking logic (`orphaned_fixture_files`, `orphaned_manifest_entries`)
is extracted into module-level functions, so that the negative case can call
the same logic over a temporary directory instead of duplicating it inside an
assertion.
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
    """Loads the manifest from `fixture_dir` solely through `yaml.safe_load`."""
    manifest_path = fixture_dir / MANIFEST_NAME
    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))


def orphaned_fixture_files(fixture_dir: Path, manifest: dict) -> set[str]:
    """Returns the names of the `*.pcap*` files in `fixture_dir` with no entry in `manifest`."""
    manifest_paths = {entry["path"] for entry in manifest["fixtures"]}
    actual_files = {p.name for p in fixture_dir.glob("*.pcap*")}
    return actual_files - manifest_paths


def orphaned_manifest_entries(fixture_dir: Path, manifest: dict) -> set[str]:
    """Returns the paths from `manifest` whose file does not exist in `fixture_dir`."""
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
    assert not orphaned, f"A manifest entry with no corresponding file: {orphaned}"


# --- Ksztalt kazdego wpisu ----------------------------------------------------


def test_manifest_entries_have_required_nonempty_fields():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        for field in REQUIRED_NONEMPTY_FIELDS:
            assert entry.get(field), f"Field '{field}' empty or missing for {entry.get('path')}"


def test_synthetic_entries_have_generator_pointing_to_existing_script():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        if entry["source"] != "synthetic":
            continue
        generator = entry.get("generator")
        assert generator, f"A synthetic entry with no 'generator' field: {entry['path']}"
        script_path = generator.split("::", 1)[0]
        assert (REPO_ROOT / script_path).exists(), (
            f"The generator script does not exist: {script_path} (entry {entry['path']})"
        )


def test_non_synthetic_entries_require_url_and_license():
    # In phase 1 every fixture is synthetic, so this branch has no data yet -
    # the requirement is meant to stand in the test before phase 4 starts
    # downloading public capture sets, because it is cheap now and will not be
    # later.
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        if entry["source"] == "synthetic":
            continue
        assert entry.get("url"), f"Non-synthetic entry without a 'url' field: {entry['path']}"
        assert entry.get("license"), f"A non-synthetic entry with no 'license' field: {entry['path']}"


# --- Zgodnosc sum kontrolnych --------------------------------------------------


def test_manifest_checksums_match_actual_files():
    manifest = load_manifest(FIXTURE_DIR)
    for entry in manifest["fixtures"]:
        actual = hashlib.sha256((FIXTURE_DIR / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"Checksum mismatch for {entry['path']}"


# --- Negative case: a file without an entry breaks the gate, in a temp dir --


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
    (tmp_fixture_dir / orphan_name).write_bytes(b"not a real pcap, just bytes for the test")

    orphaned = orphaned_fixture_files(tmp_fixture_dir, tmp_manifest)
    assert orphaned == {orphan_name}

    # `tmp_path` cleans itself up after the test; this test never writes
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
        f"gen_fixtures.py --check did not return code 0: stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
