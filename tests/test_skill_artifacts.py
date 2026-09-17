"""Offline tests for reproducible packages and independent version catalogs."""

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import skill_artifacts as artifacts  # noqa: E402

REVISION = "a" * 40


def test_package_preserves_files_and_is_reproducible(skill):
    root, directory = skill
    (directory / ".hidden-config").write_text("included\n")
    (directory / "__pycache__").mkdir()
    (directory / "__pycache__" / "unused.pyc").write_bytes(b"ignored")
    first = artifacts.build_skill(root, "sample-skill", REVISION, root / "one")
    os.utime(directory / "SKILL.md", (1_700_000_000, 1_700_000_000))
    second = artifacts.build_skill(root, "sample-skill", "b" * 40, root / "two")
    assert first["sha256"] == second["sha256"]
    assert first["sourceRevision"] != second["sourceRevision"]
    archive = root / "one" / first["filename"]
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == first["sha256"]
    assert first["sizeBytes"] == archive.stat().st_size
    with zipfile.ZipFile(archive) as zipped:
        assert set(zipped.namelist()) == {
            "sample-skill/SKILL.md",
            "sample-skill/references/schema.md",
            "sample-skill/.hidden-config",
        }
        assert zipped.read("sample-skill/SKILL.md") == (directory / "SKILL.md").read_bytes()
    assert first["referenceFiles"] == 1
    assert first["downloadUrl"].endswith("sample-skill%2Fv1.2.0/sample-skill-1.2.0.zip")
    assert json.loads((root / "one/skill.json").read_text()) == first


@pytest.mark.parametrize("version", ["1", "1.2", "01.2.0", "1.2.0-rc.1", "1.2.0+build"])
def test_ambiguous_or_prerelease_versions_rejected(version):
    with pytest.raises(ValueError, match="major.minor.patch"):
        artifacts.version_key(version)


@pytest.mark.parametrize("name", ["../sample-skill", "sample/skill", "-bad", "--help"])
def test_skill_selection_cannot_escape_root(skill, name):
    root, _ = skill
    with pytest.raises(ValueError, match="skill ID"):
        artifacts.build_skill(root, name, REVISION, root / "output")


def test_missing_version_fails_before_packaging(skill):
    root, directory = skill
    entry = directory / "SKILL.md"
    entry.write_text(entry.read_text().replace('metadata:\n  version: "1.2.0"\n', ""))
    with pytest.raises(ValueError, match="metadata.version"):
        artifacts.build_skill(root, "sample-skill", REVISION, root / "output")


def test_symlink_reference_is_not_packaged(skill):
    root, directory = skill
    (directory / "references/escape").symlink_to(root)
    with pytest.raises(ValueError, match="symlink"):
        artifacts.build_skill(root, "sample-skill", REVISION, root / "output")


def test_catalog_orders_numeric_versions_and_preserves_other_skills(skill):
    root, directory = skill
    older = artifacts.build_skill(root, "sample-skill", REVISION, root / "old")
    entry = directory / "SKILL.md"
    entry.write_text(entry.read_text().replace('"1.2.0"', '"1.10.0"'))
    newer = artifacts.build_skill(root, "sample-skill", REVISION, root / "new")
    other_dir = root / "skills/other-skill"
    other_dir.mkdir()
    (other_dir / "SKILL.md").write_text(entry.read_text().replace("sample-skill", "other-skill"))
    other = artifacts.build_skill(root, "other-skill", REVISION, root / "other")
    catalog = artifacts.make_catalog([newer, older, other])
    assert catalog["skills"] == [other, newer]
    html = artifacts.render_cards(catalog)
    assert "&lt;sample&gt;" in html
    assert newer["downloadUrl"] in html
    assert "Version 1.10.0" in html
    assert "No skill releases" in artifacts.render_cards(artifacts.make_catalog([]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "invalid"),
        ("sourceRevision", "main"),
        ("sizeBytes", -1),
        ("downloadUrl", "https://example.com/other.zip"),
        ("filename", "../other.zip"),
    ],
)
def test_manifest_rejects_corrupt_release_identity(skill, field, value):
    root, _ = skill
    manifest = artifacts.build_skill(root, "sample-skill", REVISION, root / "out")
    manifest[field] = value
    with pytest.raises(ValueError):
        artifacts.validate_manifest(manifest, manifest["tag"])
