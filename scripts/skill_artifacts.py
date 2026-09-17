"""Build deterministic skill archives and validate their release manifests."""

from __future__ import annotations

import hashlib
import html
import json
import re
import stat
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

SKILL_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
REPOSITORY = "hydrolix/hydrolix-ai-toolkit"


def version_key(value: str) -> tuple[int, ...]:
    """Require a stable major.minor.patch release, without ambiguous aliases."""
    if not VERSION.fullmatch(value):
        raise ValueError("metadata.version must be a stable major.minor.patch string")
    return tuple(map(int, value.split(".")))


def skill_path(root: Path, name: str) -> Path:
    """Validate a selected skill before using it in paths or release tags."""
    if not SKILL_ID.fullmatch(name) or len(name) > 64:
        raise ValueError("invalid skill ID")
    path = root / "skills" / name
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"unknown or symlinked skill: {name}")
    return path


def read_metadata(directory: Path) -> dict[str, Any]:
    """Read publishing metadata from a checked-out SKILL.md."""
    entrypoint = directory / "SKILL.md"
    if entrypoint.is_symlink():
        raise ValueError("SKILL.md must not be a symlink")
    lines = entrypoint.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("SKILL.md requires YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError:
        raise ValueError("unterminated YAML frontmatter") from None
    data = yaml.safe_load("\n".join(lines[1:end]))
    if not isinstance(data, dict) or data.get("name") != directory.name:
        raise ValueError("skill name must match its directory")
    if not isinstance(data.get("description"), str) or not data["description"].strip():
        raise ValueError("skill description must be a nonempty string")
    metadata = data.get("metadata", {})
    version = metadata.get("version") if isinstance(metadata, dict) else None
    if not isinstance(version, str):
        raise ValueError("metadata.version is required for every packaged skill")
    version_key(version)
    compatibility = data.get("compatibility")
    if compatibility is not None and not isinstance(compatibility, str):
        raise ValueError("compatibility must be a string")
    return {
        "description": data["description"].strip(),
        "version": version,
        "compatibility": compatibility,
    }


def archive_files(directory: Path) -> list[Path]:
    """Inventory regular files, rejecting symlinks and excluding generated files."""
    files = []
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if "__pycache__" in relative.parts or path.suffix == ".pyc" or path.name == ".DS_Store":
            continue
        if path.is_symlink():
            raise ValueError(f"skill archives cannot contain symlinks: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"skill archives require regular files: {relative}")
        files.append(path)
    return files


def download_url(tag: str, filename: str) -> str:
    """Return the exact release asset URL, never GitHub's repository-wide latest."""
    return (
        f"https://github.com/{REPOSITORY}/releases/download/"
        f"{quote(tag, safe='')}/{quote(filename, safe='')}"
    )


def write_json(path: Path, value: object) -> None:
    """Write reproducible, ASCII JSON with a final newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_skill(root: Path, name: str, revision: str, output: Path) -> dict[str, Any]:
    """Package one skill; commit provenance stays outside deterministic ZIP bytes."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full Git commit SHA")
    directory = skill_path(root, name)
    metadata = read_metadata(directory)
    files = archive_files(directory)
    version = metadata["version"]
    tag = f"{name}/v{version}"
    filename = f"{name}-{version}.zip"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / filename
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for path in files:
            relative = path.relative_to(directory).as_posix()
            info = zipfile.ZipInfo(f"{name}/{relative}", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            bundle.writestr(info, path.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    manifest = {
        "schemaVersion": 1,
        "name": name,
        **metadata,
        "entrypoint": "SKILL.md",
        "sourceRevision": revision,
        "tag": tag,
        "filename": filename,
        "downloadUrl": download_url(tag, filename),
        "sha256": digest,
        "sizeBytes": archive.stat().st_size,
        "referenceFiles": sum(
            path.relative_to(directory).parts[0] == "references" for path in files
        ),
    }
    write_json(output / "skill.json", manifest)
    (output / "SHA256SUMS").write_text(f"{digest}  {filename}\n", encoding="ascii")
    return manifest


def validate_manifest(value: object, tag: str) -> dict[str, Any]:
    """Fail closed on malformed published metadata before changing the catalog."""
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise ValueError(f"invalid release manifest: {tag}")
    name, version = value.get("name"), value.get("version")
    if not isinstance(name, str) or not SKILL_ID.fullmatch(name):
        raise ValueError(f"invalid release skill name: {tag}")
    if not isinstance(version, str):
        raise ValueError(f"missing release version: {tag}")
    version_key(version)
    filename = f"{name}-{version}.zip"
    expected = {
        "tag": f"{name}/v{version}",
        "filename": filename,
        "downloadUrl": download_url(tag, filename),
        "entrypoint": "SKILL.md",
    }
    if tag != expected["tag"] or any(value.get(k) != v for k, v in expected.items()):
        raise ValueError(f"release identity mismatch: {tag}")
    _validate_manifest_fields(value)
    return value


def _validate_manifest_fields(value: dict[str, Any]) -> None:
    for field, pattern in (("sourceRevision", r"[0-9a-f]{40}"), ("sha256", r"[0-9a-f]{64}")):
        if not isinstance(value.get(field), str) or not re.fullmatch(pattern, value[field]):
            raise ValueError(f"invalid {field}")
    for field in ("sizeBytes", "referenceFiles"):
        if type(value.get(field)) is not int or value[field] < 0:
            raise ValueError(f"invalid {field}")
    if not isinstance(value.get("description"), str) or not value["description"].strip():
        raise ValueError("invalid description")
    if value.get("compatibility") is not None and not isinstance(value["compatibility"], str):
        raise ValueError("invalid compatibility")


def make_catalog(manifests: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the greatest published stable version independently for each skill."""
    latest: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        validate_manifest(manifest, manifest["tag"])
        name = manifest["name"]
        previous = latest.get(name)
        if previous is None or version_key(manifest["version"]) > version_key(previous["version"]):
            latest[name] = manifest
    return {
        "schemaVersion": 1,
        "repository": f"https://github.com/{REPOSITORY}",
        "skills": [latest[name] for name in sorted(latest)],
    }


def render_cards(catalog: dict[str, Any]) -> str:
    """Render only published skills, using exact release URLs in each card."""
    if not catalog["skills"]:
        return "<p>No skill releases have been published yet.</p>"
    cards = []
    for item in catalog["skills"]:
        validate_manifest(item, item["tag"])
        name, version = html.escape(item["name"]), html.escape(item["version"])
        description = html.escape(item["description"])
        url = html.escape(item["downloadUrl"], quote=True)
        cards.append(
            f'<div class="skill-card"><h2>{name}</h2><p>{description}</p>'
            f'<div class="meta">Version {version}</div>'
            f'<a href="{url}" class="download-btn">Download {name}.zip</a></div>'
        )
    return "\n".join(cards)
