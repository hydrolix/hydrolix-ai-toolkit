"""Publish independent skill releases and assemble the Pages catalog through gh."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from skill_artifacts import (
    REPOSITORY,
    build_skill,
    make_catalog,
    render_cards,
    validate_manifest,
    write_json,
)


def gh(*args: str) -> str:
    """Run gh with explicit repository scope and propagate API/auth failures."""
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def releases() -> list[dict[str, Any]]:
    """Read all release pages; a transport failure is never an empty catalog."""
    pages = json.loads(
        gh("api", "--paginate", "--slurp", f"repos/{REPOSITORY}/releases?per_page=100")
    )
    return [release for page in pages for release in page]


def release_manifest(release: dict[str, Any]) -> dict[str, Any]:
    """Read and check the immutable package descriptor and advertised ZIP size."""
    tag = release["tag_name"]
    with TemporaryDirectory() as tmp:
        gh(
            "release",
            "download",
            tag,
            "--repo",
            REPOSITORY,
            "--pattern",
            "skill.json",
            "--dir",
            tmp,
        )
        manifest = validate_manifest(json.loads((Path(tmp) / "skill.json").read_text()), tag)
    assets = {asset["name"]: asset for asset in release["assets"]}
    archive = assets.get(manifest["filename"])
    if archive is None or archive.get("size") != manifest["sizeBytes"]:
        raise ValueError(f"missing or wrong-sized ZIP for {tag}")
    digest = archive.get("digest")
    if digest and digest != f"sha256:{manifest['sha256']}":
        raise ValueError(f"GitHub asset checksum disagrees with {tag}")
    if "SHA256SUMS" not in assets:
        raise ValueError(f"missing SHA256SUMS for {tag}")
    return manifest


def verify_existing(release: dict[str, Any], expected: dict[str, Any]) -> None:
    """Allow exact package reruns, but never overwrite an existing version."""
    actual = release_manifest(release)
    # An unchanged skill may be retried after unrelated commits. Preserve its
    # original release provenance instead of attributing it to the new commit.
    for key in expected.keys() - {"sourceRevision"}:
        if actual.get(key) != expected[key]:
            raise ValueError(
                f"{expected['tag']} already contains different content; bump metadata.version"
            )
    with TemporaryDirectory() as tmp:
        gh(
            "release",
            "download",
            expected["tag"],
            "--repo",
            REPOSITORY,
            "--pattern",
            expected["filename"],
            "--pattern",
            "SHA256SUMS",
            "--dir",
            tmp,
        )
        digest = hashlib.sha256((Path(tmp) / expected["filename"]).read_bytes()).hexdigest()
        checksum = (Path(tmp) / "SHA256SUMS").read_text(encoding="ascii")
    if digest != expected["sha256"] or checksum != f"{digest}  {expected['filename']}\n":
        raise ValueError("existing release assets failed checksum verification")


def publish(root: Path, name: str, revision: str, output: Path) -> None:
    """Stage assets in a draft, then publish only after successful verification."""
    manifest = build_skill(root, name, revision, output)
    tag = manifest["tag"]
    existing = next((item for item in releases() if item["tag_name"] == tag), None)
    if existing is not None:
        if existing.get("prerelease"):
            raise ValueError(f"{tag} already exists as a prerelease")
        verify_existing(existing, manifest)
        if existing["draft"]:
            gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")
        print(f"Verified existing release: {tag}")
        return
    # Reject an orphan tag: gh must create the tag at the validated checkout,
    # never silently reuse a tag that points at different source.
    refs = json.loads(gh("api", f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}"))
    if any(ref["ref"] == f"refs/tags/{tag}" for ref in refs):
        raise ValueError(f"tag {tag} exists without a release; inspect it before retrying")
    notes = output / "release-notes.md"
    notes.write_text(
        f"{name} {manifest['version']}\n\n{manifest['description']}\n\n"
        f"Source commit: {revision}\n\n"
        "Download the skill ZIP, not GitHub's repository source archive. "
        "Verify it with SHA256SUMS; skill.json describes the artifact.\n",
        encoding="utf-8",
    )
    assets = [
        str(output / filename) for filename in (manifest["filename"], "skill.json", "SHA256SUMS")
    ]
    gh(
        "release",
        "create",
        tag,
        *assets,
        "--repo",
        REPOSITORY,
        "--target",
        revision,
        "--title",
        f"{name} {manifest['version']}",
        "--notes-file",
        str(notes),
        "--draft",
        "--latest=false",
    )
    staged = next(item for item in releases() if item["tag_name"] == tag)
    verify_existing(staged, manifest)
    gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false")
    print(f"Published release: {tag}")


def catalog(output: Path) -> None:
    """Rebuild from published releases; unrelated skills and old assets survive."""
    manifests = []
    for release in releases():
        if release["draft"] or release["prerelease"] or "/v" not in release["tag_name"]:
            continue
        manifests.append(release_manifest(release))
    write_json(output, make_catalog(manifests))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "publish"):
        child = sub.add_parser(command)
        child.add_argument("--skill", required=True)
        child.add_argument("--revision", required=True)
        child.add_argument("--root", type=Path, default=Path("."))
        child.add_argument("--output", type=Path, default=Path("dist"))
    sub.add_parser("catalog").add_argument("--output", type=Path, required=True)
    sub.add_parser("render").add_argument("--catalog", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "render":
        print(render_cards(json.loads(args.catalog.read_text())))
    elif args.command == "catalog":
        catalog(args.output)
    elif args.command == "publish":
        publish(args.root, args.skill, args.revision, args.output)
    else:
        manifest = build_skill(args.root, args.skill, args.revision, args.output)
        print(json.dumps(manifest))


if __name__ == "__main__":
    main()
