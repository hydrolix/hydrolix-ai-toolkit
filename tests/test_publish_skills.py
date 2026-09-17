"""Exercise GitHub publication boundaries without a network or release mutation."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import publish_skills as publisher  # noqa: E402

REVISION = "a" * 40


class Github:
    """Small gh fake retaining uploaded assets and release visibility."""

    def __init__(self):
        self.rows = []
        self.assets = {}
        self.calls = []
        self.orphan = False

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "api":
            if "matching-refs" in args[-1]:
                return json.dumps([{"ref": self.orphan}] if self.orphan else [])
            return json.dumps([self.rows])
        command, tag = args[1:3]
        if command == "create":
            start = args.index("--repo")
            assets = args[3:start]
            self.assets[tag] = {Path(path).name: Path(path).read_bytes() for path in assets}
            self.rows.append(
                {
                    "tag_name": tag,
                    "draft": True,
                    "prerelease": False,
                    "assets": [
                        {"name": name, "size": len(raw)} for name, raw in self.assets[tag].items()
                    ],
                }
            )
        elif command == "download":
            destination = Path(args[args.index("--dir") + 1])
            for index, arg in enumerate(args):
                if arg == "--pattern":
                    name = args[index + 1]
                    (destination / name).write_bytes(self.assets[tag][name])
        elif command == "edit":
            next(item for item in self.rows if item["tag_name"] == tag)["draft"] = False
        else:
            raise AssertionError(args)
        return ""


@pytest.fixture
def github(monkeypatch):
    fake = Github()
    monkeypatch.setattr(publisher, "gh", fake)
    return fake


def test_publish_attaches_selected_assets_before_publication_and_reruns(skill, github):
    root, _ = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    assert github.rows[0]["tag_name"] == "sample-skill/v1.2.0"
    assert github.rows[0]["draft"] is False
    assert set(github.assets["sample-skill/v1.2.0"]) == {
        "skill.json",
        "SHA256SUMS",
        "sample-skill-1.2.0.zip",
    }
    create = next(call for call in github.calls if call[:2] == ("release", "create"))
    assert "--draft" in create and "--latest=false" in create
    assert create[create.index("--target") + 1] == REVISION
    publisher.publish(root, "sample-skill", "b" * 40, root / "second")
    assert sum(call[:2] == ("release", "create") for call in github.calls) == 1
    assert (
        json.loads(github.assets["sample-skill/v1.2.0"]["skill.json"])["sourceRevision"] == REVISION
    )


def test_content_change_requires_version_bump(skill, github):
    root, directory = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    (directory / "references/schema.md").write_text("changed")
    with pytest.raises(ValueError, match="bump metadata.version"):
        publisher.publish(root, "sample-skill", REVISION, root / "second")
    assert sum(call[:2] == ("release", "edit") for call in github.calls) == 1


def test_orphan_tag_is_not_silently_reused(skill, github):
    root, _ = skill
    github.orphan = "refs/tags/sample-skill/v1.2.0"
    with pytest.raises(ValueError, match="exists without a release"):
        publisher.publish(root, "sample-skill", REVISION, root / "out")
    assert not github.rows


def test_complete_draft_can_be_resumed(skill, github):
    root, _ = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    github.rows[0]["draft"] = True
    publisher.publish(root, "sample-skill", REVISION, root / "second")
    assert github.rows[0]["draft"] is False


def test_catalog_preserves_other_skills_and_ignores_drafts(skill, github):
    root, directory = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    other = root / "skills/another-skill"
    shutil.copytree(directory, other)
    entry = other / "SKILL.md"
    entry.write_text(entry.read_text().replace("sample-skill", "another-skill"))
    publisher.publish(root, "another-skill", REVISION, root / "second")
    github.rows.append({"tag_name": "unpublished/v1.0.0", "draft": True, "prerelease": False})
    output = root / "catalog.json"
    publisher.catalog(output)
    result = json.loads(output.read_text())
    assert [item["name"] for item in result["skills"]] == ["another-skill", "sample-skill"]


def test_api_failure_never_replaces_existing_catalog(tmp_path, monkeypatch):
    output = tmp_path / "catalog.json"
    output.write_text("previous catalog")

    def fail(*args):
        raise subprocess.CalledProcessError(1, ["gh", "api"])

    monkeypatch.setattr(publisher, "gh", fail)
    with pytest.raises(subprocess.CalledProcessError):
        publisher.catalog(output)
    assert output.read_text() == "previous catalog"


def test_missing_release_asset_fails_before_catalog_write(skill, github):
    root, _ = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    github.rows[0]["assets"] = []
    with pytest.raises(ValueError, match="ZIP"):
        publisher.catalog(root / "catalog.json")
    assert not (root / "catalog.json").exists()


def test_workflow_limits_publication_and_serializes_catalog():
    path = Path(__file__).resolve().parents[1] / ".github/workflows/package-skills.yml"
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert "release" not in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    job = workflow["jobs"]["publish"]
    assert "refs/heads/main" in job["if"]
    step = next(
        step for step in job["steps"] if step.get("name") == "Publish selected skill release"
    )
    assert "workflow_dispatch" in step["if"]
    assert '"$SKILL_ID"' in step["run"]
    assert "${{ inputs.skill }}" not in step["run"]


def test_published_site_uses_release_catalog_without_unreleased_cards(skill, github):
    import os

    root, _ = skill
    publisher.publish(root, "sample-skill", REVISION, root / "bundle")
    catalog = root / "releases.json"
    publisher.catalog(catalog)
    project = Path(__file__).resolve().parents[1]
    shutil.copytree(project / "scripts", root / "scripts")
    # Use the project's installed dev dependencies from the isolated site build.
    env = {**os.environ, "PUBLISHED_CATALOG": str(catalog), "UV_PROJECT": str(project)}
    subprocess.run(["bash", "scripts/generate-site.sh"], cwd=root, env=env, check=True)
    assert json.loads((root / "site/skills.json").read_text()) == json.loads(catalog.read_text())
    html = (root / "site/index.html").read_text()
    assert 'href="https://github.com/hydrolix/hydrolix-ai-toolkit/releases/download/' in html
    assert "Version 1.2.0" in html
    assert 'href="./sample-skill.zip"' not in html
    assert "A &lt;sample&gt; skill" in html


def test_corrupt_published_zip_cannot_be_reused(skill, github):
    root, _ = skill
    publisher.publish(root, "sample-skill", REVISION, root / "first")
    github.assets["sample-skill/v1.2.0"]["sample-skill-1.2.0.zip"] = b"corrupt"
    with pytest.raises(ValueError, match="checksum"):
        publisher.publish(root, "sample-skill", REVISION, root / "second")
