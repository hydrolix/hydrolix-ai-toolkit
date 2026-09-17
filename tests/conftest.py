"""Shared offline skill fixture for publishing tests."""

import pytest


@pytest.fixture
def skill(tmp_path):
    directory = tmp_path / "skills" / "sample-skill"
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        '---\nname: sample-skill\ndescription: "A <sample> skill"\n'
        'metadata:\n  version: "1.2.0"\n---\n# Skill\n'
    )
    (directory / "references").mkdir()
    (directory / "references" / "schema.md").write_text("# Schema\n")
    return tmp_path, directory
