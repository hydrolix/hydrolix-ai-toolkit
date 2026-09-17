# Releasing individual skills

Each skill has an independent stable version in its `SKILL.md` frontmatter:

```yaml
metadata:
  version: "1.0.0"
```

Use `major.minor.patch`. Prerelease and build suffixes are not supported by this
publishing workflow. Increment the version when any packaged instruction,
reference, script, or asset changes. The toolkit plugin's version is separate.

## Publish a skill

1. Merge the skill changes and version bump into `main`.
2. Open Actions -> Package Hydrolix AI Toolkit -> Run workflow.
3. Select `main` and enter the directory name in `skill`, such as `bot-insights`
   or `debugging-hydrolix-queries`.
4. The workflow validates all skills, builds preview artifacts, and releases
   only the selected skill. It then refreshes GitHub Pages in the same run.
5. Check the new release and the skill's entry in
   `https://skills.hydrolix.ai/skills.json`.

For example, Bot Insights version `1.1.0` creates tag and release
`bot-insights/v1.1.0` with three assets:

- `bot-insights-1.1.0.zip`: a directory containing the complete selected skill.
- `SHA256SUMS`: the ZIP's SHA-256 checksum.
- `skill.json`: version, description, compatibility, source commit, download
  URL, ZIP size, checksum, and entrypoint.

Use the attached skill ZIP. GitHub's automatic source archives contain the
whole repository. Releases are created as drafts, verified, and then published;
they are not marked as the repository-wide latest release.

Ordinary pushes and pull requests validate and build preview artifacts. A push
to `main` also rebuilds the site from published releases; it does not publish
unreleased source as a skill version. Run the workflow with an empty `skill`
input to refresh the catalog without creating a release. Publishing and Pages
deployment run only in the canonical repository on `main`.

## Catalog and retention

The published `skills.json` has `schemaVersion: 1`, `repository`, and `skills`.
Each skill entry is the full `skill.json` from its highest published stable
version, comparing numeric major/minor/patch components. Publishing one skill
preserves the other skills' selected versions. Older release assets remain
available at their exact URLs. Clients use the supplied `downloadUrl`,
`sha256`, and `sizeBytes`, rather than resolving Git refs or GitHub's global
latest-release endpoint. The author-declared version identifies a release;
`sourceRevision` identifies the exact source commit.

The published website displays the same release versions and links as the
catalog. Local `scripts/generate-site.sh` remains a source preview for authoring
validation. Published builds set `PUBLISHED_CATALOG` to the generated catalog.
Versioned release URLs replace mutable ZIP links in the published catalog.
Until the first skill release exists, pushes leave the existing Pages site
untouched rather than replacing it with an empty release catalog.

Release/catalog/deploy runs share a concurrency group with cancellation of
active runs disabled. GitHub can replace an older pending run with a newer one;
rerun a displaced manual release request. Catalog generation reads all release
pages and never treats an API failure as an empty catalog.

## Reruns and recovery

An identical release rerun verifies the existing ZIP and retains its original
source provenance. It never overwrites published assets. Changed content with
the same version fails with a request to bump `metadata.version`.

A complete draft from an interrupted run can be verified and published on a
rerun. A partial or mismatched draft fails closed: inspect the draft and its
assets, remove the incomplete draft/tag if appropriate, then rerun the action.
An existing tag without a release also requires inspection; the workflow will
not silently publish it against a different source commit.

If release publication succeeds but Pages deployment fails, rerun the workflow
or run it with an empty `skill` input. The catalog is reconstructed from
published manifests, so its previous local build is not needed. Keep released
assets and tags unchanged; clients verify ZIP checksums before reading them.
An administrator can still alter or delete assets unless repository release
immutability is enabled separately.

## Local verification

These commands build and test locally; they do not publish:

```sh
uv sync --locked
uv run pytest -q
uv run python scripts/check-source-lines.py
uv run python scripts/validate-skill-examples.py --strict
uv run python scripts/publish_skills.py build --skill bot-insights --revision "$(git rev-parse HEAD)" --output dist/bot-insights
```

GitHub CLI authentication is needed only by the `publish` and `catalog`
commands. The workflow supplies its scoped `GITHUB_TOKEN` through `GH_TOKEN`.
The packages themselves add no Python dependency to skill consumers; PyYAML is
an authoring-time dependency for reading release metadata.
