# Hydrolix AI Toolkit 1.1.0

Bot Insights is now a focused investigation skill. It guides traffic
composition, baseline changes, crawler governance, and cache/origin analysis
through existing Hydrolix query tools.

## Breaking changes

- Removed the Bot Insights Python package and its capture, report, rendering,
  scorecard, comparison, attribution, and cache/origin analysis commands.
- Removed report templates, custom report-artifact workflows, branding assets,
  reportkit, and the dedicated application tests and examples.
- Removed the repository's Bot Insights capture helper and schema generator.
- The skill no longer renders saved report artifacts or provides a replacement
  reporting application. Prior implementations remain in Git history.

For manual installations, replace the existing `bot-insights` skill directory
completely before installing the new ZIP. Overlay extraction can retain removed
files. Workflows calling removed Python modules or command-line tools must stay
on their previous revision or be replaced before upgrading.

## Investigation improvements

- Focused playbooks for triage, SOC changes, crawler governance, and Edge/Ops.
- Explicit CDN-only versus Bot Manager encoding semantics and scope handling.
- Metadata-driven table selection, aggregate-state merging, and path-pattern
  grouping instead of universal deployment assumptions.
- Evidence limits for classification, denominators, missing data, and causality.

The query-debugging skill retains its existing behavior.

## Validation

Local skill, packaging, test, and site-generation checks passed during release
preparation. Read-only demo tests exercised all SQL templates on hourly Bot
Manager/CDN summaries. CDN-only templates and classification boundaries also
passed synthetic live-engine tests; populated CDN-only deployment data was not
available in the checked window. See the [validation record](docs/bot-insights-live-validation.md).
