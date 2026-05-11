# Bot Insights guidance sources

The investigation skill is adapted from the `bot-insights` core and SOC, SEO,
Edge/Ops, and multi-domain triage packs in the `domain-skills` worktree of
`hydrolix/mcp-hydrolix`. Its standalone references do not require that server's
domain-pack retrieval API; they use the existing metadata and query tools.

Bundle semantics were checked against `hydrolix/cac-tools` commit
`ef20bbbdd64025a640e4536d78c9c383c353c94b`, under
`data/bundles/trafficpeak/`:

- `bot_insights/1.1.1/hydrolix/resources.hdp.yaml`: CDN-only classification,
  cohort derivation, encoding variant, and identity enrichment.
- `bot_insights_bm_siem/1.1.1/hydrolix/resources.hdp.yaml`: Bot Manager and SIEM
  classification and policy/action semantics.
- `bot_insights_bm_siem/1.1.1/hydrolix/tables/bi_cdn_summary_hour.sql`: retained
  dimensions, path-pattern grouping, and aggregate definitions.
- `bot_insights_bm_siem/1.1.1/hydrolix/tables/bi_bm_siem_summary_hour.sql`: SIEM
  host/status aliases, policy grouping, and aggregate definitions.

Earlier toolkit table/field names are retained only as discovery hints, from
its prior `references/data-model.md` at toolkit commit
`8b632480d98a2f6cf78869ec5e572f51fedcc6f1`. They do not establish deployment
availability or equivalence to the versioned bundle.

## Maintaining the guidance

Verify changed semantics against the relevant versioned source. Inspect actual
metadata before using a query on a deployment; source aliases do not determine
live aggregate representation. Keep classification, ingestion coverage, and
operational observations separate. Local checks do not establish live query
compatibility. Subsequent authorized demo testing is recorded in
[live validation](bot-insights-live-validation.md); it establishes compatibility
only for the documented tables, scopes, and query adaptations.

The adaptation uses retained path patterns, resolves aggregate expressions from
metadata, avoids summing distinct cardinalities, and uses local objectives or
baselines instead of universal severity thresholds. It retains investigation
patterns without the former scoring, capture, and report application.
