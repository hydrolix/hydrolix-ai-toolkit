# bot-insights - Scorecard Analysis

Bot Insights scorecards are artifact generation and prioritization, not
dashboards. Dashboards show panels for exploration. Scorecards synthesize
cross-surface evidence into deterministic investigation packets that can be
saved, compared, handed to another workflow, or summarized by an LLM without
letting the LLM invent scores.

Use `scripts/scorecard.py` after Hydrolix has produced small aggregate rows.
The script accepts Hydrolix MCP result JSON, saved aggregate JSON, or pasted
JSON and emits:

- `bot_entity_scorecard.v1` packets for each entity.
- `bot_scorecard_index.v1` ranking entities by rule-based score.

The script does not query Hydrolix, open database clients, read credentials, or
perform forecast, correlation, ML, or opaque classification.

## Contents

- [Workflow](#workflow)
- [Rowset And Feature Provenance](#rowset-and-feature-provenance)
- [Producer Limit Metadata](#producer-limit-metadata)
- [Rule Domains](#rule-domains)
- [Summary-First Table Selection](#summary-first-table-selection)
- [Scorecard-Ready Columns](#scorecard-ready-columns)
- [SQL Templates](#sql-templates)
- [Example Input](#example-input)
- [Example Output](#example-output)

## Workflow

1. Pick the report lens and entity type. Supported entity types are
   `client_asn`, `request_path_norm`, `request_host`, `bot_class`, or
   `ai_category`. `request_path_norm` and `bot_class` are not retained at
   deployed-summary grain on every cluster — when the cluster lacks them,
   apply the deployment-availability rule (SKILL.md) and state the limitation
   rather than substituting a non-deployed table.
2. Start from the narrowest summary table whose retained dimensions fit that
   lens, entity, and requested scope. For TrafficPeak/Akamai SOC/security
   scorecards, seed the entity population from `bi_siem_policy_summary_*`; do
   not reuse an Edge/Ops, crawler, or posture top-N population unless that is
   the explicit scope.
3. Aggregate current and baseline windows in Hydrolix, returning one row per
   entity with scorecard-ready fields.
4. Add SIEM enrichment only when security action or policy evidence is needed.
5. Fall back to request-level tables only when (a) those tables are deployed
   on the target cluster and (b) the required dimension is unavailable in
   summaries; otherwise apply the deployment-availability rule (SKILL.md).
   State the reason.
6. Run `scripts/scorecard.py` on the aggregate JSON to create reusable packets.
   Pass `analysis_domains` in the input JSON, or `--domains` on the CLI, when
   generating a lens-specific scorecard such as `security_evidence` for SOC or
   `crawler_governance` for crawler reports.

Missing fields are not interpreted as safe behavior. They are emitted in
`not_evaluated_features` and reflected in confidence reasons such as
`feature_input_missing` or `siem_unavailable`.

Contribution scoring requires total-scope evidence. Prefer computing
`contribution_pct` or `contribution_to_total_delta_pct` in Hydrolix over the
full grouped scope before applying any result `LIMIT`. The script only
auto-computes missing contribution percentages when the input metadata
explicitly proves completeness with `rowset_complete: true` or
`contribution_basis: "complete_scope"`. Limited or filtered rowsets without
that metadata leave `contribution_to_total_delta_high` unevaluated.

Use one input row shape per run. Rows may be already-combined entity rows with
`current_*` and `baseline_*` fields, or period-split rows with `period` values
of `"current"`/`"baseline"` that the script combines. Do not mix those row
shapes in one payload; normalize or join enrichment before running
`scorecard.py`.

## Rowset And Feature Provenance

Callers may supply structured provenance on the payload or on individual rows so
that downstream report renderers can prove that generic rate features such as
`rate_429_delta_high` or `rate_5xx_delta_high` came from a crawler-specific
rowset. The script preserves these fields on emitted
`bot_entity_scorecard.v1` artifacts but does not synthesize them.

Supported fields:

- `rowset_scope.population`, when present, must be one of `crawler`,
  `good_bot`, `ai_crawler`, `all_traffic`, or `unknown`. Other
  `rowset_scope` fields (such as `filters`, `entity_type`, and `table_used`)
  are passed through unchanged.
- `feature_provenance` must be a JSON object keyed by scorecard feature name.
  Each entry may carry its own `rowset_scope`, a `metric_inputs` array of
  strings naming the aggregate inputs, and free-form `notes`.
- `feature_provenance.<feature>.metric_inputs`, when present, must be an array
  of strings.

Row-level `rowset_scope` and `feature_provenance` override payload-level
values on the emitted scorecard. Feature-level provenance is preserved so a
renderer can resolve feature-specific populations over artifact-level ones.
Invalid provenance shapes fail closed with an explicit error so artifacts stay
deterministic.
For period-split rows that the script combines into one entity row, matching
row-level provenance is preserved; conflicting per-period provenance is a hard
failure instead of last-row-wins merge behavior.

## Producer Limit Metadata

`scripts/scorecard.py --limit <n>` truncates scorecards and ranked index
entries before they reach a renderer. Producer-limit metadata is emitted only
on metadata-capable outputs:

- Default `bot_scorecard_artifacts.v1` output carries `producer_limit`,
  `result_row_count`, `result_truncated`, and `total_ranked_entities` at the
  packet level, and the embedded `bot_scorecard_index.v1` carries the same
  fields.
- `--output index` emits `bot_scorecard_index.v1` with `producer_limit`,
  `result_row_count`, `result_truncated`, and `total_ranked_entities`.
- `--output scorecards` intentionally emits a bare JSON list of
  `bot_entity_scorecard.v1` artifacts. A bare list has no packet-level
  location for `producer_limit`, `result_row_count`, or `result_truncated`;
  downstream renderers must treat the list as the emitted known collection
  rather than as proof of the upstream population.

## Rule Domains

The MVP actively scores these domains:

- `movement`: new entities, volume deltas, total-delta contribution, bot-share
  movement.
- `origin_impact`: origin p95 movement and origin cost contribution.
- `cache_busting`: cache miss rate, cache miss movement, query-string
  diversity, and query-string diversity with high miss rate.
- `crawler_governance`: 429/5xx movement, good bot rate limiting, good bot
  error rate, governance-surface failures, AI crawler growth.
- `security_evidence`: SIEM blocked/auth-fail evidence and bad bot share.
- `policy_collateral`: good bot collateral 429s, protected-population error
  rates, and displacement movement after a policy or control change.

`signal_alignment` is reserved for future scorecard inputs. When any optional
domain inputs are unavailable, do not score them as zero-risk substitutes; leave
the evidence unevaluated or add explicit feature inputs in a future schema
revision.

## Summary-First Table Selection

- Use `akamai.bi_summary_day`, `akamai.bi_summary_hour`, or
  `akamai.bi_summary_minute` for Akamai-project host, ASN, bot class, AI
  category, bot share, cache miss rate, 429/5xx rate, and origin latency when
  those retained dimensions answer the question.
- Use `akamai.bi_siem_policy_summary_*` for SIEM blocked requests, auth
  failures, and policy/action evidence on the TrafficPeak Akamai project.
  This surface exists only on SIEM-enabled clusters such as
  `demo.trafficpeak.live`; SOC scorecards must gracefully fall back to posture
  evidence when the SIEM surface is absent.
- Path-grain (`bot_agg_path_*`), focused ASN/UA (`bot_agg_asn_hour`,
  `bot_agg_ua_hour`), and request-level (`bot_detection`,
  `bot_detection_siem`) tables are **not currently deployed**; do not seed
  scorecards from them. When a required dimension (exact user agent, verified
  owner, verification tier, bot confidence, attack payload, exact query
  string) is not retained in `bi_summary_*` or `bi_siem_policy_summary_*`,
  emit a `feature_input_missing` entry rather than substituting a non-deployed
  table.

If Hydrolix metadata reports aggregate-state columns, replace `sum(metric)`
with the merge function reported by the table metadata tool.

## Scorecard-Ready Columns

The script recognizes current/baseline prefixes such as:

- `current_requests`, `baseline_requests`
- `current_bot_share_pct`, `baseline_bot_share_pct`
- `current_cache_miss_pct`, `baseline_cache_miss_pct`
- `current_origin_p95_ms`, `baseline_origin_p95_ms`
- `current_rate_429_pct`, `baseline_rate_429_pct`
- `current_rate_5xx_pct`, `baseline_rate_5xx_pct`
- `current_ai_crawler_requests`, `baseline_ai_crawler_requests`

It also accepts current-only fields such as:

- `contribution_pct` or `contribution_to_total_delta_pct`
- `qs_diversity_ratio`
- `origin_cost_contribution_pct`
- `good_bot_429_requests`
- `good_bot_error_rate_pct`
- `policy_surface_failures`
- `siem_blocked_requests`
- `siem_auth_fail_requests`
- `bad_bot_share_pct`
- `good_bot_collateral_429_requests`
- `policy_collateral_error_rate_pct`

Policy displacement fields should be provided as current/baseline pairs:

- `current_displacement_requests`, `baseline_displacement_requests`

When no policy-change context is available, generate the protected-population
collateral inputs that can be derived from posture summaries and omit
displacement fields. The scorecard evaluates the protected-population inputs
and does not treat absent displacement fields as missing evidence unless a
caller provides displacement inputs.

## SQL Templates

These templates intentionally omit clients, credentials, and execution logic.
For the predefined report types these templates feed (`soc_triage`,
`scorecard_brief`, `crawler_governance`, `edge_ops_impact`), prefer the
script-orchestrated path documented in [reporting.md](reporting.md) —
`bot_insights_capture.py` runs the query directly when local credentials
resolve and emits a `bot_hydrolix_mcp_query_request.v1` handoff packet
otherwise. Run these templates directly via Hydrolix MCP only when no script
path covers the report type, or for exploratory analysis outside a predefined
report. See [SKILL.md "Data Firewall"](../SKILL.md#data-firewall).

Replace `<posture_summary_day>` / `<posture_summary_hour>` with
`akamai.bi_summary_day` / `akamai.bi_summary_hour` for Akamai-project
scorecards. Replace `<siem_summary_hour>` with
`akamai.bi_siem_policy_summary_hour` for TrafficPeak/Akamai.

**`bot_class` is producer-script terminology, not a deployed column.**
Deployed posture summaries (`bi_summary_*`) retain `userAgentCategory`, not
`bot_class`. The producer in `scripts/bot_insights_report.py` aliases
`toString(userAgentCategory) AS bot_class` (see `SCORECARD_ENTITY_SQL` and
related maps) so downstream scorecard rows expose a canonical `bot_class`
field. When adapting the templates below for direct MCP execution against
deployed clusters, replace `bot_class = '<value>'` predicates with the
metadata-confirmed `userAgentCategory` value (for example
`userAgentCategory = 'Search Engine Crawler'`); SIEM-grade classification
filters belong on `botType` on `bi_siem_policy_summary_*`. The literal
`'good'`, `'bad'`, and `'crawler'` values that appear in the templates
reflect the canonical scorecard schema, not deployed column values.

### ASN Scorecards

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end,
  toDateTime('<baseline_start>') AS baseline_start,
  toDateTime('<baseline_end>') AS baseline_end,
  by_entity AS (
    SELECT
      asn,
      countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end) AS current_requests,
      countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end) AS baseline_requests,
      round(
        countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND isBotTraffic = true)
        / greatest(current_requests, 1) * 100, 2
      ) AS current_bot_share_pct,
      round(
        countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end AND isBotTraffic = true)
        / greatest(baseline_requests, 1) * 100, 2
      ) AS baseline_bot_share_pct,
      round(
        countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= current_start AND reqTimeSec < current_end))
        / greatest(current_requests, 1) * 100, 2
      ) AS current_cache_miss_pct,
      round(
        countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end))
        / greatest(baseline_requests, 1) * 100, 2
      ) AS baseline_cache_miss_pct,
      NULL AS current_origin_p95_ms,   -- tail-latency percentiles are NOT retained on bi_summary_*; the deployed producer emits NULL here. For average origin latency use sum_originTurnAroundTime_ms / cnt_originTurnAroundTime (see edge-ops-analysis.md).
      NULL AS baseline_origin_p95_ms,
      round(
        countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= current_start AND reqTimeSec < current_end))
        / greatest(current_requests, 1) * 100, 2
      ) AS current_rate_429_pct,
      round(
        countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end))
        / greatest(baseline_requests, 1) * 100, 2
      ) AS baseline_rate_429_pct,
      round(
        countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= current_start AND reqTimeSec < current_end))
        / greatest(current_requests, 1) * 100, 2
      ) AS current_rate_5xx_pct,
      round(
        countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end))
        / greatest(baseline_requests, 1) * 100, 2
      ) AS baseline_rate_5xx_pct
    FROM <project>.<posture_summary_hour>
    WHERE reqTimeSec >= baseline_start
      AND reqTimeSec < current_end
      AND reqHost = '<host>'
    GROUP BY asn
  )
SELECT
  asn,
  current_requests,
  baseline_requests,
  current_bot_share_pct,
  baseline_bot_share_pct,
  current_cache_miss_pct,
  baseline_cache_miss_pct,
  current_origin_p95_ms,
  baseline_origin_p95_ms,
  current_rate_429_pct,
  baseline_rate_429_pct,
  current_rate_5xx_pct,
  baseline_rate_5xx_pct,
  abs(current_requests - baseline_requests)
    / greatest(sum(abs(current_requests - baseline_requests)) OVER (), 1) * 100 AS contribution_pct,
  NULL AS origin_cost_contribution_pct   -- needs per-entity tail latency, not retained on bi_summary_* (see the origin_p95 note above); the deployed producer emits NULL
FROM by_entity
ORDER BY abs(current_requests - baseline_requests) DESC
LIMIT 50
```

### Path Scorecards

Path-grain scorecards depend on the `bot_agg_path_*` family, which is **not
currently deployed**. The `edge_ops_impact` report exposes path-grain
candidates only behind `--include-paths`; without that flag, scorecards run at
entity grain. When path-grain tables become available, follow the v1 contract
in [cache-origin-impact.md](cache-origin-impact.md) and feed the resulting
aggregate rows to `scorecard.py` with entity_type `request_path_norm`. The
expected path-grain row fields are `current_requests`, `baseline_requests`,
`current_cache_miss_pct`, `baseline_cache_miss_pct`, `current_origin_p95_ms`,
`baseline_origin_p95_ms`, `current_rate_429_pct`, `baseline_rate_429_pct`,
`current_rate_5xx_pct`, `baseline_rate_5xx_pct`, plus optional
`qs_diversity_ratio` and `origin_cost_contribution_pct`.

### Host Scorecards

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end,
  toDateTime('<baseline_start>') AS baseline_start,
  toDateTime('<baseline_end>') AS baseline_end
SELECT
  reqHost,
  countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end) AS current_requests,
  countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end) AS baseline_requests,
  round(countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND isBotTraffic = true) / greatest(current_requests, 1) * 100, 2) AS current_bot_share_pct,
  round(countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end AND isBotTraffic = true) / greatest(baseline_requests, 1) * 100, 2) AS baseline_bot_share_pct,
  -- bad-bot classification requires SIEM botType (bi_siem_policy_summary_*); not retained on posture
  round(countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_cache_miss_pct,
  round(countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_cache_miss_pct,
  NULL AS current_origin_p95_ms,   -- tail-latency percentiles are NOT retained on bi_summary_*; the deployed producer emits NULL here. For average origin latency use sum_originTurnAroundTime_ms / cnt_originTurnAroundTime (see edge-ops-analysis.md).
  NULL AS baseline_origin_p95_ms,
  round(countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_rate_429_pct,
  round(countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_rate_429_pct,
  round(countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_rate_5xx_pct,
  round(countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_rate_5xx_pct,
  countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND aiCategory != '') AS current_ai_crawler_requests,
  countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end AND aiCategory != '') AS baseline_ai_crawler_requests,
  countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot')) AS good_bot_429_requests,
  round(
    countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot'))
    / greatest(countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot'), 1) * 100, 2
  ) AS good_bot_error_rate_pct
FROM <project>.<posture_summary_day>
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
GROUP BY reqHost
ORDER BY abs(current_requests - baseline_requests) DESC
LIMIT 50
```

### AI Category Scorecards

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end,
  toDateTime('<baseline_start>') AS baseline_start,
  toDateTime('<baseline_end>') AS baseline_end
SELECT
  aiCategory,
  countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end) AS current_requests,
  countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end) AS baseline_requests,
  current_requests AS current_ai_crawler_requests,
  baseline_requests AS baseline_ai_crawler_requests,
  round(countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_cache_miss_pct,
  round(countMergeIf(`count()`, cacheStatus = false AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_cache_miss_pct,
  round(countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_rate_429_pct,
  round(countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_rate_429_pct,
  round(countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= current_start AND reqTimeSec < current_end)) / greatest(current_requests, 1) * 100, 2) AS current_rate_5xx_pct,
  round(countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= baseline_start AND reqTimeSec < baseline_end)) / greatest(baseline_requests, 1) * 100, 2) AS baseline_rate_5xx_pct
FROM <project>.<posture_summary_day>
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
  AND aiCategory != ''
GROUP BY aiCategory
ORDER BY current_requests DESC
```

### Crawler Governance Enrichment

For the predefined `crawler_governance` report this template feeds, prefer
the script-orchestrated path documented in
[`references/reporting.md`](reporting.md) — `bot_insights_report.py --report
crawler_governance` runs the query directly when local credentials resolve
and emits a handoff packet otherwise. Run the template directly via Hydrolix
MCP only for exploratory crawler analysis outside a predefined report. See
[SKILL.md "Data Firewall"](../SKILL.md#data-firewall).

Run this over the same `bi_summary_*` posture table used for the base
scorecard when the scorecard should support the `crawler_governance` report
lens. Join the returned fields into the scorecard row by entity before calling
`scorecard.py`. Preserve zero values; a zero count is evaluated evidence, while
a missing field becomes `feature_input_missing`.

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end,
  toDateTime('<baseline_start>') AS baseline_start,
  toDateTime('<baseline_end>') AS baseline_end
SELECT
  reqHost,
  countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND aiCategory != '') AS current_ai_crawler_requests,
  countMergeIf(`count()`, reqTimeSec >= baseline_start AND reqTimeSec < baseline_end AND aiCategory != '') AS baseline_ai_crawler_requests,
  countMergeIf(`count()`, statusCode = 429 AND (reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot')) AS good_bot_429_requests,
  round(
    countMergeIf(`count()`, statusCode >= 500 AND (reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot'))
    / greatest(countMergeIf(`count()`, reqTimeSec >= current_start AND reqTimeSec < current_end AND trafficCohort = 'Bot'), 1) * 100, 2
  ) AS good_bot_error_rate_pct,
  0 AS policy_surface_failures
FROM <project>.<posture_summary_hour>
WHERE reqTimeSec >= baseline_start
  AND reqTimeSec < current_end
GROUP BY reqHost
```

For aggregate-state posture summary tables such as `akamai.bi_summary_hour`, use
the metadata-reported merge functions directly. The posture summary only stores
`count()` and `sum(bytes)` aggregate states, so status-code (and method/cache)
subsets are derived from the `count()` state with a predicate, not from
per-status `countIf(...)` aggregate-state columns: use
`countMergeIf(\`count()\`, statusCode = 429)` and
`countMergeIf(\`count()\`, statusCode >= 500)`. (The
`countIfMergeIf(\`countIf(...)\`, ...)` idiom applies to the SIEM summaries,
which do retain those `countIf` states - see the SOC and SIEM enrichment
blocks below.) The fields emitted to `scorecard.py` stay canonical:
`current_ai_crawler_requests`, `baseline_ai_crawler_requests`,
`good_bot_429_requests`, `good_bot_error_rate_pct`, and
`policy_surface_failures`.

### Policy Collateral Protected-Population Enrichment

Run this over `akamai.bi_summary_hour` / `bi_summary_*` when the available data
can support protected-population collateral checks but no external policy
change record is available. Join the returned fields into the scorecard row by
entity and run `scorecard.py` with `analysis_domains: ["policy_collateral"]` or
`--domains policy_collateral`.

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end
SELECT
  reqHost,
  countMergeIf(
    `count()`,
    reqTimeSec >= current_start
      AND reqTimeSec < current_end
      AND trafficCohort = 'Bot'
  ) AS protected_population_requests,
  countMergeIf(
    `count()`,
    statusCode = 429
      AND reqTimeSec >= current_start
      AND reqTimeSec < current_end
      AND trafficCohort = 'Bot'
  ) AS good_bot_collateral_429_requests,
  round(
    countMergeIf(
      `count()`,
      statusCode >= 500
        AND reqTimeSec >= current_start
        AND reqTimeSec < current_end
        AND trafficCohort = 'Bot'
    )
    / greatest(protected_population_requests, 1) * 100, 2
  ) AS policy_collateral_error_rate_pct
FROM <project>.<posture_summary_hour>
WHERE reqTimeSec >= current_start
  AND reqTimeSec < current_end
GROUP BY reqHost
HAVING protected_population_requests > 0
ORDER BY good_bot_collateral_429_requests DESC,
  policy_collateral_error_rate_pct DESC,
  protected_population_requests DESC
LIMIT 50
```

Do not synthesize `current_displacement_requests` or
`baseline_displacement_requests` without a defined policy-change or control
review scope. Add those fields only when a caller supplies the displacement
population and comparison window.

### SOC Security Evidence Scorecards

For SOC triage, start from the SIEM-active population and evaluate only the
`security_evidence` domain. This prevents a SOC scorecard from inheriting an
Edge/Ops host list that has no SIEM rows, and it prevents unrelated cache,
origin, crawler, or policy-collateral inputs from appearing as missing SOC
evidence. Use `akamai.bi_siem_policy_summary_hour` on the TrafficPeak Akamai
project unless metadata proves a different SIEM summary table is required.

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end,
  toDateTime('<baseline_start>') AS baseline_start,
  toDateTime('<baseline_end>') AS baseline_end
SELECT
  reqHost AS request_host,
  countMergeIf(`count()`, timestamp >= current_start AND timestamp < current_end) AS current_requests,
  countMergeIf(`count()`, timestamp >= baseline_start AND timestamp < baseline_end) AS baseline_requests,
  countIfMergeIf(
    `countIf(equals(actionClass, 'deny'))`,
    timestamp >= current_start AND timestamp < current_end
  ) AS siem_blocked_requests,
  countIfMergeIf(
    `countIf(equals(authOutcome, 'fail'))`,
    timestamp >= current_start AND timestamp < current_end
  ) AS siem_auth_fail_requests,
  0 AS bad_bot_share_pct
FROM <project>.<siem_summary_hour>
WHERE timestamp >= baseline_start
  AND timestamp < current_end
GROUP BY request_host
HAVING current_requests > 0 OR siem_blocked_requests > 0 OR siem_auth_fail_requests > 0
ORDER BY siem_blocked_requests DESC, siem_auth_fail_requests DESC, current_requests DESC
LIMIT 50
```

Wrap the rows with lens metadata before running the script:

```json
{
  "entity_type": "request_host",
  "analysis_domains": ["security_evidence"],
  "table_used": "akamai.bi_siem_policy_summary_hour",
  "rows": []
}
```

Or pass the lens on the CLI:

```bash
uv run python skills/bot-insights/scripts/scorecard.py \
  --domains security_evidence \
  --file /tmp/soc-scorecard-input.json
```

Replace the `bad_bot_share_pct` placeholder with a posture-summary enrichment
when bad-bot share is needed for the SOC decision. A zero value is evaluated as
"not present"; an omitted value is treated as a missing scorecard input.

### Optional SIEM Enrichment

Run this as an enrichment query when scorecards need security action or policy
evidence. Join the returned rows to the base scorecard rows by entity in the
calling workflow before feeding JSON to `scorecard.py`.

```sql
WITH
  toDateTime('<current_start>') AS current_start,
  toDateTime('<current_end>') AS current_end
SELECT
  asn AS client_asn,
  countMerge(`count()`) AS siem_requests,
  countIfMerge(`countIf(equals(actionClass, 'deny'))`) AS siem_blocked_requests,
  countIfMerge(`countIf(equals(authOutcome, 'fail'))`) AS siem_auth_fail_requests
FROM <project>.<siem_summary_hour>
WHERE timestamp >= current_start
  AND timestamp < current_end
  AND reqHost = '<host>'
GROUP BY client_asn
ORDER BY siem_blocked_requests DESC, siem_auth_fail_requests DESC
LIMIT 50
```

## Example Input

```json
{
  "entity_type": "request_host",
  "comparison_type": "week_over_week",
  "granularity": "hour",
  "table_used": "akamai.bi_summary_hour",
  "current_window": {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"},
  "baseline_windows": [
    {"start": "2026-04-01T00:00:00Z", "end": "2026-04-08T00:00:00Z", "label": "previous_week"}
  ],
  "scope": {},
  "rows": [
    {
      "request_host": "www.example.com",
      "current_requests": 82000,
      "baseline_requests": 12000,
      "current_cache_miss_pct": 94.2,
      "baseline_cache_miss_pct": 32.4,
      "current_origin_p95_ms": 930,
      "baseline_origin_p95_ms": 410,
      "origin_cost_contribution_pct": 42.1,
      "current_rate_429_pct": 8.2,
      "baseline_rate_429_pct": 0.4,
      "bad_bot_share_pct": 76.5,
      "siem_blocked_requests": 1840
    }
  ]
}
```

## Example Output

This output is abbreviated. A full scorecard includes every evaluated feature
and every feature skipped because inputs were missing.

```json
{
  "schema_version": "bot_scorecard_artifacts.v1",
  "scorecards": [
    {
      "schema_version": "bot_entity_scorecard.v1",
      "entity_type": "request_host",
      "entity": "www.example.com",
      "scope": {},
      "comparison_type": "week_over_week",
      "granularity": "hour",
      "table_used": "akamai.bi_summary_hour",
      "current_window": {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"},
      "baseline_windows": [
        {"start": "2026-04-01T00:00:00Z", "end": "2026-04-08T00:00:00Z", "label": "previous_week"}
      ],
      "score": 100,
      "band": "urgent_review",
      "primary_domain": "origin_impact",
      "domain_scores": {
        "movement": 34,
        "origin_impact": 28,
        "cache_busting": 22,
        "crawler_governance": 8,
        "security_evidence": 26,
        "signal_alignment": 0,
        "policy_collateral": 0
      },
      "features": [
        {
          "name": "cache_miss_pct_delta_high",
          "domain": "cache_busting",
          "points": 12,
          "current": 94.2,
          "baseline": 32.4,
          "evidence": "Cache miss share moved from 32.4% to 94.2%."
        }
      ],
      "not_evaluated_features": [
        {
          "name": "good_bot_429_present",
          "domain": "crawler_governance",
          "missing_inputs": ["good_bot_429_requests"],
          "reason": "feature_input_missing"
        }
      ],
      "evidence_summary": [
        "Cache miss share moved from 32.4% to 94.2% on www.example.com."
      ],
      "recommended_next_steps": [
        "Inspect cache miss concentration on www.example.com and run edge_ops_impact with --include-paths once path-grain aggregates are available."
      ],
      "confidence": "medium",
      "confidence_reasons": [
        "summary_table_used",
        "retained_dimensions_fit",
        "current_count_sufficient",
        "baseline_count_sufficient",
        "feature_input_missing"
      ],
      "interpretation_constraints": [
        "rule_based_scorecard",
        "mechanical_features_only",
        "no_causal_claim",
        "llm_may_summarize_structured_evidence_only"
      ]
    }
  ],
  "index": {
    "schema_version": "bot_scorecard_index.v1",
    "scope": {},
    "comparison_type": "week_over_week",
    "table_used": "akamai.bi_summary_hour",
    "current_window": {"start": "2026-04-08T00:00:00Z", "end": "2026-04-15T00:00:00Z"},
    "baseline_windows": [
      {"start": "2026-04-01T00:00:00Z", "end": "2026-04-08T00:00:00Z", "label": "previous_week"}
    ],
    "ranked_entities": [
      {
        "rank": 1,
        "entity_type": "request_host",
        "entity": "www.example.com",
        "score": 100,
        "band": "urgent_review",
        "primary_domain": "origin_impact",
        "confidence": "medium"
      }
    ],
    "interpretation_constraints": [
      "rule_based_scorecard",
      "mechanical_features_only",
      "no_causal_claim",
      "llm_may_summarize_structured_evidence_only"
    ]
  }
}
```
