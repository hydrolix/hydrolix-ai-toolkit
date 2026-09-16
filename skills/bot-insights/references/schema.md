# Schema and classification

## Deployment selection

The patterns describe the TrafficPeak CDN and Bot Manager/SIEM bundles at
version `1.1.1`. This is source guidance, not detection of an installed version.
Discover actual tables and inspect query-visible types and aggregate states.

| Concept | Bundle 1.1.1 guidance | Other names documented by earlier toolkit guidance |
| --- | --- | --- |
| CDN summaries | `bi_cdn_summary_minute/hour/day` | `bi_summary_minute/hour/day` |
| SIEM summaries | `bi_bm_siem_summary_minute/hour/day` | `bi_siem_policy_summary_minute/hour/day` |
| CDN time / host | `reqTimeSec` / `reqHost` | Verify metadata |
| SIEM time / host | `timestamp` / `reqHost` | `timestamp` / `host` or `reqHost` |
| Cohort | `biTrafficCohort` | `trafficCohort` |
| AI / UA category | `biAiCategory` / `biUserAgentCategory` | `aiCategory` / `userAgentCategory` |
| Resource / path grouping | `biResourceCategory` / `biReqPathPattern` | `resourceCategory` / `reqPathPattern` |
| SIEM action / bot type | `biActionClass` / `biBotType` | `actionClass` / `botType` |

These are discovery hints, not interchangeable aliases. Establish each field's
meaning and aggregation before adapting SQL. Neither table naming nor matching
columns proves the active transform version. Request-level tables and path/IP/UA
detail are usable only when separately discovered and authorized; a summary
cannot recover dimensions it did not retain.

## Encoding variants

Determine which rules encoded the selected rows from deployment evidence or,
when `biVariant` exists, an authorized bounded query of its values.

- `cdn`: CDN `biIsBotTraffic` comes from the user-agent dictionary verdict.
- `bm_siem`: CDN classification also includes a `securityRules` BOT match.
  SIEM classification uses `attack_bot` or positive `botScore`, with the UA
  dictionary fallback. SIEM action classification prioritizes deny/block,
  mitigation, monitoring, then allow.
- CDN `biTrafficCohort` is `Human` when the bot flag is false, otherwise `AI`
  when `biAiCategory` is nonempty, otherwise `Bot`.

For `cdn` investigations, finish with CDN findings; SIEM is outside that
variant and is not required input.

A Bot Manager subscription or missing SIEM table does not select an encoding
variant. If encoding is unknown, continue supported totals and request context
before interpreting classification. Report mixed variants separately for
classification comparisons and show excluded coverage if narrowing the scope.
Mixed variants alone prove neither duplicated nor disjoint requests; qualify
unique-request claims unless ingestion/deduplication evidence supports them.

Owner enrichment and bot-identity checks are separate from UA classification.
Their presence in a transform does not guarantee their retention as dimensions
in a summary. A category label alone cannot verify a crawler owner.

## Summary anatomy

Record the selected time grain, retained dimensions, metric representations,
and missing detail needed by the question. The versioned CDN hour definition
retains `biReqPathPattern`, not raw `reqPath`. Use the label "path pattern" for
that grouping; a request for exact URLs needs another verified surface.

The source defines count, conditional count/sum, and distinct aggregate aliases.
Resolve their live column names and representations before writing queries:

- A verified count state such as `count()` uses `countMerge` / `countMergeIf`.
  Source alias `cnt_all` is not proof of a summable numeric column.
- Inspect `column_category` and `default_expr` as well as the type. A numeric
  `SummaryColumn` can expand to an aggregate expression. Use its underlying
  state with the metadata's exact `merge_function`, or select the alias directly
  with the requested dimension grouping; wrapping it in `sum()` nests aggregates.
- Origin latency is the merged valid-duration sum divided by its matching
  merged observation count. Average of per-row averages is incorrect.
- Query-string request counts use the verified conditional-count merge.
  Distinct query-string states require the matching distinct merge across
  groups. Summing per-group distinct counts does not give global cardinality.

## Template parameters

All SQL fences in these playbooks are templates, not executable tool calls.
Resolve `{database}`, `{cdn_summary}`, and `{siem_summary}` from discovered
identifiers and safely quote them. Replace `{host_sql}` with an escaped string
literal, and timestamps with explicit UTC `YYYY-MM-DD HH:MM:SS` values.
`{variant_scope}` is `AND biVariant = 'cdn'`, `AND biVariant = 'bm_siem'`, or
empty for requested all-variant totals. Keep comparison scopes consistent.
For fleet questions, omit the host predicate and preserve requested grouping.

Templates assume DateTime-compatible time columns, string dimensions, numeric
status, boolean cache status, and a verified `count()` count state. Adapt only
from metadata evidence. Specialized metric-expression placeholders are defined
beside their queries and must be resolved before execution. Missing prerequisites
block the affected metric or pattern, not independently supported totals.
