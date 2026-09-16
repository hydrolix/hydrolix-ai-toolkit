# Edge and origin

Use this playbook for cache misses, origin latency, and query-string churn.
Apply [schema guidance](schema.md) before rendering SQL parameters.

## Cache misses by path pattern

Prerequisites beyond common CDN fields: `biReqPathPattern`, `biTrafficCohort`,
and boolean `cacheStatus`. Keep variants separate for cohort interpretation.

```sql
SELECT
    biReqPathPattern AS path_pattern,
    biTrafficCohort AS cohort,
    countMerge(`count()`) AS requests,
    countMergeIf(`count()`, cacheStatus = false) AS cache_misses,
    100.0 * cache_misses / nullIf(requests, 0) AS cache_miss_pct
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
GROUP BY biReqPathPattern, biTrafficCohort
ORDER BY cache_misses DESC, requests DESC, path_pattern, cohort
LIMIT 10
```

Keep miss volume and miss rate separate. Dynamic and static content have
different expected behavior; compare like content with its baseline or local
cache objectives. Missing cache status limits coverage. A miss is not proof of
an origin fetch, backend cost, cache busting, or abuse.

## Origin latency

Resolve `{origin_sum_merge}` and `{origin_count_merge}` to aggregate expressions
for the same valid-duration population from live metadata. Use matching merge
functions for states, or `sum()` only for confirmed additive numeric metrics.
Prerequisites also include the path grouping and common scope/count fields.

```sql
SELECT
    biReqPathPattern AS path_pattern,
    countMerge(`count()`) AS requests,
    {origin_sum_merge} AS origin_duration_sum_ms,
    {origin_count_merge} AS origin_observations,
    origin_duration_sum_ms / nullIf(origin_observations, 0) AS avg_origin_ms
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
GROUP BY biReqPathPattern
ORDER BY origin_duration_sum_ms DESC, path_pattern
LIMIT 10
```

The duration sum is an observed latency-volume proxy, not CPU time, money, or
proof of bot-caused load. Show observation coverage alongside request counts.
Using total requests times average origin latency can inflate the proxy when
only a subset has an origin observation.

## Query-string churn

For the same paths and scope, merge the query-string-present count and distinct
query-string state using metadata-confirmed functions. Pair them with miss
volume/rate and origin observations. Distinct counts per summary group are not
additive; if only finalized counts remain, label their sum as per-group counts
and state that global distinct cardinality is unavailable.

High variation plus cache misses is a lead for checking cache-key rules and
query parameter behavior. Summary co-occurrence does not establish causality.
Use raw requests or cache configuration when exact URLs, parameter names, or
fetch causes are necessary; end with that targeted check or an ops-owner review.
