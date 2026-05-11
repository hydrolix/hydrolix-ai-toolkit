# Traffic composition and triage

Use this playbook for totals, traffic mix, or broad operational checks. Apply
[schema guidance](schema.md) before rendering SQL parameters.

## Composition

Prerequisites: CDN time, host, count state, and `biTrafficCohort`. Classification
requires established encoding semantics. For mixed variants, add `biVariant`
to SELECT and GROUP BY to report composition separately. For a plain total,
keep all requested rows and omit the cohort expressions; cohort or variant
unavailability does not block an independently supported total.

```sql
SELECT
    countMerge(`count()`) AS total_requests,
    countMergeIf(`count()`, biTrafficCohort = 'Human') AS human_requests,
    countMergeIf(`count()`, biTrafficCohort = 'Bot') AS bot_requests,
    countMergeIf(`count()`, biTrafficCohort = 'AI') AS ai_requests
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
```

Automation share is `(bot_requests + ai_requests) / total_requests` for a
positive denominator. Show any residual outside the named cohorts. With no
represented requests, report no observations; the share is undefined.

## Freshness and operational rates

Check the latest observed bucket in the same scope. Its timestamp reflects the
summary grain, not necessarily the latest individual event. An empty result
cannot establish freshness, and a recent bucket cannot prove complete ingestion.

```sql
SELECT maxOrNull(reqTimeSec) AS latest_bucket
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
```

When `statusCode` and `cacheStatus` are retained, inspect service symptoms:

```sql
SELECT
    countMerge(`count()`) AS requests,
    100.0 * countMergeIf(`count()`, statusCode = 429)
        / nullIf(requests, 0) AS rate_limited_pct,
    100.0 * countMergeIf(`count()`, statusCode >= 500 AND statusCode < 600)
        / nullIf(requests, 0) AS server_error_pct,
    100.0 * countMergeIf(`count()`, cacheStatus = true)
        / nullIf(requests, 0) AS cache_hit_pct
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
```

Compare symptoms with the requested baseline or deployment-specific objectives.
Nullable status/cache fields can leave unclassified observations; name that
coverage limit when interpreting the rates. Universal bot-share or cache-miss
thresholds are not evidence of an incident.

Route changes and ASN contributors to [SOC](soc.md), crawler access and AI
content targeting to [governance](seo.md), and cache/origin symptoms to
[Edge/Ops](edge-ops.md). Treat unavailable rate inputs separately from a healthy
result. Broad triage need not run every playbook.
