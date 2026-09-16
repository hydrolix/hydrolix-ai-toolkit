# SOC and changes

Use this playbook for baseline changes, ASN contributors, and SIEM policy
context. Apply [schema guidance](schema.md) before rendering SQL parameters.

## Current versus baseline

Use the user's baseline; otherwise start with the immediately preceding
window of equal duration. Match host, variant, cohort, and other filters.
Equal duration alone does not control weekday/hour seasonality or collection
lag. For a before/after control review, also establish the intervention time
and check protected traffic; coincident changes do not establish effectiveness.

Run [composition and operational rates](triage.md) for each window to establish
totals and denominators. Then rank signed contributor deltas by absolute
magnitude, so both rising and falling contributors remain visible.

The following assumes adjacent, equal-duration, bucket-aligned windows.
Prerequisites beyond the common CDN fields: string `asn` and `biTrafficCohort`.
It measures Bot/AI volume, not all traffic. Keep one established variant for
this classification comparison, or run separately for each variant.

```sql
WITH
    toDateTime('{baseline_start_utc}', 'UTC') AS baseline_start,
    toDateTime('{start_utc}', 'UTC') AS current_start,
    toDateTime('{end_utc}', 'UTC') AS current_end
SELECT
    asn,
    countMergeIf(`count()`, reqTimeSec >= current_start
        AND reqTimeSec < current_end) AS current_requests,
    countMergeIf(`count()`, reqTimeSec >= baseline_start
        AND reqTimeSec < current_start) AS baseline_requests,
    toInt64(current_requests) - toInt64(baseline_requests) AS delta
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= baseline_start AND reqTimeSec < current_end
  AND reqHost = {host_sql}
  {variant_scope}
  AND biTrafficCohort IN ('Bot', 'AI')
  AND notEmpty(asn)
GROUP BY asn
ORDER BY abs(delta) DESC, asn
LIMIT 10
```

Compare returned contributions with the full-window Bot/AI totals. Show the
residual, including missing ASNs and contributors outside top-N. Opposing
changes can cancel in the net delta; do not present a share of net change as a
share of traffic. ASN is an investigation dimension, not actor identity.

A source absent from the baseline is newly observed in that window, not
first-ever or malicious. An explicit longer lookback can test recurrence.
Pair 429/5xx changes with cohort/path evidence before attributing pressure.

## SIEM policy context

Use only when Bot Manager/SIEM evidence is relevant and the actual SIEM table
is available. Missing SIEM data leaves policy context unavailable; retain
supported CDN observations without changing the assumed CDN encoding variant.
Prerequisites: SIEM `timestamp`, `reqHost`, `policyId`, `biActionClass`,
`biBotType`, and the verified count state.

```sql
SELECT
    policyId,
    biActionClass,
    biBotType,
    countMerge(`count()`) AS events
FROM `{database}`.`{siem_summary}`
WHERE timestamp >= toDateTime('{start_utc}', 'UTC')
  AND timestamp < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  AND isNotNull(policyId)
GROUP BY policyId, biActionClass, biBotType
ORDER BY events DESC, policyId, biActionClass, biBotType
LIMIT 50
```

`deny` groups show recorded denial context. This query includes all selected
SIEM events, not just bot verdicts. Its top groups do not supply a complete
policy denominator. To calculate denial rate per policy, group by policy and
conditionally merge denial counts over all selected actions. Keep that SIEM
rate separate from CDN request rates.

Recommend the next focused validation or policy-owner review supported by the
evidence. Enforcement recommendations need corroborated identity/behavior,
local policy context, and a check for useful-crawler or other collateral impact.
