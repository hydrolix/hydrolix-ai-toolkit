# Crawler governance

Use this playbook for crawler-file access, useful-crawler rate limiting, and AI
content targeting. Apply [schema guidance](schema.md) before rendering SQL.

## Crawler-file responses

Prerequisites beyond common CDN fields: `biResourceCategory` and numeric
`statusCode`. This query needs neither raw paths nor UA categories.

```sql
SELECT
    biResourceCategory AS resource_category,
    countMerge(`count()`) AS requests,
    countMergeIf(`count()`, statusCode >= 200 AND statusCode < 300) AS status_2xx,
    100.0 * status_2xx / nullIf(requests, 0) AS status_2xx_pct
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
  AND biResourceCategory IN ('robots.txt', 'sitemap.xml', 'ads.txt', 'llms.txt')
GROUP BY biResourceCategory
ORDER BY resource_category
```

This is observed response coverage for classified resources. A missing category
means no matching observations, not a missing file. A 2xx rate is not complete
crawler success: inspect redirects, 304s, failures, and intended site policy
when the decision depends on reachability. These counts include all selected
requesters unless a verified crawler filter is added.

## Crawler rate limiting

Prerequisites: `biUserAgentCategory`, numeric status, and common CDN fields.

```sql
SELECT
    biUserAgentCategory AS user_agent_category,
    countMerge(`count()`) AS requests,
    countMergeIf(`count()`, statusCode = 429) AS rate_limited_requests,
    100.0 * rate_limited_requests / nullIf(requests, 0) AS rate_limited_pct
FROM `{database}`.`{cdn_summary}`
WHERE reqTimeSec >= toDateTime('{start_utc}', 'UTC')
  AND reqTimeSec < toDateTime('{end_utc}', 'UTC')
  AND reqHost = {host_sql}
  {variant_scope}
  AND notEmpty(biUserAgentCategory)
GROUP BY biUserAgentCategory
ORDER BY rate_limited_requests DESC, requests DESC, user_agent_category
LIMIT 50
```

The query lists labeled UA categories; nonempty category does not mean a
verified good bot. Establish which categories represent locally useful crawlers
and corroborate identity before recommending an allowlist. Sustained 429s can
justify a rate-limit policy review, depending on the site's objectives.

## AI targeting

When `biReqPathPattern` and `biTrafficCohort` are retained, group represented
requests by path pattern and conditionally merge the `AI` cohort. Divide AI
requests by all requests for the same pattern. Rank by AI volume and show both
volume and share. Use the composition pattern with that extra grouping.

A pattern groups multiple URLs. If exact paths are required, discover a surface
that retains them. High AI share identifies content for governance review;
robots/terms, identity evidence, and business context are needed to assess
policy violation or harm. Return findings to the site owner with those limits.
