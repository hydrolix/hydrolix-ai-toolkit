---
name: bot-insights
description: Investigate Bot Insights traffic composition and changes, crawler access, SIEM policy observations, and cache or origin impact using Hydrolix query tools.
license: Apache-2.0
metadata:
  version: 1.1.0
  author: Hydrolix
  bundle: bot-insights
---

# Bot Insights Investigation

Connect automation classifications to observed traffic and operational impact.
Use the existing Hydrolix MCP or host query tools within the user's authorized
scope. This skill supplies domain guidance and SQL patterns.

## Start with the question

1. Establish the cluster, database, host or fleet scope, time window, and
   decision the user needs. Preserve their requested grouping and baseline.
2. Discover tables and inspect their columns, types, time grain, and aggregate
   representations with `get_table_info` or the equivalent metadata tool.
   Read [schema and classification](references/schema.md) when selecting a
   table, interpreting bot labels, or adapting between deployment versions.
3. Select the smallest relevant playbook below. Check its query prerequisites;
   run supported portions and explain the specific missing inputs for the rest.
4. Interpret results with coverage limits and a concrete next investigation or
   operator decision. Separate observations from possible explanations.

| Question | Read |
| --- | --- |
| What is the traffic mix, or which operational area needs attention? | [Traffic composition and triage](references/triage.md) |
| What changed, which ASNs moved, or what did SIEM policies observe? | [SOC and changes](references/soc.md) |
| Are useful crawlers being limited, or which content attracts AI crawlers? | [Crawler governance](references/seo.md) |
| Which paths have cache misses, origin latency, or query-string churn? | [Edge and origin](references/edge-ops.md) |

## Evidence rules

- Bot, Human, and AI are encoding labels. They alone establish neither intent,
  verified ownership, abuse, nor business impact. UA-derived classifications
  can be spoofed; corroborate identity and behavior before recommending controls.
- `biVariant` identifies encoding rules. Both `cdn` and `bm_siem` can occur in
  CDN summaries. All-CDN totals retain both unless the user narrows the scope;
  classification comparisons keep variants separate and consistent over time.
- Count represented requests with the verified aggregate expression. Counting
  summary rows measures stored groups. A source SQL alias does not establish
  that the live column is an ordinary number suitable for `sum()`.
- Use half-open UTC windows `[start, end)` aligned to summary buckets. Choose
  a finer verified grain when partial buckets matter. Keep the original window
  and filters during contributor drill-downs.
- Report residual categories and traffic outside top-N contributors. Distinguish
  no observations, unavailable dimensions, incomplete coverage, and query failure.
- Compare rates as well as counts. Unknown ingestion coverage, collection lag,
  seasonality, and changed transform/dictionary versions limit delta conclusions.
  A zero baseline does not support a finite percentage increase.
- CDN request counts and SIEM event counts have different populations. Shared
  host/time scope does not establish a join or a one-to-one relationship.

Return the user's requested format, supported findings, material limitations,
and the next useful step. A simple total needs only its scope and relevant
caveats; use focused playbooks when the question needs a deeper investigation.
