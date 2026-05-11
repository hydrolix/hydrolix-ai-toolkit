# Bot Insights live validation

Result: all nine SQL templates in the simplified investigation skill executed
successfully through Hydrolix MCP against `demo.trafficpeak.live`, project
`akamai`, on 2026-09-16. The user explicitly requested these live tests.
Queries were read-only SELECTs with a 30-second execution limit.

## Scope and routing

- Metadata: `bi_cdn_summary_hour`, `bi_bm_siem_summary_hour`, `bi_summary_hour`.
- Main host: `www.big-mega-corp.com`.
- Additional populated SEO/AI/churn scope: `docs.hydrolix.io`.
- Current window: `[2026-09-15 13:00:00, 2026-09-15 14:00:00)` UTC.
- Baseline: `[2026-09-15 12:00:00, 2026-09-15 13:00:00)` UTC.
- Encoding: `bm_siem`, version field `111`, observed during bounded discovery.
- Initial discovery scanned hourly summaries over September 15-16 UTC, with
  limited grouped output. Subsequent checks used the windows above.

Every MCP call specified the cluster explicitly. Metadata confirmed the live
time/host aliases, retained path patterns, count state, and specialized merge
functions. SQL templates were extracted from the actual skill references and
rendered with these values. No source tables, settings, or policies were changed.

## Checks

| Playbook | Outcome |
| --- | --- |
| Composition | Passed; totals reconciled with a separate hour/cohort/status/cache grouping. |
| Freshness | Passed; populated scope returned its hour bucket; empty scope returned null. |
| Operational rates | Passed; rates reconciled with grouped counts; empty denominators returned null. |
| ASN changes | Passed; top contributors, signed deltas, and ordering matched a separate hourly ASN aggregation. |
| SIEM policy groups | Passed; group totals reconciled with an independent total; conditional denials matched the dedicated denial aggregate state. |
| Crawler files | Main host returned no matching rows; docs host returned populated categories. Totals and 2xx counts reconciled with a separate status breakdown. |
| UA-category rate limiting | Passed with populated results. Category labels were not treated as verified crawler identity. |
| Cache by path pattern | Passed with populated results and numeric rates. |
| Origin latency | Passed using metadata-selected merges; duration sums and observation counts matched direct summary aliases with the same grouping. |

Additional prose-guided AI path and query-string churn queries returned
populated results. Churn used `countIfMerge` and `uniqIfMerge` from metadata,
without summing distinct counts. The older `bi_summary_hour` supported a total
query but lacked `biVariant`; encoding-specific interpretation stayed unverified.

## Guidance correction

Live metadata exposes numeric `SummaryColumn` aliases that expand to aggregate
expressions. The schema reference now explicitly requires checking column
category and expression, not only numeric type. Direct grouped alias values
were compared successfully with the corresponding underlying state merges.

## What this cannot tell you

This validates query compatibility and selected arithmetic invariants on hourly
demo summaries. It does not establish complete or duplicate-free ingestion,
raw-request parity, bot intent, crawler ownership, causality, or the quality of
customer-facing operational recommendations. It does not exercise a populated
`cdn` deployment, populated mixed-variant comparisons, other summary grains,
or other clusters. Synthetic CDN-only evaluation is recorded below.

The AI/churn checks establish executable, populated patterns; their results
were not independently reconciled against raw requests. Empty-scope checks used
a deliberately unmatched `.invalid` host. No missing-table queries or invalid
column queries were deliberately submitted: unsupported scope was identified
from metadata. This was an informed execution review, not a blind agent trial.

## Local evidence

Exact SQL, MCP responses, selected table metadata, and assertion outcomes are
saved in `docs/live-tests/bot-insights/evidence.json` beside this report. That
local evidence directory is ignored by Git; it is not part of skill downloads.
This report is a validation record, not a promise of ongoing coverage.


## CDN-only evaluation

A follow-up scan grouped daily summary rows by variant/version over
`[2026-08-17 00:00:00, 2026-09-17 00:00:00)` UTC and found only `bm_siem`.
An independent hourly query with `biVariant = 'cdn'` over the same window
returned zero represented requests and null bounds. This establishes no matching
CDN-only rows in those summaries and that window, not cluster-wide absence.

All eight applicable CDN query templates then passed on the live query engine
using synthetic aggregate states in read-only CTEs. The fixture supplied explicit
UA dictionary verdicts; CDN classification and cohort expressions were taken
from the versioned CDN-only bundle source. The fixture does not test dictionary
lookup contents, ingestion, or a deployed CDN-only transform.

Expected results were asserted for composition, freshness, rates, ASN deltas,
crawler resources, UA categories, cache patterns, and weighted origin latency.
Additional checks verified that:

- A UA-negative request with a BOT security rule stays Human under CDN-only
  rules; the corresponding Bot Manager fixture becomes Bot.
- The CDN filter excludes a deliberately included Bot Manager row, while an
  all-variant total includes it.
- Merged distinct query strings deduplicate repeated strings across groups.
- No SIEM query is part of CDN-only template evaluation.

The schema guidance now explicitly says CDN-only investigations require no SIEM
input. Exact fixtures, SQL, responses, and expected-result assertions are saved
locally in `docs/live-tests/bot-insights/cdn-only-evidence.json` (Git-ignored).
CDN-only logic and query execution passed; populated deployment coverage remains
unverified and is not a release gate for this preparation, per user direction.
