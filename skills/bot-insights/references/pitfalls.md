# bot-insights — Pitfalls

## Pitfalls

- **Bot score range**: `bot_score` is a uint8 (0-255). A score of 0 does not
  necessarily mean human — check `is_bot_traffic` for the boolean classification.
- **CDN-specific enrichment**: `bot_class`, `bot_confidence`, `bot_intent`, and
  `bot_verification_tier` come from 6 transforms (primarily Akamai SIEM). They
  may be empty for traffic from other CDN sources, and they live on
  request-level surfaces that are not currently deployed on observed clusters
  — apply the deployment-availability rule (SKILL.md) before composing SQL
  against them.
- **Akamai vs. Hydrolix columns**: Akamai-provided signals (`bot_score`,
  `bot_category`, `bot_type`) and Hydrolix-derived signals (`bot_class`,
  `bot_intent`, `bot_confidence`) are independent. Divergences between the two
  are investigative signals, not errors. The Hydrolix-derived columns live on
  request-level surfaces that are not currently deployed; apply the
  deployment-availability rule (SKILL.md) when comparing the two today.
- **`user_agent_category`**: Only populated from Akamai SIEM transforms, not
  all 8 CDN sources. Use `bot_category` for broader coverage.
- **`response_status_code` is a string**: Use string comparison (e.g.,
  `>= '400'`) or cast with `toUInt32OrZero()`.
- **TrafficPeak status fields are numeric**: The live
  `demo.trafficpeak.live` summary dashboards use numeric `statusCode` on
  `bi_summary_*` and numeric `status`/`statusCode` on
  `bi_siem_policy_summary_*`. Do not copy request-level string comparisons
  into those summary queries.
- **TrafficPeak SIEM policy names are camelCase**: The live Akamai SIEM policy
  summaries expose fields such as `policyId`, `actionClass`, `botType`,
  `cnt_authFail`, `avg_botScore`, and `uniq_clientIp`. Normalize result JSON to
  snake_case only after querying.
- **SIEM/DS2 deduplication**: The same request can appear in both SIEM and DS2
  feeds. Be explicit about which data source you are querying when counting.
  Filter by `hdx_cdn` to isolate a single source.
- **Suppressed columns**: `attack_data_raw`, `request_headers_raw`,
  `request_query_string`, and several others are suppressed. Use the normalized
  equivalents.
- **Summary-first selection**: This bundle has minute/hour/day summaries. Prefer
  them when retained dimensions fit the question, especially for posture
  movement and executive trends.
- **Request-level query is explicit**: Use request-level tables only when (a)
  the target cluster actually deploys them and (b) a required dimension is
  missing from summaries; otherwise apply the deployment-availability rule
  (SKILL.md). State the reason and keep tight time filters.
- **QoQ performance**: Do not assume quarter-over-quarter queries need monthly
  or quarterly summaries. Query or benchmark daily summaries first, then propose
  coarser summaries only with measured evidence.
- **Summary metadata**: Summary tables expose aggregate-state columns. Inspect
  table metadata with Hydrolix MCP or the host query tool before querying and
  use reported merge functions when required.
- **Local scripts**: Scripts must accept MCP query results or pasted aggregate
  JSON. Do not add database clients, connection settings, credential handling,
  or direct query execution.
- **Delta baselines**: The demo and dashboards use `(current - baseline) / greatest(baseline, 1) * 100`
  as the standard delta formula. Use the same approach for consistency when writing
  custom queries.
- **Incident report raw-log bounds**: Any query the incident_report flow runs
  against `akamai.logs` MUST carry both a time predicate (between the analyst
  window's start/end) and a scope predicate (`reqHost`, `asn`, and/or
  `request_path LIKE ...`). The orchestrator builds the WHERE clause
  mechanically — never let analyst input flow directly into SQL.
- **DESCRIBE-validated field names only**: The incident_report orchestrator
  validates `--fields` against the cluster's actual `akamai.logs` column list
  before running any phase-2 query. Unknown field names fail closed before
  the raw-log table is touched. Do not add fields the cluster does not deploy
  by hand-editing the SQL.
- **Missing raw access log graceful skip**: When `akamai.logs` is not present
  on the target cluster, the incident_report flow sets
  `raw_drilldown_available: false`, populates `limitations`, and still
  renders Section A from summary tables. It does not silently substitute
  another raw surface, and the LLM prose must never name `akamai.logs`
  directly — refer to "this report's raw access log" or "the actors section"
  instead.
- **Suspicious-target heuristics are conservative by design**: The v2
  ladder in `bot_insights_report.py` caps single-signal flags at
  `severity: review`. Promoting to `high` requires multi-signal
  concurrence. `suggested_action_hint` is always `"review"` in v2
  regardless of severity — the field is present so downstream WAF /
  bot-manager MCP tooling can switch on it later, not because v2
  knows where the false-positive line sits. Do not edit
  `_SUSPICIOUS_*` constants or `_AUTOMATION_UA_PATTERN` without
  re-running calibration against representative incidents.
