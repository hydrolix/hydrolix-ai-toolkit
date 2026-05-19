# www\.example\.com

Window\-scoped incident confirmation with actor\-level drilldown\.

Report type: `incident_report`

Scope: demo / akamai · host `www\.example\.com` · granularity `minute` · SIEM not available

Window: 2026\-05\-13T14:00:00Z → 2026\-05\-13T17:00:00Z vs 2026\-05\-13T11:00:00Z → 2026\-05\-13T14:00:00Z
## Executive Summary — what's critical, and why

**Criticality: Medium** · **Confidence: Low**

Volume on www\.example\.com is materially up \(\+210% on the top host\) and 429s are spiking on \`/login/\*\` — both consistent with a login\-attack pattern, but per\-actor evidence is unavailable on this cluster so naming specific origins is out of reach\. The spike flags volume\_up \+ rate\_429\_up are the only concurring signals, with no SIEM surface and no raw\-log breakdown to confirm whether the increase is concentrated on a handful of actors or spread broadly\. Escalation should wait on raw\-log access for this scope rather than acting on summary evidence alone\.

_From AI assistant._

### Confidence Drivers

- spike flags fired \(Volume up, 429 rate up\)
- raw\-log drilldown unavailable on this cluster, so target naming is out of reach
- no edge\-response signal available \(neither SIEM action class nor raw action\_applied\), so block coverage cannot be cross\-checked
- Raw actor rankings and action-target priority are shown separately so volume, severity, action class, and confidence remain distinct.

### Open Validation Items

- Validate edge-control candidates against protected traffic before enforcement.
- Credential\-access findings require auth endpoint, failure pattern, account/user identifiers, or SIEM/auth correlation\. Without those, T1110/T1110\.004 remain investigation leads\.
- Confirm whether path-pattern rows are normalized routes, real path patterns, or aggregation artifacts before route-level controls.

## Impact

| Measure | Value | Sub |
| --- | --- | --- |
| Requests | 2\.15M | \+210% |
| 429s served | 137\.60K | 6\.40% of window |
| 5xx served | 19\.35K | 0\.90% of window |
| Edge blocks | — | no edge block data |
| Hosts affected | 3 | in window |
| Top path share | 69\.8% | /login/\* · \+410% |

Top affected host: **www\.example\.com** (95\.3% of incident requests, \+210% vs baseline).

Top path pattern: `/login/\*` — 1\.50M requests (69\.8% of target traffic, \+410% vs baseline).

## Drilldown: Flagged Signals

> **No flagged targets** — no targets crossed the suspicious-actor heuristic thresholds for this window. Either the cluster has no raw access log, or no actor crossed the heuristic thresholds. Scope evidence below still applies.

## Section A — Scope Confirmation

| Measure | Value |
| --- | --- |
| Requests | 2\.15M |
| Bot share | 64\.2% |
| 429 rate | 6\.40% |
| 5xx rate | 0\.90% |

Spike flags: Volume up; 429 rate up
### Top targeted hosts

| Host | Requests | % of incident requests | Δ vs baseline |
| --- | --- | --- | --- |
| www\.example\.com | 2\.05M | 95\.3% | \+210% |
| api\.example\.com | 70\.00K | 3\.30% | \+18\.0% |
| assets\.example\.com | 20\.00K | 0\.90% | \+4\.00% |

### Top targeted path patterns

| Path pattern | Requests | % of target traffic | Δ vs baseline |
| --- | --- | --- | --- |
| /login/\* | 1\.50M | 69\.8% | \+410% |
| /api/v1/auth/\* | 340\.00K | 15\.8% | \+280% |
| / | 120\.00K | 5\.60% | \+6\.00% |

### Status mix

| Status | Requests | % of incident requests |
| --- | --- | --- |
| 200 | 1\.80M | 83\.7% |
| 429 | 137\.60K | 6\.40% |
| 401 | 130\.00K | 6\.00% |
| 500 | 19\.35K | 0\.90% |

### Country mix

| Country | Requests | % of incident requests | Δ vs baseline |
| --- | --- | --- | --- |
| US | 1\.10M | 51\.2% | \+220% |
| DE | 380\.00K | 17\.7% | \+290% |
| BR | 250\.00K | 11\.6% | \+260% |

## Section B — Actors

> **Raw drilldown unavailable** — the cluster's raw access log was not available for this report, so per-actor rankings are not shown. Scope-confirmation evidence in Section A above still applies. See the limitations appendix for the captured detail.

## Recommended Actions

| Action | Target | Duration | Risk | Validation | Rollback |
| --- | --- | --- | --- | --- | --- |
| Schedule retrospective — review SIEM coverage on affected endpoints | Detection and response coverage | Post\-incident | Low; process review\. | Retrospective identifies whether SIEM and edge evidence agree\. | N/A\. |

## Next Steps

\- Confirm the spike in the linked dashboard against a longer baseline\.
\- Stand up raw\-log access on this cluster so the actors section can populate the next time this scope is investigated\.

## Limitations

- SIEM policy summary table not present on this cluster; SIEM mixes are not available\.
- akamai\.logs is not present on this cluster; per\-actor drilldown is not available\.
- Suspicious\-target heuristics produced no flagged rows because the cluster has no raw access log; only summary\-level scope evidence is available\.

## SOC Evidence Appendix

### Artifact source map

| Claim | Artifact | Source fields |
| --- | --- | --- |
| Scope metrics and baseline deltas | `bot\_incident\_scope\.v1` | window\_confirmation, volume\_timeseries, and scope dimension rows |
| Highest\-volume raw actors | `bot\_incident\_actors\.v1` | actor\_rankings/client\_ip |
| Highest\-priority action targets | `bot\_incident\_action\_targets\.v1` | targets plus evidence\_refs |

Credential\-access findings require auth endpoint, failure pattern, account/user identifiers, or SIEM/auth correlation\. Without those, T1110/T1110\.004 remain investigation leads\.

## Method

Incident report for Demo · Akamai, scope-confirmed against trailing equal\-length prior window\.

- Schema: `bot_incident_scope.v1`
- Comparison: 2026\-05\-13T14:00:00Z → 2026\-05\-13T17:00:00Z vs 2026\-05\-13T11:00:00Z → 2026\-05\-13T14:00:00Z
- Top-N per actor field: 10
- Scoring thresholds: Action targets are sorted by heuristic severity, then observed request volume\.; Raw actor rows are sorted by raw request volume within the actor ranking artifact\.; ATT\&CK credential\-access mappings are investigation leads unless auth\-specific evidence is present\.
- Constraints: Mechanical features only; No causal claim; No malicious intent claim

Generated 2026-05-19 02:44 UTC