# www\.example\.com

Window\-scoped incident confirmation with actor\-level drilldown\.

Report type: `incident_report`

Scope: demo / akamai · host `www\.example\.com` · granularity `minute` · SIEM not available

Window: 2026\-05\-13T14:00:00Z → 2026\-05\-13T17:00:00Z vs 2026\-05\-13T11:00:00Z → 2026\-05\-13T14:00:00Z
## Executive Summary — what's critical, and why

**Criticality: Medium** · **Confidence: Low**

Volume on www\.example\.com is materially up \(\+210% on the top host\) and 429s are spiking on \`/login/\*\` — both consistent with a login\-attack pattern, but per\-actor evidence is unavailable on this cluster so naming specific origins is out of reach\. The spike flags volume\_up \+ rate\_429\_up are the only concurring signals, with no SIEM surface and no raw\-log breakdown to confirm whether the increase is concentrated on a handful of actors or spread broadly\. Escalation should wait on raw\-log access for this scope rather than acting on summary evidence alone\.

_From AI assistant._

## Impact

| Measure | Value | Sub |
| --- | --- | --- |
| Requests | 2\.15M | \+210% |
| 429s served | 137\.60K | 6\.40% of window |
| 5xx served | 19\.35K | 0\.90% of window |
| Edge blocks | — | no edge block data |
| Hosts affected | 3 | in window |
| Top path share | 69\.8% | /login/\* · \+410% |

Top affected: **www\.example\.com** `/login/\*` — 1\.50M requests (69\.8% of window, \+410% vs baseline).

## Suspicious Targets

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

| Host | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| www\.example\.com | 2\.05M | 95\.3% | \+210% |
| api\.example\.com | 70\.00K | 3\.30% | \+18\.0% |
| assets\.example\.com | 20\.00K | 0\.90% | \+4\.00% |

### Top targeted path patterns

| Path pattern | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| /login/\* | 1\.50M | 69\.8% | \+410% |
| /api/v1/auth/\* | 340\.00K | 15\.8% | \+280% |
| / | 120\.00K | 5\.60% | \+6\.00% |

### Status mix

| Status | Requests | Share |
| --- | --- | --- |
| 200 | 1\.80M | 83\.7% |
| 429 | 137\.60K | 6\.40% |
| 401 | 130\.00K | 6\.00% |
| 500 | 19\.35K | 0\.90% |

### Country mix

| Country | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| US | 1\.10M | 51\.2% | \+220% |
| DE | 380\.00K | 17\.7% | \+290% |
| BR | 250\.00K | 11\.6% | \+260% |

## Section B — Actors

> **Raw drilldown unavailable** — the cluster's raw access log was not available for this report, so per-actor rankings are not shown. Scope-confirmation evidence in Section A above still applies. See the limitations appendix for the captured detail.

## Next Steps

\- Confirm the spike in the linked dashboard against a longer baseline\.
\- Stand up raw\-log access on this cluster so the actors section can populate the next time this scope is investigated\.

## Limitations

- SIEM policy summary table not present on this cluster; SIEM mixes are not available\.
- akamai\.logs is not present on this cluster; per\-actor drilldown is not available\.
- Suspicious\-target heuristics produced no flagged rows because the cluster has no raw access log; only summary\-level scope evidence is available\.

## Method

Incident report for Demo · Akamai, scope-confirmed against a trailing equal-length baseline.

- Schema: `bot_incident_scope.v1`
- Top-N per actor field: 10
- Constraints: Mechanical features only; No causal claim; No malicious intent claim

Generated 2026-05-18 02:03 UTC