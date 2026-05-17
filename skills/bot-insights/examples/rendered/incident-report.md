# www\.example\.com

Window\-scoped incident confirmation with actor\-level drilldown\.

Report type: `incident_report`

Scope: demo / akamai · host `www\.example\.com` · granularity `minute` · SIEM available

Window: 2026\-05\-13T14:00:00Z → 2026\-05\-13T17:00:00Z vs 2026\-05\-13T11:00:00Z → 2026\-05\-13T14:00:00Z
## Executive Summary — what's critical, and why

**Criticality: Critical** · **Confidence: High**

\*\*Assessed with high confidence:\*\* this window is consistent with a targeted credential\-stuffing pattern against \`/login/\*\` on www\.example\.com — with a separately\-corroborating signal in the Browser\-cohort behavioral anomaly\. This is not a broad traffic shift\.

Four independent signals concur:

\- Spike flags \`volume\_up\`, \`rate\_429\_up\`, and \`bot\_share\_up\` all fired against the trailing window\.
\- Three client IPs \(\`203\.0\.113\.10\`, \`198\.51\.100\.42\`, \`192\.0\.2\.17\`\) reached \`severity: critical\` — they share ASN \`64500\`, concentrate on a single path, and carry both high volume share and high 429 share\. ASN \`64500\` itself and User Agent \`python\-requests/2\.31\` sit at \`severity: high\` alongside them\.
\- SIEM \`block\-credential\-stuff\` policy delta is \+520% vs baseline, with \`rate\-limit\-login\` at \+610%\.
\- The Traffic cohort \`Browser\` graduated on the \`anomaly\` primitive: its current\-window error rate of 13\.7% is 26× its baseline \(~0\.5%\)\. This is consistent with sophisticated automation passing bot\-classification — the kind of pattern that needs an application\-layer response, not just WAF rules tuned for the named IP cluster\.

The 4\.25M\-request / 8\.2% 429\-rate Impact tiles are consistent with the primary read; the reasons to escalate are the named single\-ASN cluster, the automation UA matches, \*and\* the Browser\-cohort behavioral departure — not the raw volume\.

_From AI assistant._

## Impact

**429s per minute:** peak 6\.54K (baseline avg ~203) across 2026\-05\-13 14:00Z → 2026\-05\-13 17:00Z. _(rate\_429\_up was the most specific spike flag — the rate\-limit pressure curve is the lede)_

| Measure | Value | Sub |
| --- | --- | --- |
| Requests | 4\.25M | \+312% |
| 429s served | 348\.50K | 8\.20% of window |
| 5xx served | 46\.75K | 1\.10% of window |
| Edge blocks | 195\.50K | 4\.60% of window |
| Hosts affected | 5 | in window |
| Top path share | 68\.2% | /login/\* · \+530% |

Top affected: **www\.example\.com** `/login/\*` — 2\.90M requests (68\.2% of window, \+530% vs baseline).

## Suspicious Targets

**Top 5 of 9 flagged targets, by share of window traffic:**

- **Client ASN** `64500` — 43\.5% (High)
- **Traffic cohort** `Browser` — 28\.6% (High)
- **User Agent** `python\-requests/2\.31` — 21\.6% (High)
- **Client IP** `203\.0\.113\.10` — 12\.7% (Critical)
- **Client IP** `198\.51\.100\.42` — 9\.90% (Critical)

| Type | Target | Reasons | ATT&CK (consistent with) | Requests | Share | 429s | Severity | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Client IP | `203\.0\.113\.10` | high volume share; high 429 share; single\-path concentration; single\-ASN cluster | T1498, T1110, T1110\.004, T1583\.003 | 540\.00K | 12\.7% | 92\.00K | Critical | High |
| Client IP | `198\.51\.100\.42` | high volume share; high 429 share; single\-path concentration; single\-ASN cluster | T1498, T1110, T1110\.004, T1583\.003 | 420\.00K | 9\.90% | 65\.00K | Critical | High |
| Client IP | `192\.0\.2\.17` | high volume share; high 429 share; single\-path concentration; single\-ASN cluster | T1498, T1110, T1110\.004, T1583\.003 | 360\.00K | 8\.50% | 41\.00K | Critical | High |
| Client ASN | `64500` | high volume share; high 429 share | T1498, T1110 | 1\.85M | 43\.5% | 195\.00K | High | Medium |
| Traffic cohort | `Browser` | behavioral anomaly | T1036 | 1\.22M | 28\.6% | 138\.50K | High | Medium |
| User Agent | `python\-requests/2\.31` | high volume share; high 429 share; automation user agent | T1498, T1110, T1071\.001 | 920\.00K | 21\.6% | 142\.00K | High | High |
| User Agent | `curl/7\.88\.1` | high volume share; automation user agent | T1498, T1071\.001 | 410\.00K | 9\.60% | 51\.00K | High | Medium |
| Client IP | `203\.0\.113\.55` | new in window | — | 220\.00K | 5\.20% | 36\.00K | Low | Low |
| User Agent | `Go\-http\-client/1\.1` | automation user agent | T1071\.001 | 210\.00K | 4\.90% | 19\.00K | Low | Low |

## Section A — Scope Confirmation

| Measure | Value |
| --- | --- |
| Requests | 4\.25M |
| Bot share | 71\.4% |
| 429 rate | 8\.20% |
| 5xx rate | 1\.10% |
| Edge blocked share | 4\.60% |

Spike flags: Volume up; 429 rate up; Bot share up
### Top targeted hosts

| Host | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| www\.example\.com | 4\.10M | 96\.5% | \+312% |
| api\.example\.com | 110\.00K | 2\.60% | \+14\.0% |
| assets\.example\.com | 32\.00K | 0\.80% | \+2\.00% |
| login\.example\.com | 5\.80K | 0\.10% | \-3\.00% |
| cdn\.example\.com | 2\.20K | 0\.05% | 0\.00% |

### Top targeted path patterns

| Path pattern | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| /login/\* | 2\.90M | 68\.2% | \+530% |
| /api/v1/auth/\* | 720\.00K | 16\.9% | \+410% |
| / | 230\.00K | 5\.40% | \+12\.0% |
| /static/\* | 180\.00K | 4\.20% | \-5\.00% |
| /checkout/\* | 65\.00K | 1\.50% | \-1\.00% |

### Status mix

| Status | Requests | Share |
| --- | --- | --- |
| 200 | 3\.50M | 82\.4% |
| 429 | 348\.50K | 8\.20% |
| 403 | 215\.00K | 5\.10% |
| 401 | 140\.00K | 3\.30% |
| 500 | 46\.50K | 1\.10% |

### Country mix

| Country | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| US | 2\.10M | 49\.4% | \+280% |
| DE | 820\.00K | 19\.3% | \+410% |
| BR | 540\.00K | 12\.7% | \+360% |
| GB | 320\.00K | 7\.50% | \+60\.0% |
| FR | 180\.00K | 4\.20% | \+22\.0% |

### SIEM action mix

| Action | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| allow | 3\.65M | 85\.9% | \+290% |
| rate\_limit | 348\.00K | 8\.20% | \+540% |
| block | 196\.00K | 4\.60% | \+480% |
| challenge | 56\.00K | 1\.30% | \+130% |

### SIEM policy mix

| Policy | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| rate\-limit\-login | 320\.00K | 7\.50% | \+610% |
| block\-credential\-stuff | 175\.00K | 4\.10% | \+520% |
| challenge\-suspect\-ua | 50\.00K | 1\.20% | \+140% |
| allow\-default | 3\.65M | 85\.9% | \+290% |

### SIEM bot-type mix

| Bot type | Requests | Share | Δ vs baseline |
| --- | --- | --- | --- |
| unknown\_bot | 2\.20M | 51\.8% | \+740% |
| browser | 1\.20M | 28\.2% | \+70\.0% |
| verified\_bot | 380\.00K | 8\.90% | \+10\.0% |
| tool | 360\.00K | 8\.50% | \+410% |
| ai\_crawler | 110\.00K | 2\.60% | \+18\.0% |

## Operational Interpretation

Client IP \`203\.0\.113\.10\` is the top flagged target, promoted on high volume share and single\-path concentration against \`/login/submit\`\. User Agent \`python\-requests/2\.31\` also crosses the high\-volume\-share threshold and matches the curated automation pattern\. ASN \`64500\` is flagged via single\-ASN clustering — multiple flagged client IPs share that origin network\.

_From AI assistant._

## Section B — Actors

### Client IP — top 10

| Client IP | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 203\.0\.113\.10 | 540\.00K | 1\.45B | 1 | 92\.00K | 17\.0% | 200 | 0\.04% |
| 198\.51\.100\.42 | 420\.00K | 1\.12B | 1 | 65\.00K | 15\.5% | 80 | 0\.02% |
| 192\.0\.2\.17 | 360\.00K | 980\.00M | 1 | 41\.00K | 11\.4% | 60 | 0\.02% |
| 203\.0\.113\.55 | 220\.00K | 590\.00M | 2 | 36\.00K | 16\.4% | 30 | 0\.01% |
| 198\.51\.100\.7 | 180\.00K | 470\.00M | 3 | 18\.00K | 10\.0% | 25 | 0\.01% |
| 203\.0\.113\.99 | 150\.00K | 410\.00M | 6 | 12\.00K | 8\.00% | 30 | 0\.02% |
| 192\.0\.2\.201 | 120\.00K | 320\.00M | 4 | 8\.00K | 6\.70% | 18 | 0\.02% |
| 203\.0\.113\.4 | 95\.00K | 250\.00M | 7 | 7\.80K | 8\.20% | 22 | 0\.02% |
| 198\.51\.100\.23 | 78\.00K | 210\.00M | 3 | 6\.50K | 8\.30% | 10 | 0\.01% |
| 192\.0\.2\.66 | 64\.00K | 170\.00M | 5 | 4\.40K | 6\.90% | 14 | 0\.02% |

### Client ASN — top 5

| Client ASN | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 64500 | 1\.85M | 4\.90B | 22 | 195\.00K | 10\.5% | 950 | 0\.05% |
| 64600 | 920\.00K | 2\.45B | 18 | 78\.00K | 8\.50% | 410 | 0\.04% |
| 64700 | 540\.00K | 1\.39B | 12 | 38\.00K | 7\.00% | 240 | 0\.04% |
| 64800 | 310\.00K | 840\.00M | 9 | 21\.00K | 6\.80% | 90 | 0\.03% |
| 64900 | 215\.00K | 590\.00M | 14 | 11\.00K | 5\.10% | 50 | 0\.02% |

### Request Path — top 5

| Request Path | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| /login/submit | 1\.45M | 3\.70B | 1 | 220\.00K | 15\.2% | 600 | 0\.04% |
| /api/v1/auth/login | 690\.00K | 1\.75B | 1 | 92\.00K | 13\.3% | 240 | 0\.03% |
| /login | 260\.00K | 670\.00M | 1 | 14\.00K | 5\.40% | 80 | 0\.03% |
| /api/v1/auth/refresh | 30\.00K | 76\.00M | 1 | 1\.20K | 4\.00% | 15 | 0\.05% |
| / | 230\.00K | 590\.00M | 1 | 800 | 0\.35% | 12 | 0\.01% |

### User Agent — top 5

| User Agent | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Mozilla/5\.0 \(Linux; Android 13\) AppleWebKit/537\.36 | 1\.28M | 3\.30B | 14 | 168\.00K | 13\.1% | 450 | 0\.04% |
| python\-requests/2\.31 | 920\.00K | 2\.45B | 8 | 142\.00K | 15\.4% | 380 | 0\.04% |
| curl/7\.88\.1 | 410\.00K | 1\.08B | 6 | 51\.00K | 12\.4% | 130 | 0\.03% |
| Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) Chrome/124\.0 | 380\.00K | 990\.00M | 18 | 9\.20K | 2\.40% | 110 | 0\.03% |
| Go\-http\-client/1\.1 | 210\.00K | 540\.00M | 5 | 19\.00K | 9\.00% | 60 | 0\.03% |

### Country — top 5

| Country | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| US | 2\.10M | 5\.40B | 28 | 178\.00K | 8\.50% | 480 | 0\.02% |
| DE | 820\.00K | 2\.15B | 21 | 78\.00K | 9\.50% | 220 | 0\.03% |
| BR | 540\.00K | 1\.39B | 17 | 56\.00K | 10\.4% | 180 | 0\.03% |
| GB | 320\.00K | 840\.00M | 19 | 22\.00K | 6\.90% | 110 | 0\.03% |
| FR | 180\.00K | 470\.00M | 16 | 9\.00K | 5\.00% | 60 | 0\.03% |

### Traffic cohort — top 5

| Traffic cohort | Requests | Bytes | Distinct paths | 429s | 429 share | 5xx | 5xx share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Bot | 2\.20M | 5\.70B | 32 | 195\.00K | 8\.90% | 950 | 0\.04% |
| Browser | 1\.22M | 3\.15B | 41 | 138\.50K | 11\.4% | 28\.00K | 2\.30% |
| Unknown | 364\.00K | 940\.00M | 28 | 7\.30K | 2\.00% | 1\.00K | 0\.27% |
| Tool | 360\.00K | 930\.00M | 18 | 5\.60K | 1\.60% | 250 | 0\.07% |
| AI | 110\.00K | 280\.00M | 14 | 2\.10K | 1\.90% | 90 | 0\.08% |

## Next Steps

\- Pivot in the linked dashboard to \`/login/\*\` and confirm the 429 trajectory against the trailing window\.
\- Enrich Client IP \`203\.0\.113\.10\`, \`198\.51\.100\.42\`, and \`192\.0\.2\.17\` in the SOC queue; all three cluster on ASN \`64500\`\.
\- Treat User Agent \`python\-requests/2\.31\` and \`curl/7\.88\.1\` as candidate automation patterns when triaging the broader event\.

## Continue investigating

[Open the linked Grafana dashboard](https://grafana.example.com/d/bot-incident?var-cluster=demo&var-host=www.example.com&from=2026-05-13T14:00:00Z&to=2026-05-13T17:00:00Z) — pre-scoped to this window and scope filters for further drilldown.

## Indicators of Compromise

The same flagged targets, restructured as a portable indicator feed (schema `bot\_incident\_iocs\.v1`, 9 indicators). Each entry carries severity, confidence, the analyst window as first/last observed timestamps, ATT&CK techniques consistent with the signal, and the supporting evidence numbers.

```json
{
  "schema": "bot_incident_iocs.v1",
  "scope": {
    "cluster": "demo",
    "host": "www.example.com",
    "asn": null,
    "path_pattern": null,
    "window_start": "2026-05-13T14:00:00Z",
    "window_end": "2026-05-13T17:00:00Z",
    "baseline_start": "2026-05-13T11:00:00Z",
    "baseline_end": "2026-05-13T14:00:00Z"
  },
  "source_artifact": "bot_incident_action_targets.v1",
  "heuristic_version": "v2",
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.10",
      "kind": "actor",
      "severity": "critical",
      "confidence": "high",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "high_rate_429_share",
        "single_path_concentration",
        "single_asn_cluster"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1110",
          "name": "Brute Force",
          "tactic": "Credential Access"
        },
        {
          "id": "T1110.004",
          "name": "Credential Stuffing",
          "tactic": "Credential Access"
        },
        {
          "id": "T1583.003",
          "name": "Acquire Infrastructure: Virtual Private Server",
          "tactic": "Resource Development"
        }
      ],
      "supporting": {
        "requests": 540000,
        "share_pct": 12.7,
        "req_429": 92000,
        "req_429_share_pct": 26.4,
        "distinct_paths": 1
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "ip",
      "value": "198.51.100.42",
      "kind": "actor",
      "severity": "critical",
      "confidence": "high",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "high_rate_429_share",
        "single_path_concentration",
        "single_asn_cluster"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1110",
          "name": "Brute Force",
          "tactic": "Credential Access"
        },
        {
          "id": "T1110.004",
          "name": "Credential Stuffing",
          "tactic": "Credential Access"
        },
        {
          "id": "T1583.003",
          "name": "Acquire Infrastructure: Virtual Private Server",
          "tactic": "Resource Development"
        }
      ],
      "supporting": {
        "requests": 420000,
        "share_pct": 9.9,
        "req_429": 65000,
        "req_429_share_pct": 18.7,
        "distinct_paths": 1
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "ip",
      "value": "192.0.2.17",
      "kind": "actor",
      "severity": "critical",
      "confidence": "high",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "high_rate_429_share",
        "single_path_concentration",
        "single_asn_cluster"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1110",
          "name": "Brute Force",
          "tactic": "Credential Access"
        },
        {
          "id": "T1110.004",
          "name": "Credential Stuffing",
          "tactic": "Credential Access"
        },
        {
          "id": "T1583.003",
          "name": "Acquire Infrastructure: Virtual Private Server",
          "tactic": "Resource Development"
        }
      ],
      "supporting": {
        "requests": 360000,
        "share_pct": 8.5,
        "req_429": 41000,
        "req_429_share_pct": 11.8,
        "distinct_paths": 1
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "asn",
      "value": "64500",
      "kind": "actor",
      "severity": "high",
      "confidence": "medium",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "high_rate_429_share"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1110",
          "name": "Brute Force",
          "tactic": "Credential Access"
        }
      ],
      "supporting": {
        "requests": 1850000,
        "share_pct": 43.5,
        "req_429": 195000,
        "req_429_share_pct": 56.0,
        "distinct_paths": 22
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "user_agent",
      "value": "python-requests/2.31",
      "kind": "actor",
      "severity": "high",
      "confidence": "high",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "high_rate_429_share",
        "automation_user_agent"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1110",
          "name": "Brute Force",
          "tactic": "Credential Access"
        },
        {
          "id": "T1071.001",
          "name": "Application Layer Protocol: Web Protocols",
          "tactic": "Command and Control"
        }
      ],
      "supporting": {
        "requests": 920000,
        "share_pct": 21.6,
        "req_429": 142000,
        "req_429_share_pct": 40.7,
        "distinct_paths": 8
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "user_agent",
      "value": "curl/7.88.1",
      "kind": "actor",
      "severity": "high",
      "confidence": "medium",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "high_volume_share",
        "automation_user_agent"
      ],
      "attack_techniques": [
        {
          "id": "T1498",
          "name": "Network Denial of Service",
          "tactic": "Impact"
        },
        {
          "id": "T1071.001",
          "name": "Application Layer Protocol: Web Protocols",
          "tactic": "Command and Control"
        }
      ],
      "supporting": {
        "requests": 410000,
        "share_pct": 9.6,
        "req_429": 51000,
        "req_429_share_pct": 14.6,
        "distinct_paths": 6
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "user_agent",
      "value": "Go-http-client/1.1",
      "kind": "actor",
      "severity": "low",
      "confidence": "low",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "automation_user_agent"
      ],
      "attack_techniques": [
        {
          "id": "T1071.001",
          "name": "Application Layer Protocol: Web Protocols",
          "tactic": "Command and Control"
        }
      ],
      "supporting": {
        "requests": 210000,
        "share_pct": 4.9,
        "req_429": 19000,
        "req_429_share_pct": 5.4,
        "distinct_paths": 5
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "ip",
      "value": "203.0.113.55",
      "kind": "actor",
      "severity": "low",
      "confidence": "low",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "new_in_window"
      ],
      "attack_techniques": [],
      "supporting": {
        "requests": 220000,
        "share_pct": 5.2,
        "req_429": 36000,
        "req_429_share_pct": 10.3,
        "distinct_paths": 2
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    },
    {
      "type": "cohort",
      "value": "Browser",
      "kind": "actor",
      "severity": "high",
      "confidence": "medium",
      "first_observed": "2026-05-13T14:00:00Z",
      "last_observed": "2026-05-13T17:00:00Z",
      "reason_flags": [
        "anomaly"
      ],
      "attack_techniques": [
        {
          "id": "T1036",
          "name": "Masquerading",
          "tactic": "Defense Evasion"
        }
      ],
      "supporting": {
        "requests": 1216000,
        "share_pct": 28.6,
        "req_429": 138500,
        "req_429_share_pct": 39.7,
        "distinct_paths": 41,
        "baseline_error_rate_pct": 0.52,
        "current_error_rate_pct": 13.7,
        "error_rate_ratio": 26.3
      },
      "suggested_action_hint": "review",
      "action_class": "watch"
    }
  ]
}
```

## Method

Incident report for Demo · Akamai, scope-confirmed against a trailing equal-length baseline.

- Schema: `bot_incident_scope.v1`
- Top-N per actor field: 10
- Constraints: Mechanical features only; No causal claim; No malicious intent claim

Generated 2026-05-17 16:09 UTC