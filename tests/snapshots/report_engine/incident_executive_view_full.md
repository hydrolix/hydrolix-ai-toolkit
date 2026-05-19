# www.example.com — Incident Executive View

**Status:** Active
**Window:** 2026-05-13T14:00:00Z → 2026-05-13T17:00:00Z UTC

## What happened

Coordinated automated traffic concentrated on `/login/*` during a 1-hour window. Three client IPs sharing one ASN drove the spike; the edge filtered the bulk of it but a tail reached origin.

## Measured impact

- **Requests:** 4.25M (+312%)
- **429s served:** 348.50K (8.20% of window)
- **5xx served:** 46.75K (1.10% of window)
- **Edge blocks:** 195.50K (4.60% of window)
- **Hosts affected:** 5 (in window)
- **Top affected host:** `www.example.com` (96.5%, +312% vs baseline)
- **Top path pattern:** `/login/*` — 68.2% of window, +530% vs baseline


## Business / customer impact

Login conversion not measurably affected; no confirmed customer reports.

## Response taken / recommended

Edge block deployed for the top ASN; rate-limit tightened on `/login/submit`.

1. Time-boxed edge control candidate: Client IP `203.0.113.10` — _SOC, now_ · Observed volume: 540.00K (12.7% of window).
2. Enrich the 3 critical target(s) in case management — `203.0.113.10`, `198.51.100.42`, `192.0.2.17` — _Threat Intel, today_
3. Investigate behavioral-anomaly cohort — Traffic cohort `Browser` — _AppSec, this week_
4. Continue investigating in the linked Grafana dashboard (pre-scoped to the incident window) — _IR Lead, now_
5. Schedule retrospective — review SIEM coverage on affected endpoints — _IR Lead, this week_

## Decision needed

Approve a 7-day extension of the ASN block, or roll back at 24 hours?

## Confidence and caveat

High confidence in traffic anomaly and infrastructure concentration; no root-cause or intent attribution.