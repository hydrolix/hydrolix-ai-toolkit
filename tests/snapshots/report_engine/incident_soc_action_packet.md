# www.example.com — SOC Action Packet

**Window:** 2026-05-13T14:00:00Z -> 2026-05-13T17:00:00Z UTC

## Verdict

**Critical** · Confidence: High

Assessed with high confidence: this window is consistent with a high-severity targeted incident and warrants escalation.

**Why it fires:**

- spike flags fired (Volume up, 429 rate up, Bot share up)
- 3 target(s) at severity:critical — Client IP `203.0.113.10`, Client IP `198.51.100.42`, Client IP `192.0.2.17`
- 4 target(s) at severity:high — Client ASN `64500`, Traffic cohort `Browser`, User Agent `python-requests/2.31`

**Window shape:** 4,250,000 requests; 429 rate 8.2%; 5xx rate 1.1%; bot share 71.4%; edge-blocked share 4.6%. Spike flags: Volume up, 429 rate up, Bot share up.

**Top affected host:** `www.example.com` (96.5%).

## Suspicious Actors

- `203.0.113.10` (Client IP): Critical, High confidence, 540.00K requests; high volume share, high 429 rate, single-path concentration, single-ASN cluster- `198.51.100.42` (Client IP): Critical, High confidence, 420.00K requests; high volume share, high 429 rate, single-path concentration, single-ASN cluster- `192.0.2.17` (Client IP): Critical, High confidence, 360.00K requests; high volume share, high 429 rate, single-path concentration, single-ASN cluster- `64500` (Client ASN): High, Medium confidence, 1.85M requests; high volume share, high 429 rate- `Browser` (Traffic cohort): High, Medium confidence, 1.22M requests; behavioral anomaly- `python-requests/2.31` (User Agent): High, High confidence, 920.00K requests; high volume share, high 429 rate, automation user agent- `curl/7.88.1` (User Agent): High, Medium confidence, 410.00K requests; high volume share, automation user agent- `203.0.113.55` (Client IP): Low, Low confidence, 220.00K requests; new in window- `Go-http-client/1.1` (User Agent): Low, Low confidence, 210.00K requests; automation user agent
## IOC Handoff

- ip `203.0.113.10`: critical severity, watch action class
- ip `198.51.100.42`: critical severity, watch action class
- ip `192.0.2.17`: critical severity, watch action class
- asn `64500`: high severity, watch action class
- user_agent `python-requests/2.31`: high severity, watch action class
- user_agent `curl/7.88.1`: high severity, watch action class
- user_agent `Go-http-client/1.1`: low severity, watch action class
- ip `203.0.113.55`: low severity, watch action class
- cohort `Browser`: high severity, watch action class

## Edge Actions And Deny Rules

- Edge action mix unavailable in this artifact.
- Deny-rule mix unavailable in this artifact.

## Evidence Caveats

- Edge action mix was not present in the incident artifact.
- Deny-rule mix was not present in the incident artifact.
