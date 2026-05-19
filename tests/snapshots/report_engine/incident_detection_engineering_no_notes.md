# www.example.com — Detection Engineering Review

**Window:** 2026-05-13T14:00:00Z -> 2026-05-13T17:00:00Z UTC

## Mechanical Rules Fired

- high volume share: 6 targets
- high 429 rate: 5 targets
- automation user agent: 3 targets
- single-ASN cluster: 3 targets
- single-path concentration: 3 targets
- behavioral anomaly: 1 targets
- new in window: 1 targets

## Fields Driving Confidence

### Client IP
- `203.0.113.10`: 540.00K requests, 17.0% 429 rate within row traffic, 0.04% 5xx share
- `198.51.100.42`: 420.00K requests, 15.5% 429 rate within row traffic, 0.02% 5xx share
- `192.0.2.17`: 360.00K requests, 11.4% 429 rate within row traffic, 0.02% 5xx share
- `203.0.113.55`: 220.00K requests, 16.4% 429 rate within row traffic, 0.01% 5xx share
- `198.51.100.7`: 180.00K requests, 10.0% 429 rate within row traffic, 0.01% 5xx share
### Client ASN
- `64500`: 1.85M requests, 10.5% 429 rate within row traffic, 0.05% 5xx share
- `64600`: 920.00K requests, 8.50% 429 rate within row traffic, 0.04% 5xx share
- `64700`: 540.00K requests, 7.00% 429 rate within row traffic, 0.04% 5xx share
- `64800`: 310.00K requests, 6.80% 429 rate within row traffic, 0.03% 5xx share
- `64900`: 215.00K requests, 5.10% 429 rate within row traffic, 0.02% 5xx share
### Request Path
- `/login/submit`: 1.45M requests, 15.2% 429 rate within row traffic, 0.04% 5xx share
- `/api/v1/auth/login`: 690.00K requests, 13.3% 429 rate within row traffic, 0.03% 5xx share
- `/login`: 260.00K requests, 5.40% 429 rate within row traffic, 0.03% 5xx share
- `/api/v1/auth/refresh`: 30.00K requests, 4.00% 429 rate within row traffic, 0.05% 5xx share
- `/`: 230.00K requests, 0.35% 429 rate within row traffic, 0.01% 5xx share
### User Agent
- `Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36`: 1.28M requests, 13.1% 429 rate within row traffic, 0.04% 5xx share
- `python-requests/2.31`: 920.00K requests, 15.4% 429 rate within row traffic, 0.04% 5xx share
- `curl/7.88.1`: 410.00K requests, 12.4% 429 rate within row traffic, 0.03% 5xx share
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0`: 380.00K requests, 2.40% 429 rate within row traffic, 0.03% 5xx share
- `Go-http-client/1.1`: 210.00K requests, 9.00% 429 rate within row traffic, 0.03% 5xx share
### Country
- `US`: 2.10M requests, 8.50% 429 rate within row traffic, 0.02% 5xx share
- `DE`: 820.00K requests, 9.50% 429 rate within row traffic, 0.03% 5xx share
- `BR`: 540.00K requests, 10.4% 429 rate within row traffic, 0.03% 5xx share
- `GB`: 320.00K requests, 6.90% 429 rate within row traffic, 0.03% 5xx share
- `FR`: 180.00K requests, 5.00% 429 rate within row traffic, 0.03% 5xx share
### Traffic cohort
- `Bot`: 2.20M requests, 8.90% 429 rate within row traffic, 0.04% 5xx share
- `Browser`: 1.22M requests, 11.4% 429 rate within row traffic, 2.30% 5xx share
- `Unknown`: 364.00K requests, 2.00% 429 rate within row traffic, 0.27% 5xx share
- `Tool`: 360.00K requests, 1.60% 429 rate within row traffic, 0.07% 5xx share
- `AI`: 110.00K requests, 1.90% 429 rate within row traffic, 0.08% 5xx share

## Calibration Calls

high volume share dominated detector firing; 7 distinct rules fired this window.
- **Keep:** `high volume share` — fired 6 times this window without producing pad findings
- **Watch:** `behavioral anomaly` — fired on a single target; insufficient evidence to tune

## Missing Coverage

- Edge action mix was not present in the incident artifact.
- Deny-rule mix was not present in the incident artifact.

## Follow-Up Instrumentation

- Emit edge action mix for future incident action review.
- Emit deny-rule mix to connect detector output to policy controls.
