# www.example.com — Edge Platform Brief

**Window:** 2026-05-13T14:00:00Z -> 2026-05-13T17:00:00Z UTC

## Request Impact

- **Requests:** 4.25M (+312%)
- **429s served:** 348.50K (8.20% of window)
- **5xx served:** 46.75K (1.10% of window)
- **Edge blocks:** 195.50K (4.60% of window)
- **Hosts affected:** 5 (in window)
- **Top path share:** 68.2% (/login/* · +530%)

## 429 / 5xx Shape

- 200: 3.50M (82.4%)
- 429: 348.50K (8.20%)
- 403: 215.00K (5.10%)
- 401: 140.00K (3.30%)
- 500: 46.50K (1.10%)

## Top Hosts And Paths

- Host `www.example.com`: 4.10M (96.5%)
- Host `api.example.com`: 110.00K (2.60%)
- Host `assets.example.com`: 32.00K (0.80%)
- Host `login.example.com`: 5.80K (0.10%)
- Host `cdn.example.com`: 2.20K (0.05%)
- Path `/login/*`: 2.90M (68.2%)
- Path `/api/v1/auth/*`: 720.00K (16.9%)
- Path `/`: 230.00K (5.40%)
- Path `/static/*`: 180.00K (4.20%)
- Path `/checkout/*`: 65.00K (1.50%)

## Policy Assessment

Edge is filtering the bulk of suspicious traffic, but a tail still passes without an action applied. Recommend extending the deny rule that already dominates this window to cover the pass-through cohort, and revisit after 24h.

## Operational Caveats

- Edge action mix was not present in the incident artifact.
- Deny-rule mix was not present in the incident artifact.
