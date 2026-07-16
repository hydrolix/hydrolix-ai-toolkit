# Live query-surface validation (bot-insights)

A repeatable suite that proves the bot-insights skill's SQL claims hold against a
**real** Hydrolix deployment. It exists because the skill's reference docs and
producer scripts assert a specific physical schema and query idiom for the
`bi_summary_*` / `bi_siem_policy_summary_*` summary tables; this suite executes
those claims so drift is caught before it ships.

## What it checks

`validate_live.py` runs five families of checks (246 checks against the
`demo.trafficpeak.live` `akamai` project at last run, all passing):

| Family | What it proves |
|--------|----------------|
| **schema**   | Every documented column exists (probed with a real `SELECT`, so Alias/Summary columns like `cnt_all`/`reqTimeSec` resolve); every phantom column the docs say is absent (`cnt_cache_miss`, `p95_origin_ttfb`, `bot_class`, `requestPathPattern`, ...) is in fact absent. |
| **doc-sql**  | Every ```` ```sql ```` block in the skill markdown that targets a deployed summary table is extracted, its placeholders resolved to real values, and executed. `bot_agg_*` / `bot_detection` blocks (documented as not-deployed) are skipped. |
| **negative** | Things the docs say are impossible actually fail: `sum(cnt_all)` -> `ILLEGAL_AGGREGATION`; selecting `cnt_cache_miss` / `p95_origin_ttfb` / `bot_class` / `requestPathPattern` / `is_bot_traffic`. |
| **prose**    | Factual claims in the prose are executable: `statusCode` numeric, `cacheStatus` boolean, `trafficCohort in {Human,Bot,AI}`, `aiSource` empty when `aiCategory` empty, `resourceCategory` bucket set, good-bot = `trafficCohort='Bot'`, SIEM control columns resolve. |
| **producer** | Every deployed-table SQL generator in `bot_insights.producers.sql` (executive posture, control review, all scorecard entity types, summary-columns introspection) is called with real parameters and its emitted SQL is executed. |

## Connection (credential-safe)

Reuses the skill's own cluster-env convention. No credentials live in this repo.
It reads `~/.config/hydrolix/clusters/<cluster>.env` for
`HYDROLIX_HOST`/`HDX_HOSTNAME` + `HYDROLIX_TOKEN`/`HDX_TOKEN`. Tokens stored as
1Password `op://` references are resolved at runtime via the `op` CLI (so you
must be signed in to 1Password for those clusters). If no usable cluster env is
found, the whole suite **skips** - offline CI stays green; live validation is
opt-in.

## Running

Standalone (prints a PASS/FAIL/SKIP table, non-zero exit on any FAIL):

```bash
python3 tests/live/validate_live.py                 # default: demo.trafficpeak.live / akamai
python3 tests/live/validate_live.py --quick         # hour-grain schema probes only (faster)
python3 tests/live/validate_live.py --json report.json
BOT_INSIGHTS_LIVE_CLUSTER=<cluster> BOT_INSIGHTS_LIVE_DB=<db> python3 tests/live/validate_live.py
```

Under pytest (skips without a cluster; `uv run` gives producer coverage by
making the `bot_insights` package importable):

```bash
uv run pytest tests/live/test_live_query_surface.py -v
BOT_INSIGHTS_LIVE_QUICK=1 uv run pytest tests/live/test_live_query_surface.py -v
```

The full run issues ~250 sequential queries (a `SELECT` probe per documented
column across every grain), so it takes a couple of minutes; `--quick` /
`BOT_INSIGHTS_LIVE_QUICK=1` trims the schema probes to the hour-grain tables.

## Scope

- Covers the **skill's** cluster-facing surface: reference-doc SQL and the
  producer SQL generators. The Grafana dashboards ship in the `cac-tools`
  bundle, not this skill, and would need a separate suite.
- Producer coverage runs against the installable `bot_insights` package, which
  is what the skill's `scripts/` entrypoints re-export at runtime.
