# bot-insights — Incident Analysis

## Contents

- [CLI](#cli)
- [Reading the Impact section](#reading-the-impact-section)
- [Reading Suspicious Targets](#reading-suspicious-targets)
- [IOC export — SIEM-ingestion-ready appendix](#ioc-export--siem-ingestion-ready-appendix)
- [MITRE ATT&CK mapping — "consistent with," not "evidence of"](#mitre-attck-mapping--consistent-with-not-evidence-of)
- [Reading Section A — scope confirmation](#reading-section-a--scope-confirmation)
- [Reading Section B — actors](#reading-section-b--actors)
- [Dashboard handoff](#dashboard-handoff)
- [Deployment-availability behavior](#deployment-availability-behavior)
- [Deferred (Phase 3)](#deferred-phase-3)

The `incident_report` flow sits between a top-N panel and a full RCA: it
confirms an analyst-supplied incident window from the cluster's summary
tables, drills into the raw access log for actor-level detail, and
points the analyst at a Grafana dashboard for further exploration.

Use this report when:

- The user supplies a window and a scope (host, ASN, path pattern) and
  asks "what was that?" or "who hit it?"
- A scorecard or executive brief flagged an entity and the analyst
  wants per-IP / per-UA detail behind it.
- A customer demo needs presentable evidence of a window-scoped
  incident without inventing a root-cause story.

Do **not** use this report for:

- Auto-detecting incidents without an analyst-supplied window.
- Cross-incident comparison.
- Claims about malicious intent or causality — the report is contractually
  prose-only on those surfaces, and the LLM contract forbids them.

## CLI

```bash
uv run python skills/bot-insights/scripts/bot_insights_report.py \
  --report incident_report \
  --cluster <name> --database akamai \
  --start <iso> --end <iso> \
  [--host <fqdn>] [--asn <num>] [--path-pattern <bucket>] \
  [--fields client_ip,asn,request_path,user_agent,country,status_code,request_method] \
  [--top-n 10] \
  --output <path>
```

The orchestrator:

1. Resolves cluster credentials via the standard data firewall path.
2. Picks granularity from the window length (`<3h → minute`, `<48h → hour`,
   else `day`).
3. Introspects `akamai.logs` and the SIEM policy summary table via
   `system.columns` queries to set `raw_drilldown_available` and
   `siem_available`.
4. Validates `--fields` mechanically against the column list. Unknown
   names fail closed before any query against `akamai.logs` runs.
5. Runs a phase-1 capture for the window-confirmation + dimension mixes,
   followed by per-field phase-2 captures when raw drilldown is
   available.
6. Assembles `bot_incident_scope.v1`, `bot_incident_actors.v1`, and
   `bot_incident_action_targets.v1`, builds the evidence packet, and
   either renders the report or emits the packet (`--mode evidence`).
   When raw drilldown is available, the orchestrator also runs a
   baseline-window actor query per resolved field (to populate the
   `new_in_window` heuristic), so the phase-2 query count is doubled
   vs v1.

When credentials don't resolve, capture emits a
`bot_hydrolix_mcp_query_request.v1` handoff packet and exits `42` —
identical to every other predefined report's MCP path.

## Reading the Impact section

Impact sits at the top of the report. It exists so a reader who reads
only this block already knows what was hit. Five tiles:

- **Requests** — absolute count served in the window, with the top
  affected host's Δ vs baseline as the subscript.
- **429s served** — absolute count, with 429-rate share of the window.
- **5xx served** — same shape as 429s.
- **SIEM blocks** — absolute count and share; renders `—` with the
  subscript "SIEM not available" when the cluster has no SIEM policy
  summary table.
- **Hosts affected** — count of distinct request hosts with at least
  one request in the window.

A single prose sentence beneath the tiles names the top affected host
and path pattern (`top_targeted_hosts[0]` + `top_targeted_path_patterns[0]`)
with absolute numbers and Δ vs baseline. The sentence is mechanical,
not LLM-authored.

(Peak requests / minute is deferred to Phase 3.)

## Reading Suspicious Targets

The Suspicious Targets table names every actor that crossed the
heuristic ladder. Empty list → an explicit banner explains why, so an
empty section never looks broken.

The orchestrator's heuristic ladder operates on actor rows from
`bot_incident_actors.v1`. Constants live at module scope in
`bot_insights_report.py` so calibration is a one-line change.

**Field-type taxonomy.** Fields fall into two buckets:

- **Individual entities** (`client_ip`, `asn`, `user_agent`, `request_path`)
  enumerate many distinct values, most of which are a small share of the
  window. Share-based primitives are meaningful here — a 5% share is an
  outlier.
- **Aggregate fields** (`trafficCohort`, `country`) enumerate a small
  fixed set of values, most of which are large shares by construction.
  Share-based primitives on aggregates would fire on every major value
  and produce noise. Only baseline-relative primitives (`anomaly`,
  `new_in_window`) apply.

This split keeps the Suspicious Targets table actionable: a row with
`severity: high` on an aggregate field means *behavioral departure
from baseline*, not "this aggregate happens to be large."

**Primitives:**

| Flag | Applies to | Fires when | ATT&CK (consistent with) |
|---|---|---|---|
| `high_volume_share` | individual entities only | `requests / total_current ≥ 5%` | T1498 Network Denial of Service |
| `high_rate_429_share` | individual entities only | `req_429 / total_429 ≥ 10%` AND `total_429 ≥ 100` | T1110 Brute Force |
| `single_path_concentration` | individual entities only | `distinct_paths == 1` AND `requests ≥ 1000` | T1110.004 Credential Stuffing |
| `automation_user_agent` | `user_agent` only | UA matches `curl\|python-requests\|Go-http-client\|wget\|libwww\|httpx\|aiohttp` | T1071.001 Application Layer Protocol: Web Protocols |
| `single_asn_cluster` | client_ip only (cross-row) | ≥ 3 client_ip rows are flagged (re-emitted on each flagged client_ip) | T1583.003 Acquire Infrastructure: VPS |
| `new_in_window` | all fields | actor has rows in current-window phase-2 query but zero in baseline-window phase-2 query for the same field | *(no technique — novelty isn't a technique)* |
| `anomaly` | all fields | actor's current-window error rate `(req_429+req_5xx)/requests` is ≥ 3× its own baseline error rate, AND current rate ≥ 5%, AND requests ≥ 1000 | T1036 Masquerading |

### IOC export — SIEM-ingestion-ready appendix

Every rendered report ends with an "Indicators of Compromise (IOCs)"
appendix when at least one target was flagged. The appendix is a
projection of the Suspicious Targets table into a SOC-tooling-ready
format, schema `bot_incident_iocs.v1`:

```json
{
  "schema": "bot_incident_iocs.v1",
  "scope": {
    "cluster": "...",
    "host": "...",
    "window_start": "...",
    "window_end": "...",
    "baseline_start": "...",
    "baseline_end": "..."
  },
  "source_artifact": "bot_incident_action_targets.v1",
  "heuristic_version": "v2",
  "indicators": [
    {
      "type": "ip",
      "value": "203.0.113.10",
      "severity": "critical",
      "confidence": "high",
      "first_observed": "<window_start>",
      "last_observed": "<window_end>",
      "reason_flags": [...],
      "attack_techniques": [{"id": "T1110.004", "name": "...", "tactic": "..."}],
      "supporting": { "requests": N, "share_pct": P, "req_429": M, ... },
      "suggested_action_hint": "review"
    }
  ]
}
```

`type` uses SOC vocabulary (`ip`, `asn`, `user_agent`, `url_path`,
`country`, `cohort`) rather than the report-internal `target_type`
values. The mapping lives in `contexts/incident_report.IOC_TYPE_MAP`.

The IOC export is *additive* — the underlying data is the same as
`bot_incident_action_targets.v1`. The IOC view is the read model
SOC automation consumes; the action-targets artifact remains the
canonical source.

### MITRE ATT&CK mapping — "consistent with," not "evidence of"

Each emitted target carries the union of ATT&CK techniques mapped from
its fired primitives (deduplicated, order preserved). The framing is
deliberately *"techniques consistent with this signal"* rather than
*"techniques used by this actor"* — a single primitive is rarely
conclusive, and the report's LLM contract forbids causal claims.

The mapping is mechanical: changing the technique attached to a
primitive is a one-line edit in
`_PRIMITIVE_ATTACK_TECHNIQUES`. The technique IDs ship in the artifact
as `attack_techniques: [{id, name, tactic}, ...]` on each target row,
ready for SIEM ingestion / downstream WAF-MCP correlation.

### Per-target severity mapping (4-tier, IOC contract)

Per-target severity stays four-tier and is the field downstream SIEM /
SOC tooling consumes via the `bot_incident_iocs.v1` export. The four
tiers — Critical / High / Medium / Low — match the convention used by
AWS Security Hub, GitHub Advanced Security, and GCP Security Command
Center. **Do not promote this field to 5 tiers without coordinating
with downstream consumers**; the editorial verdict ladder below
introduces an `elevated` tier at the *whole-incident* level only, and
intentionally does not change the per-indicator contract.

The tier calculation uses an *effective flag count* — `anomaly`
counts as 2 because it carries baseline corroboration the share-based
primitives don't.

- `severity: critical` — effective count ≥ 3 AND at least one
  *quantitative* flag (`high_volume_share` or `high_rate_429_share`)
  AND at least one *concentration* flag (`single_path_concentration`
  or `single_asn_cluster`). The intent is: the actor is concentrated
  in both *amount* and *shape*, with corroborating evidence.
- `severity: high` — effective count ≥ 2, but not meeting the
  critical rule above. (Notably: `anomaly` alone reaches this tier
  because it counts as 2.)
- `severity: medium` — 1 quantitative flag alone
  (`high_volume_share` or `high_rate_429_share`).
- `severity: low` — 1 flag (any other single flag — an isolated
  automation-UA match, `new_in_window` alone, etc.).
- 0 flags → row is not emitted.

### Whole-incident verdict (5-tier, editorial ladder)

The editorial brief's verdict pill + severity ladder uses a separate
5-tier vocabulary. The new step — `elevated` — sits between `medium`
and `high`, so reports where critical-tier targets exist but the
corroborating spike-flag / raw-drilldown signal is partial can read
the verdict honestly instead of being forced to choose between an
understated `medium` and an overstated `high`.

The verdict tiers (computed by
`contexts/incident_report._deterministic_summary`) are:

- `critical` — at least one `severity: critical` target AND
  `volume_up` fired AND raw drilldown available.
- `high` — at least one `severity: critical` or `severity: high`
  target AND one of `volume_up` / `rate_429_up` fired AND raw
  drilldown available.
- `elevated` — at least one `severity: critical` or `severity: high`
  target exists, but the strict `high` rule did not fire (e.g. the
  required spike flag did not fire, or raw drilldown is unavailable
  so target naming is partial).
- `medium` — any spike flag fired OR any flagged target.
- `low` — none of the above.

**Cross-contract guarantee:** the 4-tier per-target IOC `severity`
field and the 5-tier whole-incident verdict are independent. A SIEM
that ingests `bot_incident_iocs.v1` will never see an `elevated`
indicator severity. The editorial verdict pill and severity ladder
are the only surfaces where the 5-tier vocabulary appears.

Confidence is independent of severity tier and reflects evidence
*quality*, not urgency:

- `confidence: high` — multi-flag AND the value appears in ≥ 2
  separate per-field rankings (cross-field corroboration).
- `confidence: medium` — multi-flag, single-ranking appearance.
- `confidence: low` — single flag.

`suggested_action_hint` is **always `"review"`** in v2. The field is
present so a downstream WAF / bot-manager MCP tool can switch on it
later; calibrating it (and other thresholds) against real incidents
is a Phase-3 task. The LLM contract forbids the interpretation step
from naming a specific mitigation action — the LLM describes evidence,
not enforcement.

## Reading Section A — scope confirmation

Section A reports what changed in the analyst's window:

- **Window-confirmation tiles**: requests, bot share, 429 rate, 5xx
  rate, SIEM blocked share (when SIEM is present). Each carries a
  spike flag when its delta vs the trailing equal-length baseline
  crosses `+25%`.
- **Top targeted hosts**: ranked by current-window requests; each row
  carries share-of-fleet and Δ vs baseline.
- **Top targeted path patterns**: same shape, computed against the
  `requestPathPattern` bucket from the summary table.
- **Status mix**: current-window status code distribution.
- **Country mix**: current-window country distribution with baseline
  delta.
- **SIEM action / policy / bot-type mixes**: present only when
  `siem_available` is true. Each is ranked by current-window count
  with a baseline delta.

Section A always renders, even when the raw access log is unavailable.

## Reading Section B — actors

Section B renders one ranked table per `--fields` entry. Default fields
are `client_ip`, `asn`, `request_path`, `user_agent`, `country`,
`status_code`, and `request_method`. Each row reports requests, bytes,
distinct paths touched, 429s and 5xx (raw + share of the actor's own
traffic).

When the cluster has no `akamai.logs` table, Section B renders a
single banner explaining the limitation — Section A still applies.

## Dashboard handoff

The orchestrator reads optional Grafana link settings from the cluster's env
file (`~/.config/hydrolix/clusters/<cluster>.env`) or process env.
`BI_INCIDENT_DASHBOARD_URL` is the highest-precedence full URL template
override and may carry `{start}`, `{end}`, `{host}`, `{asn}`, and
`{path_pattern}` placeholders. Deployments that want to keep host and path
separate can instead provide both `BI_INCIDENT_GRAFANA_HOSTNAME` and
`BI_INCIDENT_DASHBOARD_PATH`, or pass `--grafana-hostname` and
`--grafana-dashboard-path`. Structured mode appends Grafana `from` / `to`
params plus repeated `var-filter` params for the active `reqHost`, `asn`, and
`requestPathPattern` scopes.

Capture writes the resolved URL into the scope artifact. When neither a full
template nor a complete hostname/path pair is configured, the renderer omits
the handoff block — it never invents a URL or assumes a canonical dashboard
path.

## Deployment-availability behavior

- **No `akamai.logs`** — `raw_drilldown_available: false`, Section B
  banner only, Section A still populated, `limitations` records the
  reason.
- **No SIEM policy summary** — `siem_available: false`, SIEM mix
  tables omitted from Section A, `limitations` records the reason.
- **`--fields` contains an unknown name** — capture fails closed
  with a clear stderr message before any query against `akamai.logs`
  runs.

## Deferred (Phase 3)

Captured here so they're visible but explicitly out of scope today:

- Curated extraction-expression registry for raw-log fields that
  aren't already columns (header value pulls, query-string key
  parsing, TLS field extraction, regex UA family).
- Auto-detection of incidents from a broader window (no analyst-supplied
  bounds).
- Cross-incident comparison ("does this look like the one two weeks
  ago?").
- Non-`akamai.logs` raw surfaces for non-TrafficPeak clusters.
- Heuristic calibration: tune the ladder constants and
  `suggested_action_hint` against real incident samples; promote
  `review` to stronger hints (`rate_limit`, `block`) only when the
  false-positive line is known.
- Peak requests / minute tile (one-shot bucketed query).
- CIDR collapse on action-target rows for downstream WAF tooling.
- Akamai bot-manager / WAF MCP integration consuming
  `bot_incident_action_targets.v1`.
