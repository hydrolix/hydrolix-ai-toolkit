# Threat Hunt Template Context

This reference describes the data available to Jinja templates when rendering
`report_type: threat_hunt`.

It documents the prepared template context, not the raw producer artifact.
The raw artifact is `bot_threat_hunt.v3`; the renderer adapts it through
`scripts/report_engine/contexts/threat_hunt.py` before templates see it.

## Rendering Flow

1. A wrapper with `schema_version: bot_report_input.v1` and
   `report_type: threat_hunt` supplies one `bot_threat_hunt.v3` artifact.
2. `assemble()` selects that artifact.
3. `prepare()` builds the screen HTML and Markdown context.
4. For print/PDF profile only, `post_prepare()` adds fixed-letter print
   fields and switches rendering to `reports/incident_report_print.html`.

Relevant files:

- `scripts/report_engine/contexts/threat_hunt.py`
- `scripts/report_engine/templates/reports/threat_hunt.html`
- `scripts/report_engine/templates/reports/threat_hunt.md.j2`
- `scripts/report_engine/templates/reports/incident_report_print.html`

## Top-Level Context

These keys are available to the screen HTML and Markdown templates.

| Key | Type | Description |
|---|---:|---|
| `artifact` | object | Original `bot_threat_hunt.v3` artifact for fallback/debug use. Prefer prepared fields for template work. |
| `title` | string | Report title, currently `Threat Hunt`. |
| `report_type` | string | `threat_hunt`. |
| `kicker` | string | Short report family label. |
| `headline` | string | Subject label derived from scope customer, tenant, cluster, or fallback. |
| `dek` | string | One-line report description. |
| `scope` | object | Raw scope object with `cluster`, `database`, `current_window`, `baseline_window`, and analysis metadata. |
| `windows` | object | Convenience object with `current` and `baseline` windows from `scope`. |
| `profile` | string | Render profile. Defaults to `screen`; print/PDF sets `print`. |
| `generated_at` | string | UTC render timestamp. |
| `scorecards` | list | Module scorecard views. |
| `campaigns` | list | Prepared campaign views. |
| `ua_families` | list | Prepared UA-family views. |
| `scraper_cases` | list | Prepared scraper-lead views. |
| `known_traffic` | list | Known crawler/infrastructure rows. |
| `bot_manager_context` | object | Operational Bot Manager context, marked informational. |
| `threat_classification` | object | Aggregate threat classification view. |
| `recommended_actions` | list | Prepared action-card views. |
| `impact_assessment` | object | Rollup, tier, campaign, family, and lead impact views. |
| `deterministic_summary` | object | Severity, confidence, and summary prose generated deterministically. |
| `severity_ladder` | list | Presentation rows for severity/risk display. |
| `analyst_assessment` | object | Screen report analyst-assessment block. |
| `primary_concern` | object | Screen report primary-concern block. |
| `threat_findings` | list | Prepared finding narrative rows. |
| `impact_tiles` | list | Prepared high-level metric tiles. |
| `threat_hunt_ui.impact_rows` | list | Screen HTML `HUNT IMPACT` rows: hits, Hydrolix log ingest, response body, and Akamai-billed bandwidth. |
| `pattern_notes` | list | Renderer-prepared scraper behavior notes. Notes are explanatory support only and require metric thresholds plus corroborating endpoint, timing, UA, fan-out, or campaign evidence. They are not classification evidence or standalone enforcement justification. |
| `threat_hunt_ui.pattern_notes` | list | Same normalized notes prepared for the screen HTML UI. |
| `campaign_readouts` | list | First five `campaigns` rows for screen cards. |
| `ua_family_readouts` | list | First five `ua_families` rows for screen cards. |
| `lead_cards` | list | First eight `scraper_cases` rows for screen cards. |
| `evidence_boundaries` | object | Observed and not-established evidence-boundary lists. |
| `fingerprints` | list | Raw/prepared fingerprint rows from the artifact. |
| `endpoints` | list | Endpoint rollup rows from the artifact. |
| `infrastructure` | object | Infrastructure rollups from the artifact. |
| `classification_gap` | object | Classification availability/gap summary. |
| `limitations` | list | Evidence/data limitations from the artifact. |
| `metric_rows` | list | Baseline movement rows. |
| `countries` | list | Country movement rows from baseline summary. |
| `traffic_cohorts` | list | Traffic cohort rows from baseline summary. |
| `method` | object | Method metadata; includes `schema_version` and interpretation constraints. |
| `confidence` | object | Confidence reason list. |

## Common View Shapes

### `impact_assessment`

`impact_assessment` is the preferred source for impact rendering.

| Field | Type | Description |
|---|---:|---|
| `totals.current.requests` | number | Total requests in the current window. |
| `totals.current.bytes` | number | Legacy byte total. Do not use for primary impact labels when explicit lanes are present. |
| `totals.current.hydrolix_log_ingest_bytes` | number or null | Total customer log volume ingested by Hydrolix. Available only when configured explicitly at export time. |
| `totals.current.response_body_bytes` | number | Total response-body bytes from raw `bytes`. |
| `totals.current.akamai_billed_bytes` | number | Total CDN billed bandwidth from raw `totalBytes`. |
| `totals.baseline.requests` | number | Total requests in the baseline window. |
| `totals.baseline.bytes` | number | Legacy baseline byte total. Do not relabel as an explicit byte lane. |
| `totals.baseline.hydrolix_log_ingest_bytes` | number or null | Baseline Hydrolix log-ingest bytes when explicitly configured. |
| `totals.baseline.response_body_bytes` | number | Baseline response-body bytes. |
| `totals.baseline.akamai_billed_bytes` | number | Baseline CDN billed bandwidth bytes. |
| `hunt` | object | Deduplicated total finding impact. |
| `tiers` | object | Impact grouped by action tier. |
| `cost_config` | object or null | Present only when cost estimates are configured. |

Impact rows such as `impact_assessment.hunt`, `campaign.impact_assessment`,
`family.impact_assessment`, and `case.impact_assessment` include raw numeric
fields plus display strings:

| Field | Type | Description |
|---|---:|---|
| `requests` | number | Current-window requests. |
| `baseline_requests` | number | Baseline-window requests. |
| `request_share` | number | Share of total current-window traffic, as a fraction. |
| `baseline_request_share` | number | Share of total baseline traffic, as a fraction. |
| `bytes` | number | Legacy compatibility byte field. Do not use as a primary impact label when explicit lanes are present. |
| `baseline_bytes` | number | Legacy compatibility baseline byte field. |
| `byte_share` | number | Legacy compatibility byte share. |
| `baseline_byte_share` | number | Legacy compatibility baseline byte share. |
| `hydrolix_log_ingest_bytes` | number or null | Hydrolix log-ingest bytes for this scope. Null means unavailable; do not infer it. |
| `hydrolix_log_ingest_byte_share` | number or null | Share of customer log volume, as a fraction. |
| `response_body_bytes` | number or null | Response-body bytes for this scope. |
| `response_body_byte_share` | number or null | Share of response bytes, as a fraction. |
| `akamai_billed_bytes` | number or null | Akamai-billed CDN bandwidth bytes for this scope. |
| `akamai_billed_byte_share` | number or null | Share of CDN billed bandwidth, as a fraction. |
| `trend_severity` | string | Trend bucket such as `accelerating`, `stable`, or `shrinking`. |
| `share_severity` | string | Current share bucket. |
| `share_direction` | string | Direction bucket such as `growing_share` or `shrinking_share`. |
| `requests_display` | string | Formatted request count. |
| `baseline_requests_display` | string | Formatted baseline request count. |
| `request_share_display` | string | Formatted current request share. |
| `baseline_request_share_display` | string | Formatted baseline request share. |
| `bytes_display` | string | Formatted byte count. |
| `baseline_bytes_display` | string | Formatted baseline byte count. |
| `byte_share_display` | string | Formatted byte share. |
| `baseline_byte_share_display` | string | Formatted baseline byte share. |
| `hydrolix_log_ingest_bytes_display` | string | Formatted Hydrolix log-ingest bytes or `unavailable`. |
| `hydrolix_log_ingest_byte_share_display` | string | Formatted customer-log-volume share or `unavailable`. |
| `response_body_bytes_display` | string | Formatted response-body bytes or `unavailable`. |
| `response_body_byte_share_display` | string | Formatted response-byte share or `unavailable`. |
| `akamai_billed_bytes_display` | string | Formatted Akamai-billed bytes or `unavailable`. |
| `akamai_billed_byte_share_display` | string | Formatted CDN billed bandwidth share or `unavailable`. |
| `cost_range_display` | string | Formatted cost estimate when enabled. |
| `cost_basis_label` | string | Cost-estimate basis when enabled. |
| `cost_disclaimer` | string | Cost-estimate disclaimer when enabled. |

Do not add cost, origin-capacity, or cache-hit claims unless the prepared
context includes explicit supporting fields.

Primary `HUNT IMPACT` rendering must use the named byte lanes above. Unlabeled
`bytes` and `byte_share` are legacy compatibility fields only; never relabel
them as response-body, Akamai-billed, or Hydrolix ingest values when the
corresponding explicit lane is missing.

### `recommended_actions[]`

Action rows are prepared for direct display.

| Field | Type | Description |
|---|---:|---|
| `tier` / `tier_label` | string | Action tier and display label. |
| `scope` / `scope_label` | string | Target scope, such as campaign, UA family, or lead. |
| `action_type` / `action_type_label` | string | Action type and display label. |
| `wording_label` | string | Enforcement wording label. |
| `target_values` | object | Target IDs, user agents, endpoint prefixes, or related values. |
| `supporting_evidence` | list | Evidence labels supporting the action. |
| `validation_notes` | list | Validation steps before enforcement. |
| `false_positive_caveat` | string | False-positive guidance. |
| `rollback_monitoring` | list | Monitoring guidance after enforcement. |
| `impact_requests_display` | string | Formatted request impact. |
| `impact_request_share_display` | string | Formatted request share impact. |
| `impact_bytes_display` | string | Formatted byte impact. |
| `impact_byte_share_display` | string | Formatted byte share impact. |
| `impact_action_text` | string | Full action-card impact line. |
| `threat_category` / `threat_category_label` | string | Classification category. |
| `threat_confidence_display` | string | Formatted classification confidence. |
| `classification_ambiguity_note` | string | Boundary note when classification is ambiguous. |

### `pattern_notes[]`

Pattern notes are generated by the renderer from existing `bot_threat_hunt.v3`
fields; the raw producer schema is not changed. They are included only when an
explicit metric threshold is met, source fields are present, and at least one
supporting evidence family is available. They explain why a shape can matter
for validation, not why traffic is malicious.

| Field | Type | Description |
|---|---:|---|
| `title` | string | Pattern label, such as `Light payload / high hits` or `Distributed fan-out`. |
| `text` | string | Conservative explanatory prose. |
| `evidence_basis` | list | Prepared evidence families or summaries that allowed the note to render. |
| `links` | list | Compact source labels and URLs for OWASP, F5, and related bot-detection references. |
| `confidence_boundary` | string | Fixed boundary text stating that the note is not proof of intent, identity, or enforcement eligibility. |
| `surface_priority` | number | Stable renderer ordering. Lower values render first. |

The current pattern library covers light payload/high hits, direct-to-data/API
focus, boxy or interval cadence, UA impersonation or rotation, and distributed
fan-out. Response candidates remain driven by `recommended_actions[]`; pattern
notes may suggest validation dimensions but do not move actions between
response and monitor/validate groups.

### `campaigns[]`

Campaign rows include raw artifact fields plus display helpers.

Common fields include:

- `campaign_id`
- `verdict`, `verdict_label`
- `sophistication`
- `temporal_pattern`, `temporal_pattern_label`
- `leads`
- `total_requests`, `total_requests_display`
- `baseline_requests`, `baseline_requests_display`
- `baseline_delta_display`
- `bytes`, `bytes_display`
- `unique_client_ips`, `unique_asns`, `unique_countries`
- `impact_assessment`
- `drilldown_coverage_summary`
- `endpoint_evidence_summary`
- `ua_plausibility_summary`
- `confidence_summary`
- `timing_summary`
- `threat_classification`
- `fanout_summary`
- `link_narratives`
- `endpoint_targets`
- `recommended_actions`

### `ua_families[]`

Common fields include:

- `family_id`
- `template`
- `members`
- `member_count`
- `version_range`, `version_range_display`
- `version_count`
- `versions`
- `total_requests`, `total_requests_display`
- `total_baseline`, `total_baseline_display`
- `request_volume_cv`, `request_volume_cv_display`
- `bytes`, `bytes_display`
- `impact_assessment`
- `common_evidence`
- `structural_checks`
- `campaign_overlaps`
- `threat_classification`
- `recommended_actions`

### `scraper_cases[]`

Common fields include:

- `user_agent`
- `verdict`, `verdict_label`
- `campaign_id`, `campaign_verdict`
- `ua_family_id`, `ua_family_template`, `nested_under_family`
- `requests`, `requests_display`
- `baseline_requests`, `baseline_display`, `baseline_delta_display`
- `bytes`, `bytes_display`
- `impact_assessment`
- `unique_client_ips`, `unique_asns`, `unique_countries`
- `drilldown_coverage`
- `endpoint_evidence`
- `ua_plausibility`
- `fanout_enrichment`
- `evidence_flags`, `evidence_flag_labels`
- `timing`
- `threat_classification`
- `case_for`, `case_against`, `missing_evidence`
- `endpoint_targets`
- `bot_manager_context`

## Print/PDF-Only Context

When rendering with `--profile print` or PDF output, `post_prepare()` adds
print-specific fields. The print template also receives every screen field
above.

Important print keys:

| Key | Type | Description |
|---|---:|---|
| `customer` | string | Cover/report customer label. |
| `meta.schema` | string | Source artifact schema, `bot_threat_hunt.v3`. |
| `window` | object | Print-formatted current/baseline window. |
| `verdict` | object | Cover score, confidence, severity band, prose, and calibration text. |
| `cover_impact` | object | Cover-page `HUNT IMPACT` rows. |
| `story_page` | object | Page 2 story metadata. |
| `story_primary_finding` | object | Page 2 primary story card. |
| `story_secondary_finding` | object | Page 2 secondary story card. |
| `story_independent_leads` | object | Page 2 independent-leads strip. |
| `chart` | object | Fallback timeline data for non-threat-hunt use of the shared print template. |
| `at_a_glance` | object | Cover at-a-glance columns. |
| `actors_page` | object | Scraper-leads page metadata. |
| `actors` | list | Print-shortened actor/lead rows. |
| `actions_page` | object | Action page metadata. |
| `actions` | list | Print action-card rows. |
| `known_traffic` | list | Print known-traffic rows. |
| `bot_manager_print_summary` | object | Print Bot Manager summary. |
| `attck_page` | object | Methodology/ATT&CK page metadata and technique rows. |
| `attack_shape` | object | Page 4 evidence-shape and impact-analysis content. |
| `methodology` | object | Page 6 methodology prose, analysis rows, and metadata. |
| `print_sections` | object | Boolean flags for optional print sections. |
| `page_numbers` | object | Fixed-letter page-number labels. |
| `page_count` | number | Expected fixed-letter page count. |

### `cover_impact`

`cover_impact` is present for threat-hunt print/PDF output when
`impact_assessment.hunt.request_share` is available.

| Field | Type | Description |
|---|---:|---|
| `eyebrow` | string | `Hunt Impact`. |
| `rows` | list | Cover rows with `label`, `value`, and optional `emphasis`. |
| `footnote` | string | Denominator and byte-display explanation. |

### `attack_shape`

Page 4 uses `attack_shape` as the evidence/impact rollup.

| Field | Type | Description |
|---|---:|---|
| `campaign_descriptor` | object | Primary campaign shape summary. |
| `findings_summary` | list | Finding summary rows. |
| `impact_story` | object | Deterministic impact narrative lines. |
| `impact_rows` | list | Print/PDF `HUNT IMPACT` rows: hits, Hydrolix log ingest, response body, and Akamai-billed bandwidth. |
| `evidence_distribution` | list | Evidence distribution rows. |
| `boundaries` | list | Evidence-boundary rows. |
| `partial_boundaries` | list | Partial-evidence rows. |
| `top_paths` | list | Endpoint/path rows. |
| `coordination_signals` | list | Coordination signal rows. |

## Template Safety Rules

- Prefer display fields such as `*_display`, `*_label`, and prepared summary
  strings over formatting raw numbers in Jinja.
- Keep selection, grouping, truncation, sorting, and claim gating in
  `contexts/threat_hunt.py`, where tests can cover it.
- Treat `bot_manager_context` as operational enrichment only; do not use it as
  independent threat attribution.
- Use `impact_assessment` as total-window share. Do not invent a
  non-infrastructure denominator in the template.
- Do not render dollar cost unless `cost_range_display` and its basis fields
  are present.
- Do not make origin-capacity or cache-hit claims unless explicit grounded
  fields are added to the prepared context.
