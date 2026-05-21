# bot-insights - Report Extension Guide

This guide is for maintainers and LLM agents extending Bot Insights reports.
It explains how to add a new predefined report type or reskin an existing
report without weakening the data firewall. It is procedural by design: prefer
small, explicit wiring over broad renderer changes.

## Contents

- [Extension Lanes](#extension-lanes)
- [New Predefined Report Wiring](#new-predefined-report-wiring)
- [Capture and Evidence Support](#capture-and-evidence-support)
- [Data Firewall](#data-firewall)
- [LLM Boundary](#llm-boundary)
- [Report Skinning](#report-skinning)
- [Compatibility Checklist](#compatibility-checklist)
- [Validation](#validation)

## Extension Lanes

There are two supported lanes:

- **New predefined report:** a named `report_type` with deterministic capture,
  evidence assembly, artifact validation, and rendering behavior. Use this when
  the report changes what evidence is required, which entities are ranked, how
  evidence is summarized, or which workflow the skill should guard.
- **Report skinning:** changes to palette, labels, CSS, templates, macros, or
  wrapper metadata that do not change evidence semantics. Use this for visual
  presentation, brand language, section order, or labels when scores,
  thresholds, evidence limits, ranks, and metric values stay the same.

If a proposed skin changes report meaning, treat it as a new report type or a
documented report variant with explicit semantics.

Current predefined report types are:

- `executive_posture`
- `control_review`
- `soc_triage`
- `scorecard_brief`
- `crawler_governance`
- `edge_ops_impact`
- `incident_report` — produces three artifacts:
  `bot_incident_scope.v1` (window confirmation + scope mixes),
  `bot_incident_actors.v1` (per-field actor rankings against
  `akamai.logs`), and `bot_incident_action_targets.v1` (suspicious
  targets graduated by the v2 heuristic ladder; required but may
  carry `"targets": []`).

## New Predefined Report Wiring

A new predefined report needs all renderer-facing wiring below before it is
considered a supported `report_type`.

1. Add a context module under `scripts/report_engine/contexts/`.
2. Register the context module in
   `scripts/report_engine/contexts/__init__.py`.
3. Route wrappers through `bot_report_input.v1.report_type`.
4. Add an HTML template and Markdown sibling under
   `scripts/report_engine/templates/reports/`.
5. Keep legacy `scripts/render_report.py` constants and choices compatible
   anywhere production routing still enters through that script.
6. Add guarded capture/report support in `scripts/bot_insights_report.py` only
   when the report is intended to be a first-class predefined report.

### Context Module Contract

Each file in `scripts/report_engine/contexts/` is a pure context preparer.
It must expose this contract:

```python
SCHEMA = "bot_example_artifact.v1"
REPORT_TYPE = "example_report"
TEMPLATE = "reports/example_report.html"
NOTE_ID_TO_SLOT = {
    "llm-interpretation": "executive_summary",
}

def assemble(artifacts: list[dict]) -> dict:
    ...

def prepare(artifact: dict) -> dict:
    ...
```

The example above is intentionally partial. Use existing modules such as
`executive_posture.py`, `control_review.py`, `soc_triage.py`,
`scorecard_brief.py`, `crawler_governance.py`, and `edge_ops_impact.py` as
the complete local patterns.

`assemble()` reshapes a `bot_report_input.v1` wrapper's `artifacts[]` into the
single dictionary that `prepare()` expects. `prepare()` must be deterministic:
it reshapes artifacts into template context and must not query Hydrolix,
inspect credentials, recompute producer-owned scores, or call an LLM.

`NOTE_ID_TO_SLOT` maps `analyst_notes[].note_id` values into template slots.
The mapping controls where LLM-authored prose appears; it must not influence
metric values, chart values, row selection, evidence limits, duplicate
detection, or ranking.

### Context Registration

Update `scripts/report_engine/contexts/__init__.py`:

- import the new module;
- include it in `_MODULES`;
- add it to `_SCHEMA_REGISTRY_EXCLUSIONS` when the raw artifact schema is
  shared with another report type and the wrapper `report_type` is required
  to disambiguate routing.

The wrapper path is the durable route for report intent. A reusable demo input
should carry:

```json
{
  "schema_version": "bot_report_input.v1",
  "report_type": "example_report",
  "artifacts": [],
  "analyst_notes": []
}
```

The example above is intentionally partial. Replace `artifacts` with complete
deterministic artifact objects and include analyst notes only when the report
has prose generated from an evidence packet or supplied by an analyst.

### Templates

Add both template siblings under `scripts/report_engine/templates/reports/`:

- `example_report.html`
- `example_report.md.j2`

Keep layout decisions in templates and shared macros. Keep data selection,
compatibility checks, and evidence truncation in Python context/renderer code
where they can be tested deterministically.

For the existing threat-hunt report, use
[threat-hunt-template-context.md](threat-hunt-template-context.md) as the
field reference for data available to the HTML, Markdown, and print/PDF Jinja
templates.

### Legacy Renderer Compatibility

Some production and smoke-test paths still enter through
`scripts/render_report.py`. When adding a predefined report, keep these
compatible with the new `report_type`:

- `REPORT_TYPES`
- CLI `--report-type` choices
- supported schema and required-artifact validation
- default title/limit behavior
- Markdown and HTML render routing
- warning behavior for dropped or incompatible companion artifacts

Do not add a report only to the new engine path if an existing user-facing
entrypoint still relies on `render_report.py`.

## Capture and Evidence Support

Only add capture/report orchestration to `scripts/bot_insights_report.py` when
the new report should be a guarded predefined report. That means it has a
stable, named workflow and the skill should enforce capture, evidence, LLM
interpretation, and rendering boundaries.

For a guarded predefined report, wire:

- CLI `--report` choices;
- deterministic capture preset or guarded SQL assembly;
- artifact production from saved raw rows;
- `bot_report_evidence.v1` packet production;
- `interpretation_contract` instructions for LLM prose;
- wrapper construction with `bot_report_input.v1.report_type`;
- final rendering through `scripts/render_report.py`.

Do not add Hydrolix access to artifact-only tools such as scorecard,
comparison, attribution, or rendering scripts. Those tools consume saved JSON.

## Data Firewall

New predefined reports must use the existing capture/report boundary for
Hydrolix access:

- `scripts/bot_insights_capture.py` may query Hydrolix directly or emit an MCP
  handoff packet when credentials are unavailable.
- `scripts/bot_insights_report.py` may query Hydrolix only by delegating to the
  capture flow.
- artifact-only renderers and transformers must not query Hydrolix, open
  database clients, read credentials, or resolve cluster config.

When a predefined report is running and local credentials resolve, MCP
`run_select_query` is forbidden for that report's data. When credentials do
not resolve, the capture script must emit a
`bot_hydrolix_mcp_query_request.v1` packet before an LLM/agent runs MCP, and
the agent must run only the packet's exact `cluster` and `validated_sql`.

For non-predefined exploratory analysis, the normal Hydrolix MCP workflow
remains available. Do not mix exploratory SQL into a scripted final-report
capture.

## LLM Boundary

The LLM may interpret evidence; it does not own report mechanics.

LLM prose can enter a report only through:

- `analyst_notes` in a `bot_report_input.v1` wrapper; or
- interpretation of a `bot_report_evidence.v1` packet before those notes are
  added to the wrapper.

The LLM must not invent layout, metrics, scores, ranks, thresholds, evidence
limits, chart values, missing-evidence claims, root cause, or malicious intent.
Use the evidence packet's `interpretation_contract` and human-readable labels.
The deterministic renderer owns final Markdown/HTML layout.

## Report Skinning

Skinning is presentation-only. It may change how an existing report looks or
how labels read, but not what the report means.

Use these surfaces for skinning:

- `scripts/report_engine/theme.py` for palette, domain labels, domain order,
  and score bands.
- `scripts/report_engine/templates/_styles.css` for CSS layout and visual
  treatment.
- `scripts/report_engine/templates/reports/*.html` and
  `scripts/report_engine/templates/reports/*.md.j2` for report-specific
  section order and copy.
- shared report macros for repeated visual or Markdown structures.
- wrapper metadata such as title, scope label, and analyst note titles when
  the underlying evidence semantics stay unchanged.

For first-party Hydrolix identity in the incident/editorial report family, use
the brand rendering note: [report-rendering-brand.md](report-rendering-brand.md).
The key rule is brand for identity and structure, Tableau-style colors for
meaning. Hydrolix primary teal is non-text chrome on light surfaces; use deep
teal or navy when text needs a brand tone.

Do not change these as skinning:

- scores;
- thresholds;
- evidence limits;
- rank order;
- selected artifact schemas;
- metric values;
- delta math;
- confidence semantics;
- report eligibility rules.

If brand or audience requirements need different semantics, create a new
report type or document a report variant. Do not hide semantic changes inside
palette, CSS, labels, or templates.

### Private Brand Skins

Brand-specific report skins belong outside public skill distributions unless
the change is documentation that shows maintainers how to apply their own
skin. Do not commit customer, partner, or Hydrolix brand assets, palette
overrides, or runtime template changes as the default report presentation.

For a local or private skin prototype:

1. Keep brand assets in a private path outside the distributable skill, or in
   an ignored/internal package owned by the deployment.
2. Patch only the documented skinning surfaces:
   `scripts/report_engine/theme.py`,
   `scripts/report_engine/templates/_styles.css`, `base.html`, and shared
   macros when repeated presentation markup is needed.
3. Embed or resolve image assets in a way that matches the renderer's output
   model. The HTML renderer produces self-contained files, so a logo needs a
   data URI or another deployment-local asset resolver; Markdown should remain
   text-only unless its templates already support image references cleanly.
4. Keep score-band thresholds, evidence limits, entity ordering, warnings,
   artifact validation, capture behavior, and firewall behavior unchanged.
5. Render representative examples in Markdown and HTML and compare visible
   report text before/after. Only presentation and explicitly added brand
   decoration should differ.

Use brand examples in this document as fragments, not committed defaults.
Complete examples should use placeholder names and colors unless the brand
owner explicitly approves redistribution.

## Compatibility Checklist

Before calling a new predefined report supported, verify:

- the new `REPORT_TYPE` is registered in the report engine;
- wrapper routing works through `bot_report_input.v1.report_type`;
- legacy `render_report.py` recognizes the report anywhere users still enter
  through that script;
- the HTML template and Markdown sibling render the same evidence semantics;
- `analyst_notes` route only to named narrative slots;
- artifact validation rejects missing required evidence clearly;
- dropped companion artifacts produce warnings instead of silent omission;
- capture/report orchestration exists only when the report is intended to be
  guarded;
- no artifact-only renderer or transformer imports a database client or reads
  Hydrolix credentials.

## Validation

For docs-only changes, run:

```bash
git diff --check
```

For report extension or skinning changes, also run targeted renderer tests or
render an existing example in both formats. A lightweight smoke command is:

```bash
uv run python skills/bot-insights/scripts/render_report.py \
  --file skills/bot-insights/examples/scorecard-brief.json \
  --format markdown \
  --output /tmp/scorecard-brief.md
```

After editing JSON, YAML, SQL, Python, or shell examples in Markdown, inspect
the changed fenced blocks and label partial examples clearly.
