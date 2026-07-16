# Report Rendering Brand Standard

Bot Insights reports use a two-channel visual system:

- Hydrolix brand tokens are for identity and structure: logo placement,
  mastheads, section rules, focus rings, non-semantic CTA accents, decorative
  frames, and neutral page architecture.
- Tableau-style semantic tokens are for meaning: severity ladders, risk pills,
  hot stats, deltas, incident/current/baseline series, action tones, chart
  encodings, and table heat cues.

Do not use Hydrolix brand colors to encode risk, severity, incident state,
delta direction, confidence, or action priority. Those meanings must continue
to resolve through the semantic/Tableau token channel so visual identity cannot
change analytical meaning.

## Hydrolix Identity Tokens

Bot Insights reports follow the 2026 Hydrolix Brand
Guidelines for identity chrome:

- Typography: Public Sans for editorial text and Inconsolata for labels,
  metadata, and compact tabular material.
- Logo: Hydrolix wordmark in the upper-left masthead; lower-left placement is
  the preferred footer position when a rendered format needs a second logo.
- Primary teal: `#00A99D`, reserved for non-text chrome on light surfaces such
  as dividers, borders, icons, focus outlines, and masthead rules.
- Navy: `#003D66` and deep navy `#092747`, used for brand identity and dark
  structural accents.
- Yellow: `#FFB800`, used sparingly as a brand secondary accent, not as a
  warning/severity color.
- Teal text alternatives: use deep teal `#035F60` or darker teal `#024545`
  when teal-toned text is required on white or near-white surfaces.

The primary teal is not valid body text on white. The brand contrast guidance
records it at roughly 2.93:1 on white, below WCAG AA for normal text. Use it
only for non-text elements on light backgrounds; use the deep teal or navy
tokens for text.

## Semantic Color Rules

Meaning-bearing report tokens must stay separate from the Hydrolix brand
palette:

- Severity/risk: Tableau blue, yellow, orange, red, and darkened red.
- Deltas: green for improvement/down where the report defines lower as better;
  alert colors remain semantic, not brand.
- Incident charts: current, incident highlight, scoped-window highlight, and
  baseline series use semantic chart tokens.
- Action chips: action tone classes map back to the semantic severity palette.
- Table heat cues: hot cells and critical rows use semantic red/orange/yellow
  tokens.

If a palette file is used through the existing `--palette-file` mechanism, it
may re-skin the generic report palette, but it must not turn semantic slots
into Hydrolix brand colors unless the report type explicitly changes meaning.
No new wrapper schema is required for brand-only presentation changes.

## Validation

After changing report theme or editorial CSS, run:

```bash
uv run pytest tests/test_report_engine.py -k 'palette'
```

The targeted tests assert that:

- Bot Insights and `reportkit` theme tokens stay in sync.
- Semantic tokens do not resolve to Hydrolix brand hex values.
- Meaning-bearing CSS selectors do not reference `--brand-*`.
- Primary teal is not used as text on the light editorial surface.
