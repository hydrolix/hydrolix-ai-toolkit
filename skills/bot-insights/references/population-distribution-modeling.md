# Population Distribution Modeling

Population distribution modeling adds an optional `population_anomaly` evidence
family to Bot Insights threat-hunt workflows. It scores whether a lead UA's
observed population shape matches the organic population for the browser family
it claims to be.

This file is the conceptual skill reference. The implementation planning source
of truth has moved to the standalone repository at
`/Users/turtlebender/src/bot-insights-population-mart/docs/population-distribution-modeling/README.md`.

## Concept

The signal is multivariate population shape rather than a single threshold. A
scraper may imitate one margin, such as request rate or timing, but at scale it
is harder to reproduce the joint distribution of organic browser actors.

The v1 architecture separates four concerns:

| Concern | Runtime | Reads | Writes |
| --- | --- | --- | --- |
| Harvest | Python or Go worker | Hydrolix summary/raw logs | Local mart rows |
| Training | Python | Local mart rows | Portable model artifacts |
| Inference | Go | Local mart rows and model artifacts | Population enrichment rows |
| Rendering | Python report producer | Population enrichment rows | Threat-hunt evidence family |

Training and inference stay strictly separated. Python training may use batch
ML dependencies. Go inference consumes only serialized model math and mart
facts; it must not load Python objects, call sklearn, or query Hydrolix.

## Contract Summary

- Mart storage is Parquet directory data queried with DuckDB.
- Every UA-grained table preserves exact `UA` and required `ua_hash`.
- Mart/model compatibility requires equality on `schema_version`,
  `bytes_semantics`, `timestamp_sample_policy`, `timestamp_sample_size`,
  `content_classifier_version`, and `parser_version`.
- Training uses a customer-specific rolling historical window and excludes the
  active scoring window.
- PCA component count is chosen per family by a variance target (default
  0.95). KDE bandwidth is chosen by Scott's rule. Training projection is
  capped at 10,000 points with deterministic seeded subsampling. All choices
  are serialized in the family artifact and consumed verbatim by the scorer.
- Numbers in artifacts use shortest-round-trip decimal serialization so the
  Python trainer and Go scorer produce byte-identical JSON.
- Stage 1 is contextual only.
- Stage 2 is screened by default and may carry verdict credit when scored,
  sufficiently supported (default 48 actor-hours), and the per-actor score
  distribution is `tight_anomalous`.
- Not-scored rows are caveats, not case-against evidence.
- v1 does not mitigate undetected-bot contamination of the training
  population. The manifest records
  `training_config.contamination_mitigation = "none"` so a future upgrade is
  detectable.

For concrete phases, merge points, artifact schemas, JSON examples, parity
tolerances, and readiness checks, use the planning package:

- `/Users/turtlebender/src/bot-insights-population-mart/docs/population-distribution-modeling/architecture-decisions.md`
- `/Users/turtlebender/src/bot-insights-population-mart/docs/population-distribution-modeling/implementation-phases.md`
- `/Users/turtlebender/src/bot-insights-population-mart/docs/population-distribution-modeling/artifact-contracts.md`
- `/Users/turtlebender/src/bot-insights-population-mart/docs/population-distribution-modeling/acceptance-criteria.md`
