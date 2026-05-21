from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# report_engine.humanize and report_engine.theme are pure-Python
# (no jinja2 / bleach / markdown-it-py imports). Importing them here
# lets the orchestrator surface human-readable labels alongside the
# raw snake_case identifiers in evidence packets so the LLM
# interpretation step doesn't have to copy ``cache_miss_rate_high`` /
# ``feature_input_missing`` / ``request_host`` into prose.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_engine import humanize as _humanize  # noqa: E402
from report_engine.theme import DOMAIN_LABELS as _DOMAIN_LABELS  # noqa: E402

# Heuristic-ladder calibration constants (suspicious-target thresholds,
# anomaly rate floors, automation-UA pattern, severity-rank table, and
# the quant/concentration flag partitions). Lifted to ``heuristics`` so
# tuning against real incidents is one focused file change. Imported
# under their original names so every call site in this module keeps
# working without touching the heuristic body.
from heuristics import (  # noqa: E402
    _ANOMALY_CURRENT_ERROR_RATE_MIN,
    _ANOMALY_ERROR_RATE_RATIO_MIN,
    _ANOMALY_MIN_REQUESTS,
    _AUTOMATION_UA_PATTERN,
    _SEVERITY_RANK,
    _SUSPICIOUS_ASN_CLUSTER_MIN_IPS,
    _SUSPICIOUS_BOTNET_CLUSTER_SHARE_MIN,
    _SUSPICIOUS_CONCENTRATION_FLAGS,
    _SUSPICIOUS_NEW_ACTOR_REQUESTS_MIN,
    _SUSPICIOUS_NEW_ACTOR_VOLUME_SHARE_MIN,
    _SUSPICIOUS_QUANT_FLAGS,
    _SUSPICIOUS_RATE_429_SHARE_MIN,
    _SUSPICIOUS_RATE_429_TOTAL_MIN,
    _SUSPICIOUS_SINGLE_PATH_REQUESTS_MIN,
    _SUSPICIOUS_VOLUME_SHARE_MIN,
    _is_templated_catchall_path,
)


# Runtime constants and the low-level subprocess + JSON helpers used
# across every producer module live in ``producers.runtime``. Re-imported
# here under their original names for back-compat.
from producers.runtime import (  # noqa: E402
    CAPTURE,
    DEFAULT_SAMPLE_ROOT,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    PUBLIC_SKILLS,
    load_raw_query_result,
    result_rows,
    run,
)


# Stateless formatters (number / time / SQL literal) live in
# ``producers.formatting``. Re-imported under the original module-level
# names so every existing call site in this file — and every test that
# reaches in via ``bot_insights_report.<name>`` — continues to work.
from producers.formatting import (  # noqa: E402
    as_number,
    bucket_expr,
    choose_granularity,
    human_number,
    label_change,
    parse_time,
    pct,
    pct_change,
    sql_literal,
    sql_ts,
)

# Per-report SQL builders live under ``producers.sql.*``. Re-imported
# under their original module-level names so main() and tests keep
# resolving them via ``bot_insights_report.<name>``.
from producers.sql.executive_posture import executive_posture_sql  # noqa: E402
from producers.sql.control_review import (  # noqa: E402
    control_review_sql,
    control_review_timeseries_sql,
)
from producers.sql.scorecard import (  # noqa: E402
    CRAWLER_ENTITY_SQL,
    CRAWLER_POPULATION_BY_ENTITY,
    EDGE_OPS_ENTITY_SQL,
    SCORECARD_ENTITY_SQL,
    SOC_ENTITY_SQL,
    cache_origin_path_sql,
    scorecard_crawler_sql,
    scorecard_edge_ops_sql,
    scorecard_soc_sql,
    scorecard_sql,
)
from producers.sql.incident import (  # noqa: E402
    _incident_actor_cooccurrence_sql,
    _incident_actor_scoped_metrics_baseline_sql,
    _incident_actor_scoped_metrics_sql,
    _incident_actor_topk_baseline_sql,
    _incident_actor_topk_sql,
    _incident_columns_query,
    _incident_deny_rule_mix_sql,
    _incident_dimension_sql,
    _incident_edge_action_mix_sql,
    _incident_in_list,
    _incident_raw_scope_predicate,
    _incident_scope_predicate,
    _incident_siem_dimension_sql,
    _incident_status_mix_sql,
    _incident_time_predicate,
    _incident_volume_timeseries_sql,
    _incident_window_confirmation_sql,
)

# Per-report evidence-packet builders + the shared metric helpers
# live under ``producers.evidence.*``. Re-imported under their
# original module-level names so existing call sites and tests that
# reach in via ``bot_insights_report.<name>`` keep working.
from producers.evidence.metrics import (  # noqa: E402
    METRIC_LABELS,
    metric_by_name,
    metric_card_from_metric,
    metric_map_from_control_effects,
    rate_row,
    standard_derived_rates,
)
from producers.evidence.posture import build_evidence_packet  # noqa: E402
from producers.evidence.control import (  # noqa: E402
    build_control_evidence_packet,
    control_followups,
)
from producers.evidence.scorecard import (  # noqa: E402
    build_scorecard_evidence_packet,
    build_scorecard_fleet_evidence_packet,
    select_scorecard,
    selected_rank,
)

# Incident-report evidence-shaping helpers (pure projections that lift
# captured rows into artifact shapes) live under
# ``producers.evidence.incident``. The heuristic-ladder evaluators
# (Phase 1 outputs) and the contract-level lookup tables (ATT&CK
# mapping, action class) live under ``producers.suspicious_targets``.
# Both are re-imported here under their original module-level names so
# main()/_run_incident_report keep working unchanged.
from producers.evidence.incident import (  # noqa: E402
    _INCIDENT_DEFAULT_FIELDS,
    _INCIDENT_FIELD_LABELS,
    _build_action_targets_artifact,
    _incident_actor_rows,
    _incident_compute_timeseries,
    _incident_compute_window_confirmation,
    _incident_dimension_rows,
    _incident_split_period_rows,
    _incident_status_rows,
)
from producers.suspicious_targets import (  # noqa: E402
    _INDIVIDUAL_ENTITY_FIELDS,
    _PRIMITIVE_ATTACK_TECHNIQUES,
    _SUSPICIOUS_TARGET_TYPE_BY_FIELD,
    _TARGET_KIND_BY_TYPE,
    _apply_asn_grouped_pivots,
    _apply_cluster_pivots,
    _apply_unverified_cluster_pivots,
    _assign_severity,
    _attack_techniques_for_flags,
    _build_target_entry,
    _compute_suspicious_targets,
    _evaluate_all_rankings,
    _evaluate_anomaly,
    _evaluate_novelty_flags,
    _evaluate_ranking_row,
    _evaluate_share_flags,
    _suspicious_action_class,
)

# The incident_report orchestrator + its tightly-coupled helpers
# (subprocess + JSON capture wrapper, MCP handoff packet builder,
# cluster-env / dashboard-URL resolution, the ``_IncidentHandoff``
# exception) live in ``producers.orchestrators.incident_report``.
# Re-imported here under the original names. Note: that module uses a
# late import of ``analyst_note_from_args``, ``build_report_wrapper``,
# and ``humanize_evidence_packet`` from this module to avoid the
# circular import that would otherwise form at module-load time.
from producers.orchestrators.incident_report import (  # noqa: E402
    INCIDENT_INTERPRETATION_CONTRACT,
    _IncidentHandoff,
    _capture_sql_to_rows,
    _emit_handoff_packet,
    _grafana_host_base,
    _incident_cluster_env,
    _resolve_dashboard_url,
    _resolve_incident_env_value,
    _run_incident_report,
)

# Evidence-packet label enrichment lives in
# ``producers.evidence.labeling``. ``humanize_evidence_packet`` and the
# private helpers it composes (``_humanize_feature_name``, etc.) are
# re-exported here so tests reach them via the historical
# ``bot_insights_report.<name>`` surface.
from producers.evidence.labeling import (  # noqa: E402
    _LABEL_PREFERENCE_RULE,
    _enrich_feature_card,
    _humanize_feature_name,
    _humanize_input_list,
    _with_label_preference,
    humanize_evidence_packet,
)

# Wrapper-construction helpers (timeseries artifact builder, per-report
# metadata stampers, analyst-note builder, the wrapper assembler, and
# the prompt-template renderer) live in ``producers.wrapper``.
from producers.wrapper import (  # noqa: E402
    add_control_metadata,
    add_report_metadata,
    add_scorecard_metadata,
    analyst_note_from_args,
    build_report_wrapper,
    build_timeseries_artifact,
    render_template_packet,
)

# CLI entry — argparse setup and the dispatch ``main()``. Lives in
# ``producers.cli`` so this module can be a thin re-export shim.
from producers.cli import main, parse_args  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

