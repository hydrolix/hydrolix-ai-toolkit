"""Incident SQL builders.

This package preserves the historical ``producers.sql.incident`` import surface
while keeping query-builder groups in smaller modules.
"""

from .actors import (
    _incident_actor_cooccurrence_sql,
    _incident_actor_scoped_metrics_baseline_sql,
    _incident_actor_scoped_metrics_sql,
    _incident_actor_topk_baseline_sql,
    _incident_actor_topk_sql,
    _incident_client_ip_bot_source_cooccurrence_sql,
    _incident_client_ip_proxy_classification_cooccurrence_sql,
)
from .dimensions import (
    _incident_bot_source_mix_sql,
    _incident_bucketed_dimension_timeseries_sql,
    _incident_bucketed_edge_action_timeseries_sql,
    _incident_deny_rule_mix_sql,
    _incident_dimension_sql,
    _incident_edge_action_mix_sql,
    _incident_proxy_classification_mix_sql,
    _incident_siem_dimension_sql,
    _incident_status_mix_sql,
)
from .targets import (
    _incident_flagged_client_ip_timeseries_sql,
    _incident_target_bucket_evidence_sql,
)
from .shared import (
    _incident_columns_query,
    _incident_identifier,
    _incident_in_list,
    _incident_raw_scope_predicate,
    _incident_scope_predicate,
    _incident_summary_count_expr,
    _incident_summary_count_if_expr,
    _incident_summary_time_expr,
    _incident_time_predicate,
)
from .window import (
    _incident_volume_timeseries_sql,
    _incident_window_confirmation_sql,
)

__all__ = ['_incident_identifier', '_incident_summary_time_expr', '_incident_summary_count_expr', '_incident_summary_count_if_expr', '_incident_time_predicate', '_incident_scope_predicate', '_incident_raw_scope_predicate', '_incident_columns_query', '_incident_in_list', '_incident_window_confirmation_sql', '_incident_volume_timeseries_sql', '_incident_dimension_sql', '_incident_edge_action_mix_sql', '_incident_bot_source_mix_sql', '_incident_proxy_classification_mix_sql', '_incident_bucketed_dimension_timeseries_sql', '_incident_bucketed_edge_action_timeseries_sql', '_incident_flagged_client_ip_timeseries_sql', '_incident_deny_rule_mix_sql', '_incident_target_bucket_evidence_sql', '_incident_status_mix_sql', '_incident_siem_dimension_sql', '_incident_actor_topk_sql', '_incident_actor_topk_baseline_sql', '_incident_actor_scoped_metrics_sql', '_incident_actor_scoped_metrics_baseline_sql', '_incident_actor_cooccurrence_sql', '_incident_client_ip_bot_source_cooccurrence_sql', '_incident_client_ip_proxy_classification_cooccurrence_sql']
