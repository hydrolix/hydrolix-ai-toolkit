"""Incident-report orchestrator.

This package preserves the historical ``producers.orchestrators.incident_report``
import surface while keeping collection and rendering phases in smaller modules.
"""

from .capture import _capture_or_raise, _capture_sql_to_rows, _emit_handoff_packet
from .contracts import INCIDENT_INTERPRETATION_CONTRACT, _IncidentCtx, _IncidentHandoff
from .emit import _incident_emit_or_render
from .helpers import (
    _grafana_host_base,
    _incident_cluster_env,
    _incident_raw_column_candidates,
    _resolve_dashboard_url,
    _resolve_incident_env_value,
    _resolve_summary_layout,
    _summary_dimension_column,
    _timeseries_has_current_requests,
)
from .introspection import _incident_introspect_columns
from .phase1 import (
    _incident_phase1_dimensions,
    _incident_phase1_window_and_timeseries,
    _incident_run_dimension,
    _incident_run_siem_dimension,
)
from .phase2 import (
    _incident_phase2_actors_and_heuristic,
    _incident_phase2_baseline_actor_field,
    _incident_phase2_baseline_actors,
    _incident_phase2_cooccurrence,
    _incident_phase2_current_actor_field,
    _incident_phase2_current_actors,
    _incident_phase2_flagged_ip_timeseries,
    _incident_phase2_provenance_cooccurrence,
)
from .runner import _run_incident_report

__all__ = ['INCIDENT_INTERPRETATION_CONTRACT', '_IncidentHandoff', '_IncidentCtx', '_incident_raw_column_candidates', '_timeseries_has_current_requests', '_summary_dimension_column', '_resolve_summary_layout', '_capture_sql_to_rows', '_incident_cluster_env', '_resolve_incident_env_value', '_grafana_host_base', '_resolve_dashboard_url', '_emit_handoff_packet', '_capture_or_raise', '_incident_introspect_columns', '_incident_phase1_window_and_timeseries', '_incident_run_dimension', '_incident_run_siem_dimension', '_incident_phase1_dimensions', '_incident_phase2_current_actor_field', '_incident_phase2_current_actors', '_incident_phase2_baseline_actor_field', '_incident_phase2_baseline_actors', '_incident_phase2_cooccurrence', '_incident_phase2_provenance_cooccurrence', '_incident_phase2_flagged_ip_timeseries', '_incident_phase2_actors_and_heuristic', '_incident_emit_or_render', '_run_incident_report']
