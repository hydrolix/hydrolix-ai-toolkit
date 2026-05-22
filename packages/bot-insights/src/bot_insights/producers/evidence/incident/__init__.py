"""Incident evidence helpers.

This package preserves the historical ``producers.evidence.incident`` import
surface while keeping evidence projections in smaller modules.
"""

from .actors import _build_action_targets_artifact, _incident_actor_rows
from .clusters import (
    _cluster_aggregate_behavior,
    _cluster_confidence,
    _cluster_coverage_summary,
    _cluster_total_requests,
    _dominant_action_profile,
    _fallback_cluster_buckets,
    _incident_behavior_clusters,
    _incident_entity_cluster,
    _incident_entity_clusters,
    _primary_cluster_buckets,
    _primary_facet_for_target,
    _representative_cluster_actors,
    _shared_facets_for_cluster,
    _target_key,
    _target_label_for_cluster,
    _target_requests,
    _target_shared_facets,
)
from .constants import _INCIDENT_DEFAULT_FIELDS, _INCIDENT_FIELD_LABELS
from .dimensions import (
    _incident_bucketed_mix_timeseries,
    _incident_dimension_rows,
    _incident_dominant_target_value,
    _incident_status_rows,
    _incident_target_evidence_entry,
    _incident_target_evidence_rows,
)
from .mitigations import _incident_mitigation_effectiveness
from .window import (
    _incident_blocked_share,
    _incident_bucket_datetime,
    _incident_bucketize,
    _incident_compute_timeseries,
    _incident_compute_window_confirmation,
    _incident_series_for,
    _incident_spike_flags,
    _incident_split_period_rows,
)

__all__ = ['_INCIDENT_DEFAULT_FIELDS', '_INCIDENT_FIELD_LABELS', '_incident_split_period_rows', '_incident_compute_window_confirmation', '_incident_blocked_share', '_incident_spike_flags', '_incident_compute_timeseries', '_incident_bucket_datetime', '_incident_bucketize', '_incident_series_for', '_incident_dimension_rows', '_incident_status_rows', '_incident_bucketed_mix_timeseries', '_incident_target_evidence_rows', '_incident_target_evidence_entry', '_incident_dominant_target_value', '_target_key', '_target_requests', '_target_shared_facets', '_incident_behavior_clusters', '_dominant_action_profile', '_incident_entity_clusters', '_primary_cluster_buckets', '_primary_facet_for_target', '_fallback_cluster_buckets', '_shared_facets_for_cluster', '_cluster_confidence', '_target_label_for_cluster', '_incident_entity_cluster', '_cluster_total_requests', '_representative_cluster_actors', '_cluster_aggregate_behavior', '_cluster_coverage_summary', '_incident_mitigation_effectiveness', '_incident_actor_rows', '_build_action_targets_artifact']
