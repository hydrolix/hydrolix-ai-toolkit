"""Second-pass campaign detector for ``bot_threat_hunt.v3`` scraper leads."""

from __future__ import annotations

from .attach import attach_campaigns
from .compose import _compose_campaign
from .constants import VERDICT_ORDER, _TARGET_ENDPOINT_CATEGORIES, _TRACKING_STATIC_PATHS
from .endpoints import (
    _campaign_endpoint_evidence_summary,
    _campaign_endpoint_reason,
    _endpoint_category,
    endpoint_prefix,
)
from .features import (
    _accumulate_case_endpoint_targets,
    _accumulate_case_features,
    _accumulate_case_geo_lists,
    _accumulate_case_hourly_bursts,
    _accumulate_case_timing,
    _accumulate_cooccurrence_features,
    _accumulate_drilldown_features,
    _add_hour_feature,
    _feature_vectors,
    _geo_for_ip,
)
from .linking import (
    _campaign_sophistication,
    _connected_components,
    _link_edge,
    _temporal_pattern,
)
from .numbers import _cosine, _num, _pct, _pearson
from .summaries import (
    _campaign_drilldown_coverage_summary,
    _campaign_fanout_summary,
    _campaign_timing_summary,
    _campaign_ua_plausibility_summary,
    _coverage_label,
)
from .verdicts import _verdict_for_family_count

__all__ = [
    "VERDICT_ORDER",
    "_TARGET_ENDPOINT_CATEGORIES",
    "_TRACKING_STATIC_PATHS",
    "_accumulate_case_endpoint_targets",
    "_accumulate_case_features",
    "_accumulate_case_geo_lists",
    "_accumulate_case_hourly_bursts",
    "_accumulate_case_timing",
    "_accumulate_cooccurrence_features",
    "_accumulate_drilldown_features",
    "_add_hour_feature",
    "_campaign_drilldown_coverage_summary",
    "_campaign_endpoint_evidence_summary",
    "_campaign_endpoint_reason",
    "_campaign_fanout_summary",
    "_campaign_sophistication",
    "_campaign_timing_summary",
    "_campaign_ua_plausibility_summary",
    "_compose_campaign",
    "_connected_components",
    "_cosine",
    "_coverage_label",
    "_endpoint_category",
    "_feature_vectors",
    "_geo_for_ip",
    "_link_edge",
    "_num",
    "_pct",
    "_pearson",
    "_temporal_pattern",
    "_verdict_for_family_count",
    "attach_campaigns",
    "endpoint_prefix",
]
