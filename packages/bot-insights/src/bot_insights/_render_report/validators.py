"""Compatibility facade for report validation helpers."""

from __future__ import annotations

from .validators_dedupe import (
    cited_artifact_selectors,
    dedupe_artifact_bodies,
    duplicate_dedupe_risk,
)
from .validators_input import (
    default_limit,
    generated_title,
    infer_report_type,
    load_report_input,
    resolve_options,
)
from .validators_normalization import (
    artifact_with_id,
    by_schema,
    duplicate_body_fingerprint,
    json_fingerprint,
    normalize_artifacts,
    reserved_artifact_id,
    schema_of,
    validate_artifact_schema,
)
from .validators_selection import (
    compatible_scorecards_for_index,
    compatible_scorecards_for_index_with_order_status,
    filter_compatible_companion,
    first_or_warn,
    require_one,
    same_packet,
    scan_metadata_warnings,
    shared_metadata_matches,
    validate_report_artifacts,
)

__all__ = [
    'json_fingerprint',
    'duplicate_body_fingerprint',
    'reserved_artifact_id',
    'schema_of',
    'validate_artifact_schema',
    'artifact_with_id',
    'normalize_artifacts',
    'load_report_input',
    'infer_report_type',
    'resolve_options',
    'default_limit',
    'generated_title',
    'by_schema',
    'cited_artifact_selectors',
    'duplicate_dedupe_risk',
    'dedupe_artifact_bodies',
    'require_one',
    'filter_compatible_companion',
    'validate_report_artifacts',
    'same_packet',
    'shared_metadata_matches',
    'compatible_scorecards_for_index_with_order_status',
    'compatible_scorecards_for_index',
    'first_or_warn',
    'scan_metadata_warnings',
]
