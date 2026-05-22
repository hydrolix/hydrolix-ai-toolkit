"""External AS reputation context for incident reports.

Provider output is explanatory context only: callers must not feed it into
risk scoring, confidence gates, target sorting, or incident-claim wording.
"""

from __future__ import annotations

from .behavior import _observed_asn_behavior, _ranking_rows_by_asn, _target_asn
from .behavior import observed_asns
from .constants import AUTHORITATIVE_SOURCE_TYPES, LABEL_DISPLAY
from .constants import QUALIFYING_SOURCE_TYPES, SPAMHAUS_ASNDROP_URL
from .context import _provider_corpus, _providers_from_active_config
from .context import build_as_reputation_context
from .corpus import _format_asn, _merge_reputation_entries, _merge_sources
from .corpus import _normalize_asn, normalize_reputation_corpus
from .evidence import _external_reputation_point, _source_is_authoritative
from .evidence import reputation_evidence_profile
from .providers import AsReputationProvider, LocalAsReputationOverrideProvider
from .providers import SpamhausAsnDropProvider, _dict_items, _iter_snapshot_records
from .providers import _keyed_snapshot_records, _read_structured_file, _record_asns

__all__ = [
    "AUTHORITATIVE_SOURCE_TYPES",
    "AsReputationProvider",
    "LABEL_DISPLAY",
    "LocalAsReputationOverrideProvider",
    "QUALIFYING_SOURCE_TYPES",
    "SPAMHAUS_ASNDROP_URL",
    "SpamhausAsnDropProvider",
    "_dict_items",
    "_external_reputation_point",
    "_format_asn",
    "_iter_snapshot_records",
    "_keyed_snapshot_records",
    "_merge_reputation_entries",
    "_merge_sources",
    "_normalize_asn",
    "_observed_asn_behavior",
    "_provider_corpus",
    "_providers_from_active_config",
    "_ranking_rows_by_asn",
    "_read_structured_file",
    "_record_asns",
    "_source_is_authoritative",
    "_target_asn",
    "build_as_reputation_context",
    "normalize_reputation_corpus",
    "observed_asns",
    "reputation_evidence_profile",
]
