"""Deterministic Bot Insights attribution report from trusted aggregate JSON.

This package does not query Hydrolix. It renders the attribution SQL template,
validates trusted-context evidence, normalizes aggregate rows, and derives
mover/displacement attribution with a canonical result digest. Hydrolix does the
filtering, grouping, and aggregation.
"""

from __future__ import annotations

from .cli import main, parse_args
from .errors import InvalidInputError
from .fingerprint import metadata_fingerprint
from .normalize import normalize_input_rows, result_digest_v1
from .report import normalize_attribution
from .sql import metadata_column_aliases
from .sql_template import render_attribution_sql_template
from .summary_tables import SUMMARY_TABLE_CATALOG, validate_summary_table_support

__all__ = [
    "InvalidInputError",
    "SUMMARY_TABLE_CATALOG",
    "main",
    "metadata_column_aliases",
    "metadata_fingerprint",
    "normalize_attribution",
    "normalize_input_rows",
    "parse_args",
    "render_attribution_sql_template",
    "result_digest_v1",
    "validate_summary_table_support",
]
