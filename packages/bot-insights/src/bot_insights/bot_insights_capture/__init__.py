"""Capture vetted Bot Insights Hydrolix query JSON or emit an MCP handoff.

Query execution, credential resolution, and SQL vetting delegate to
``reportkit.extract.hydrolix``; this package adds the Bot Insights preset SQL,
time-window handling, and CLI. It re-execs under ``op run`` when a cluster .env
references 1Password secrets.
"""

from __future__ import annotations

import os
import shutil

from reportkit.extract import hydrolix as hdx

from .cli import main
from .constants import NEEDS_MCP_EXIT, SENTINEL_ENV
from .hydrolix_bridge import (
    QueryConfig,
    build_query_config,
    credential_state,
    ensure_format_json,
    merged_environment,
    normalize_query_url,
    parse_env_file,
    query_hydrolix,
    reject_invalid_sql,
    shape_output,
    should_reexec_with_op,
)
from .query import build_handoff_packet, render_preset_sql

__all__ = [
    "NEEDS_MCP_EXIT",
    "QueryConfig",
    "SENTINEL_ENV",
    "build_handoff_packet",
    "build_query_config",
    "credential_state",
    "ensure_format_json",
    "hdx",
    "main",
    "merged_environment",
    "normalize_query_url",
    "os",
    "parse_env_file",
    "query_hydrolix",
    "reject_invalid_sql",
    "render_preset_sql",
    "shape_output",
    "should_reexec_with_op",
    "shutil",
]
