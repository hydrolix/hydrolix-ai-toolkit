from __future__ import annotations

import re


TIME_PREDICATE_RE = re.compile(
    r"(?:\b(?:timestamp|reqTimeSec)\b|`toStartOf(?:Minute|Hour|Day)\(reqTimeSec\)`)\s*(?:=|!=|<>|>=|<=|>|<|BETWEEN|IN)(?:\s|\(|'|$)",
    re.IGNORECASE,
)


FORMAT_RE = re.compile(r"\bFORMAT\s+\w+\b", re.IGNORECASE)


PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}|\$\{[^}]+\}")


SENTINEL_ENV = "BOT_INSIGHTS_CAPTURE_OP_RUN"


CLUSTER_DIR_ENV = ("BOT_INSIGHTS_CLUSTER_DIR", "HYDROLIX_CLUSTER_DIR", "HDX_CLUSTER_DIR")


NEEDS_MCP_EXIT = 42


HANDOFF_SCHEMA = "bot_hydrolix_mcp_query_request.v1"


PRESET_CHOICES = (
    "posture-overview",
    "posture-by-asn",
    "posture-by-path",
    "siem-policy",
)
