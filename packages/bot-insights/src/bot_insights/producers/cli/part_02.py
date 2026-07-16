from __future__ import annotations

from ._shared import *
from .part_01 import *

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bot-insights-report",
        description="Generate Bot Insights reports from Hydrolix summary data via local artifacts.",
    )
    parser.add_argument(
        "--cluster", required=True, help="Hydrolix cluster alias or .env file path."
    )
    parser.add_argument(
        "--database", default="akamai", help="Hydrolix database/project."
    )
    parser.add_argument(
        "--report",
        choices=[
            "executive_posture",
            "control_review",
            "scorecard_brief",
            "soc_triage",
            "crawler_governance",
            "edge_ops_impact",
        ],
        default="executive_posture",
        help="Report type to generate.",
    )
    parser.add_argument(
        "--mode",
        choices=("report", "evidence", "template"),
        default="report",
        help="Output a deterministic report, an LLM evidence packet, or a Markdown template scaffold.",
    )
    parser.add_argument(
        "--start", required=True, help="Inclusive ISO-8601 current-window start."
    )
    parser.add_argument(
        "--end", required=True, help="Exclusive ISO-8601 current-window end."
    )
    parser.add_argument(
        "--baseline-start",
        help="Inclusive ISO-8601 baseline start. Defaults to the equal-length previous window.",
    )
    parser.add_argument(
        "--baseline-end",
        help="Exclusive ISO-8601 baseline end. Defaults to --start for legacy windows.",
    )
    parser.add_argument(
        "--sample-dir",
        help="Directory for intermediate local JSON. Defaults to ~/src/sample-data/bot-insights/1.1/<cluster>.",
    )
    parser.add_argument(
        "--output", required=True, help="Output path for the selected mode."
    )
    parser.add_argument(
        "--raw-input",
        help="Resume from a saved Hydrolix MCP or ClickHouse JSON result instead of running capture.",
    )
    parser.add_argument(
        "--raw-path-input",
        type=str,
        default=None,
        help="Resume edge_ops_impact from a saved path-grain JSON result alongside --raw-input.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="html",
        help="Rendered report format.",
    )
    parser.add_argument("--title", help="Optional rendered report title.")
    parser.add_argument(
        "--policy-id", help="Optional SIEM policyId filter for control_review."
    )
    parser.add_argument(
        "--control-source",
        choices=("siem-policy", "posture"),
        default="siem-policy",
        help="Summary surface for control_review evidence.",
    )
    parser.add_argument(
        "--change-time",
        help="Optional control change timestamp. Defaults to --start for control_review.",
    )
    parser.add_argument(
        "--entity-type",
        choices=tuple(SCORECARD_ENTITY_SQL),
        default="request_host",
        help="Entity type to score for scorecard_brief.",
    )
    parser.add_argument(
        "--entity-value",
        help="Optional explicit entity value to render for scorecard_brief. Defaults to top-ranked scorecard entity.",
    )
    parser.add_argument(
        "--fleet",
        action="store_true",
        default=False,
        help=(
            "Render scorecard_brief as a fleet (multi-entity) view "
            "instead of collapsing to a single entity. The default "
            "(no flag, no --entity-value) selects the top-ranked "
            "entity and the engine auto-promotes to "
            "scorecard_entity_review for that one host. --fleet "
            "keeps every ranked scorecard in the wrapper so the "
            "report renders as scorecard_brief with the queue table, "
            "triage strip, and coverage detail; --mode evidence with "
            "--fleet also emits a fleet-shaped packet (band "
            "distribution, rule trigger counts across hosts, top "
            "entities) instead of the single-entity packet shape, so "
            "the LLM's interpretation prose matches the rendered "
            "framing. Only valid for --report scorecard_brief."
        ),
    )
    parser.add_argument(
        "--scorecard-limit",
        type=int,
        default=20,
        help="Maximum aggregate rows/scorecards to keep for scorecard_brief.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Optional hostname filter for edge_ops_impact path-grain query (scopes path candidates to a single request_host).",
    )
    parser.add_argument(
        "--include-paths",
        action="store_true",
        default=False,
        help=(
            "Opt in to the edge_ops_impact path-grain capture against "
            "bot_agg_path_<granularity>. This table is not currently "
            "deployed on any production cluster, so the path-grain query "
            "is off by default; enabling it falls back gracefully when "
            "the table is missing."
        ),
    )
    parser.add_argument(
        "--domains",
        help="Optional comma-separated scorecard domains to evaluate.",
    )
    parser.add_argument(
        "--asn",
        default=None,
        help="Optional client ASN scope filter for incident_report.",
    )
    parser.add_argument(
        "--path-pattern",
        default=None,
        help=(
            "Optional path-pattern scope filter for incident_report "
            "(requestPathPattern bucket for summary queries; SQL LIKE for "
            "raw drilldown)."
        ),
    )
    parser.add_argument(
        "--analyst-notes",
        help="LLM interpretation prose to include in the final report wrapper.",
    )
    parser.add_argument(
        "--analyst-notes-file",
        help="Read LLM interpretation prose from a file for the final report wrapper.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a threshold-override file (YAML/TOML/JSON). Overlays onto "
            "the dataclass defaults defined in scripts/config.py; any key "
            "omitted falls through to its default. See "
            "skills/bot-insights/config/defaults.yaml for the full tunable "
            "surface."
        ),
    )
    return parser.parse_args()

__all__ = [name for name in globals() if not name.startswith("__")]
