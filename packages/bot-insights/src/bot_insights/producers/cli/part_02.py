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
        choices=(
            "executive_posture",
            "control_review",
            "scorecard_brief",
            "soc_triage",
            "crawler_governance",
            "edge_ops_impact",
            "incident_report",
            "threat_hunt",
        ),
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
        "--incident-view",
        choices=(
            "analyst",
            "executive",
            "soc_action_packet",
            "edge_platform_brief",
            "detection_engineering",
        ),
        default="analyst",
        help=(
            "Incident-only render audience. Changes the wrapper report_type "
            "and template only; evidence capture semantics are unchanged."
        ),
    )
    parser.add_argument(
        "--fields",
        default=None,
        help=(
            "Comma-separated akamai.logs column names to rank in the "
            "incident_report actors section. Default: "
            f"{_INCIDENT_DEFAULT_FIELDS}."
        ),
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Top-N row cap for incident_report queries or threat_hunt tables.",
    )
    parser.add_argument(
        "--summary-parquet-glob",
        help="Local summary parquet glob for threat_hunt. JSON/CSV rows are also accepted for fixtures.",
    )
    parser.add_argument(
        "--raw-actor-dir",
        help="Directory containing threat_hunt raw actor JSON exports.",
    )
    parser.add_argument(
        "--raw-actor-chunk-seconds",
        type=int,
        default=3600,
        help=(
            "Maximum seconds per raw-log actor export query when --raw-actor-dir "
            "is omitted. Smaller chunks reduce Hydrolix memory pressure."
        ),
    )
    parser.add_argument(
        "--raw-actor-extraction-mode",
        choices=("topk", "hash"),
        default="topk",
        help=(
            "Raw actor extraction strategy when --raw-actor-dir is omitted. "
            "topk is the fast bounded default; hash is exact hash-bucket "
            "chunking for diagnostics and reproduction."
        ),
    )
    parser.add_argument(
        "--raw-actor-hash-buckets",
        type=int,
        default=16,
        help=(
            "Number of deterministic hash buckets per client_ip raw actor time "
            "chunk when --raw-actor-dir is omitted. user_agent exports remain "
            "time-only by default. Higher values reduce GROUP BY memory pressure "
            "at the cost of more queries."
        ),
    )
    parser.add_argument(
        "--raw-actor-topk-candidate-multiplier",
        type=int,
        default=5,
        help=(
            "Candidate multiplier for --raw-actor-extraction-mode topk. "
            "The producer computes exact metrics for topK(top_n * multiplier) "
            "candidate actors per time chunk."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-bytes-column",
        help=(
            "Optional akamai.logs column to sum as Hydrolix log ingest bytes "
            "for threat_hunt raw actor exports. When omitted, the ingest lane "
            "is rendered as unavailable instead of inferred from response or "
            "CDN-billed bytes."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-in",
        help=(
            "Optional local hydro.logs usagemeter JSON/CSV artifact for threat_hunt "
            "Hydrolix ingest estimates."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-project-deployment-id",
        help=(
            "Project deployment id used to export hydro.logs usagemeter rows, "
            "for example expediagroup__akamai."
        ),
    )
    parser.add_argument(
        "--hydrolix-log-ingest-usagemeter-table-name",
        default="logs",
        help="hydro.logs table_name value for the raw customer log table. Default: logs.",
    )
    parser.add_argument(
        "--impact-lane-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt raw-log impact lane behavior. auto exports raw-log "
            "response-body and Akamai-billed totals when possible, off skips "
            "lane merging, required fails if supplied or exported lane rows "
            "are unavailable."
        ),
    )
    parser.add_argument(
        "--impact-lane-totals-in",
        help=(
            "Optional saved total-window impact lane rows for threat_hunt "
            "(current_total, baseline_total)."
        ),
    )
    parser.add_argument(
        "--impact-lane-scoped-hunt-in",
        help=(
            "Optional saved high/partial-confidence Hunt Impact lane rows for "
            "threat_hunt (current_high_partial, baseline_high_partial)."
        ),
    )
    parser.add_argument(
        "--geoip-asn-v4",
        help="Optional threat_hunt IPv4 GeoIP/ASN JSON or CSV enrichment file.",
    )
    parser.add_argument(
        "--geoip-asn-v6",
        help="Optional threat_hunt IPv6 GeoIP/ASN JSON or CSV enrichment file.",
    )
    parser.add_argument(
        "--cooccurrence-in",
        help="Optional threat_hunt UA/IP cooccurrence JSON or CSV artifact.",
    )
    parser.add_argument(
        "--cooccurrence-path-in",
        help="Optional threat_hunt UA/IP/path cooccurrence JSON or CSV artifact.",
    )
    parser.add_argument(
        "--scraper-drilldown-in",
        help=(
            "Optional bounded threat_hunt scraper drilldown JSON or CSV artifact "
            "(user_agent, client_ip, request_path, hour, country, status_429, status_5xx, requests)."
        ),
    )
    parser.add_argument(
        "--scraper-hourly-in",
        help=(
            "Optional complete threat_hunt scraper hourly JSON or CSV artifact "
            "(user_agent, hour, requests). Used for coverage-aware hourly timing."
        ),
    )
    parser.add_argument(
        "--fanout-in",
        help=(
            "Optional source-aware threat_hunt per-UA fan-out artifact "
            "(user_agent, unique_ips, hits, bytes, source, probe_window_hours)."
        ),
    )
    parser.add_argument(
        "--fanout-strategy",
        choices=("auto", "summary_hour", "logs_probe", "skip"),
        default="auto",
        help=(
            "Threat-hunt fan-out enrichment strategy. auto tries summary_hour, "
            "then logs_probe, then cooccurrence lower-bound fallback."
        ),
    )
    parser.add_argument(
        "--ua-fanout-in",
        dest="ua_fanout_in",
        help=(
            "Backward-compatible alias for --fanout-in. Accepts legacy "
            "(user_agent, unique_client_ips, requests) rows."
        ),
    )
    parser.add_argument(
        "--ua-fanout-query",
        choices=("auto", "off", "required", "summary_hour", "logs_probe", "skip"),
        default="auto",
        help=(
            "Backward-compatible alias for --fanout-strategy. off maps to skip; "
            "required keeps legacy fail-if-missing behavior."
        ),
    )
    parser.add_argument(
        "--iat-sample-in",
        help=(
            "Optional bounded threat_hunt request-level timing sample JSON or CSV artifact "
            "(user_agent, client_ip, timestamp or reqTimeSec; optional request_path, status_code, response_time_ms)."
        ),
    )
    parser.add_argument(
        "--background-ua-sample-in",
        help=(
            "Optional threat_hunt mid-volume organic UA background sample JSON or CSV artifact "
            "used to estimate evidence-family background rates."
        ),
    )
    parser.add_argument(
        "--background-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt background UA sample behavior. auto exports a bounded "
            "sample when possible, off skips it, required fails if unavailable."
        ),
    )
    parser.add_argument(
        "--baseline-ua-timeseries-in",
        help=(
            "Optional threat_hunt per-UA baseline bucket JSON or CSV artifact "
            "(user_agent, bucket, requests) for z-score significance."
        ),
    )
    parser.add_argument(
        "--baseline-significance-query",
        choices=("auto", "off", "required"),
        default="auto",
        help=(
            "Threat-hunt per-UA baseline bucket query behavior. auto exports "
            "selected-lead buckets when possible, off skips it, required fails if unavailable."
        ),
    )
    parser.add_argument(
        "--edge-response-in",
        help="Optional threat_hunt edge/Bot/SIEM coverage JSON or CSV artifact.",
    )
    parser.add_argument(
        "--bot-manager-context-in",
        help=(
            "Optional aggregate threat_hunt Bot Manager context JSON or CSV artifact "
            "from bi_siem_policy_summary_* rows. Display-only enrichment."
        ),
    )
    parser.add_argument(
        "--bot-manager-siem-summary-in",
        dest="bot_manager_context_in",
        help=(
            "Alias for --bot-manager-context-in. Accepts aggregate "
            "bi_siem_policy_summary_* context rows."
        ),
    )
    parser.add_argument(
        "--bot-manager-exact-ua-in",
        help=(
            "Optional exact-UA Bot Manager or edge export JSON or CSV artifact. "
            "Rows are attached only to matching user_agent values for display."
        ),
    )
    parser.add_argument(
        "--cost-estimate-config",
        help=(
            "Optional threat_hunt JSON cost assumptions file. When enabled, "
            "adds CDN egress low/high estimates derived from observed bytes."
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
