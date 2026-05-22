"""argparse setup + main() dispatch for ``bot_insights_report``.

This module is the script's CLI surface. The original
``bot_insights_report.py`` is now a 60-line shim that re-exports
everything here under its historical name.

Layout:
  - ``parse_args``: argparse setup, ~175 lines. Every report-type-
    specific flag (``--policy-id`` for control_review,
    ``--entity-type`` for the scorecard family, ``--top-n`` /
    ``--fields`` / ``--host`` / ``--asn`` / ``--path-pattern`` /
    ``--grafana-hostname`` / ``--grafana-dashboard-path`` for
    incident_report, etc.) lives here.
  - ``main``: validates the parsed args, picks the right SQL +
    table + evidence builder per ``--report``, runs capture, and
    branches to either evidence-packet emission (``--mode evidence``)
    or the renderer (``--mode html`` / ``--mode markdown``). The
    incident_report flow is dispatched whole to
    ``producers.orchestrators.incident_report._run_incident_report``;
    the other report types stay inline (Phase 2.6 deferred per-
    report orchestrator extraction to a follow-up so the dispatch
    rewiring doesn't entangle with the rest of Phase 2).

Document the full CC + ≤500-line guideline deviations for this
module in the verification commit; both apply because ``main`` is
~700 lines and CC-monster until per-report orchestrator extraction
lands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from producers.evidence.control import build_control_evidence_packet
from producers.evidence.incident import _INCIDENT_DEFAULT_FIELDS
from producers.evidence.labeling import humanize_evidence_packet
from producers.evidence.posture import build_evidence_packet
from producers.evidence.scorecard import (
    build_scorecard_evidence_packet,
    build_scorecard_fleet_evidence_packet,
    select_scorecard,
)
from producers.formatting import choose_granularity, parse_time
from producers.orchestrators.incident_report import _run_incident_report
from producers.runtime import (
    CAPTURE,
    DEFAULT_SAMPLE_ROOT,
    HANDOFF_SCHEMA,
    NEEDS_MCP_EXIT,
    PUBLIC_SKILLS,
    load_raw_query_result,
    run,
)
from producers.rendering import render_report_command
from producers.threat_hunt import (
    build_threat_hunt_artifact,
    export_background_ua_sample,
    export_baseline_ua_timeseries,
    export_fanout_enrichment,
    export_hydrolix_usagemeter_ingest_estimate,
    export_raw_actor_fixtures,
)
from producers.sql.control_review import (
    control_review_sql,
    control_review_timeseries_sql,
)
from producers.sql.executive_posture import executive_posture_sql
from producers.sql.scorecard import (
    CRAWLER_ENTITY_SQL,
    EDGE_OPS_ENTITY_SQL,
    SCORECARD_ENTITY_SQL,
    SOC_ENTITY_SQL,
    cache_origin_path_sql,
    scorecard_crawler_sql,
    scorecard_edge_ops_sql,
    scorecard_soc_sql,
    scorecard_sql,
)
from producers.wrapper import (
    add_control_metadata,
    add_report_metadata,
    add_scorecard_metadata,
    analyst_note_from_args,
    build_report_wrapper,
    build_timeseries_artifact,
    render_template_packet,
)


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


def main() -> int:
    # Late-bind ``run`` through the ``bot_insights_report`` shim so tests
    # that patch ``mock.patch.object(bot_insights_report, "run", ...)``
    # intercept the capture subprocess calls below. Module-level
    # ``from producers.runtime import run`` would bind to the unpatched
    # function once and miss the patch entirely.
    import bot_insights_report as _bir
    run = _bir.run
    load_raw_query_result = _bir.load_raw_query_result

    args = parse_args()
    # Prime the active-thresholds singleton from --config so renderer-side
    # display caps and risk-score bands honor the override when the
    # producer drives both capture and render in one process.
    from config import load_thresholds, set_active_thresholds

    set_active_thresholds(load_thresholds(args.config))
    start = parse_time(args.start, "start")
    end = parse_time(args.end, "end")
    window = end - start
    if args.baseline_start:
        baseline_start = parse_time(args.baseline_start, "baseline-start")
    else:
        baseline_start = start - window
    if args.baseline_end:
        baseline_end = parse_time(args.baseline_end, "baseline-end")
    else:
        baseline_end = start
    if baseline_start >= baseline_end:
        raise SystemExit("--baseline-start must be earlier than --baseline-end")
    if baseline_end > start:
        raise SystemExit("--baseline-end must be earlier than or equal to --start")
    if baseline_end - baseline_start != window:
        raise SystemExit("--baseline window must match the current window duration")
    if args.baseline_end and args.report not in {"incident_report", "threat_hunt"}:
        raise SystemExit("--baseline-end is only supported with --report incident_report or --report threat_hunt.")
    if args.scorecard_limit < 0:
        raise SystemExit("--scorecard-limit must be zero or a positive integer.")
    scorecard_reports = {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }
    if args.report not in scorecard_reports and args.entity_value:
        raise SystemExit(
            "--entity-value is only supported with --report scorecard_brief, --report soc_triage, "
            "--report crawler_governance, or --report edge_ops_impact."
        )
    if args.fleet and args.report != "scorecard_brief":
        raise SystemExit(
            "--fleet is only supported with --report scorecard_brief; "
            "soc_triage, crawler_governance, and edge_ops_impact "
            "already render multi-entity views by default."
        )
    if args.fleet and args.entity_value:
        raise SystemExit(
            "--fleet and --entity-value are mutually exclusive: "
            "--fleet renders every emitted scorecard, while "
            "--entity-value pins to one specific entity."
        )
    if args.report == "soc_triage" and args.entity_type not in SOC_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for soc_triage; use one of "
            + ", ".join(sorted(SOC_ENTITY_SQL))
        )
    if (
        args.report == "crawler_governance"
        and args.entity_type not in CRAWLER_ENTITY_SQL
    ):
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for crawler_governance; use one of "
            + ", ".join(sorted(CRAWLER_ENTITY_SQL))
        )
    if args.report == "edge_ops_impact" and args.entity_type not in EDGE_OPS_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for edge_ops_impact; use one of "
            + ", ".join(sorted(EDGE_OPS_ENTITY_SQL))
        )
    if args.raw_path_input and not args.raw_input:
        raise SystemExit(
            "--raw-path-input requires --raw-input to also be supplied "
            "(both raw inputs must be provided to resume an edge_ops_impact run)."
        )
    if args.raw_path_input and args.report != "edge_ops_impact":
        raise SystemExit(
            "--raw-path-input is only valid with --report edge_ops_impact."
        )
    if args.report == "soc_triage" and not args.domains:
        # SOC scorecards must evaluate only the security_evidence domain so
        # crawler/Edge/Ops features do not surface as missing SOC evidence.
        args.domains = "security_evidence"
    if args.report == "crawler_governance" and not args.domains:
        # Crawler governance scorecards must evaluate only the
        # crawler_governance domain so SOC/Edge features do not surface as
        # missing crawler evidence.
        args.domains = "crawler_governance"
    if args.report == "edge_ops_impact" and not args.domains:
        # Edge/Ops scorecards evaluate cache_busting and origin_impact domains
        # so SOC/crawler features do not surface as missing edge evidence.
        args.domains = "cache_busting,origin_impact"
    if args.report != "incident_report" and args.incident_view != "analyst":
        raise SystemExit("--incident-view is only supported with --report incident_report.")
    if args.report == "threat_hunt" and not args.summary_parquet_glob:
        raise SystemExit("--report threat_hunt requires --summary-parquet-glob.")
    if args.report != "threat_hunt":
        local_flags = {
            "--summary-parquet-glob": args.summary_parquet_glob,
            "--raw-actor-dir": args.raw_actor_dir,
            "--hydrolix-log-ingest-bytes-column": args.hydrolix_log_ingest_bytes_column,
            "--hydrolix-log-ingest-usagemeter-in": args.hydrolix_log_ingest_usagemeter_in,
            "--hydrolix-log-ingest-usagemeter-project-deployment-id": args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            "--geoip-asn-v4": args.geoip_asn_v4,
            "--geoip-asn-v6": args.geoip_asn_v6,
            "--cooccurrence-in": args.cooccurrence_in,
            "--cooccurrence-path-in": args.cooccurrence_path_in,
            "--scraper-drilldown-in": args.scraper_drilldown_in,
            "--scraper-hourly-in": args.scraper_hourly_in,
            "--fanout-in": args.fanout_in,
            "--ua-fanout-in": args.ua_fanout_in,
            "--iat-sample-in": args.iat_sample_in,
            "--background-ua-sample-in": args.background_ua_sample_in,
            "--baseline-ua-timeseries-in": args.baseline_ua_timeseries_in,
            "--edge-response-in": args.edge_response_in,
            "--bot-manager-context-in": args.bot_manager_context_in,
            "--bot-manager-exact-ua-in": args.bot_manager_exact_ua_in,
            "--cost-estimate-config": args.cost_estimate_config,
        }
        supplied = [flag for flag, value in local_flags.items() if value]
        if supplied:
            raise SystemExit(
                ", ".join(supplied) + " are only supported with --report threat_hunt."
            )

    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir
        else DEFAULT_SAMPLE_ROOT / args.cluster
    )
    sample_dir.mkdir(parents=True, exist_ok=True)

    if args.report == "incident_report":
        incident_report_types = {
            "analyst": "incident_report",
            "executive": "incident_executive_view",
            "soc_action_packet": "incident_soc_action_packet",
            "edge_platform_brief": "incident_edge_platform_brief",
            "detection_engineering": "incident_detection_engineering",
        }
        args.incident_report_type = incident_report_types[args.incident_view]
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        return _run_incident_report(
            args,
            start,
            end,
            baseline_start,
            baseline_end,
            sample_dir,
            output_path,
        )

    if args.report == "threat_hunt":
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path = sample_dir / "threat_hunt-artifact.json"
        wrapper_path = sample_dir / "threat_hunt-wrapper.json"
        raw_actor_dir = args.raw_actor_dir
        if raw_actor_dir is None:
            raw_actor_dir = str(sample_dir / "threat_hunt-actors")
            export_raw_actor_fixtures(
                actor_dir=raw_actor_dir,
                start=args.start,
                end=args.end,
                baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                cluster=args.cluster,
                database=args.database,
                top_n=args.top_n,
                hydrolix_log_ingest_bytes_column=args.hydrolix_log_ingest_bytes_column,
                chunk_seconds=args.raw_actor_chunk_seconds,
                extraction_mode=args.raw_actor_extraction_mode,
                hash_buckets=args.raw_actor_hash_buckets,
                topk_candidate_multiplier=args.raw_actor_topk_candidate_multiplier,
            )
        hydrolix_log_ingest_usagemeter_in = args.hydrolix_log_ingest_usagemeter_in
        if (
            hydrolix_log_ingest_usagemeter_in is None
            and args.hydrolix_log_ingest_usagemeter_project_deployment_id
        ):
            usagemeter_path = sample_dir / "threat_hunt-hydrolix-usagemeter.json"
            export_hydrolix_usagemeter_ingest_estimate(
                output=str(usagemeter_path),
                start=args.start,
                end=args.end,
                cluster=args.cluster,
                project_deployment_id=args.hydrolix_log_ingest_usagemeter_project_deployment_id,
                table_name=args.hydrolix_log_ingest_usagemeter_table_name,
            )
            hydrolix_log_ingest_usagemeter_in = str(usagemeter_path)
        fanout_strategy = args.fanout_strategy
        if args.ua_fanout_query in {"summary_hour", "logs_probe", "skip"}:
            fanout_strategy = args.ua_fanout_query
        elif args.ua_fanout_query == "off":
            fanout_strategy = "skip"
        fanout_in = args.fanout_in or args.ua_fanout_in
        if fanout_in is None and fanout_strategy != "skip":
            fanout_path = sample_dir / "threat_hunt-fanout.json"
            try:
                export_fanout_enrichment(
                    actor_dir=raw_actor_dir,
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    top_leads=args.top_n,
                    output=str(fanout_path),
                    strategy=fanout_strategy,
                    scraper_hourly_in=args.scraper_hourly_in,
                    cooccurrence_in=args.cooccurrence_in,
                )
                fanout_in = str(fanout_path)
            except SystemExit:
                if args.ua_fanout_query == "required":
                    raise
                print(
                    "WARNING: source-aware fanout enrichment unavailable; falling back to supplied cooccurrence lower-bound counts.",
                    file=sys.stderr,
                )
        elif fanout_in is None and fanout_strategy == "skip" and args.cooccurrence_in:
            fanout_path = sample_dir / "threat_hunt-fanout.json"
            export_fanout_enrichment(
                actor_dir=raw_actor_dir,
                start=args.start,
                end=args.end,
                cluster=args.cluster,
                database=args.database,
                top_leads=args.top_n,
                output=str(fanout_path),
                strategy="skip",
                cooccurrence_in=args.cooccurrence_in,
            )
            fanout_in = str(fanout_path)
        selected_user_agents: list[str] = []
        current_ua_path = Path(raw_actor_dir) / "expedia-actors-current-user_agent.json"
        if current_ua_path.exists():
            try:
                rows = json.loads(current_ua_path.read_text(encoding="utf-8"))
                if isinstance(rows, list):
                    rows = sorted(
                        [row for row in rows if isinstance(row, dict)],
                        key=lambda row: (-float(row.get("requests") or 0), str(row.get("user_agent") or row.get("value") or "")),
                    )
                    selected_user_agents = [
                        str(row.get("user_agent") or row.get("value"))
                        for row in rows[: args.top_n]
                        if row.get("user_agent") or row.get("value")
                    ]
            except (OSError, ValueError, TypeError):
                selected_user_agents = []
        background_ua_sample_in = args.background_ua_sample_in
        if background_ua_sample_in is None and args.background_query in {"auto", "required"}:
            background_path = sample_dir / "threat_hunt-background-ua-sample.json"
            try:
                export_background_ua_sample(
                    start=args.start,
                    end=args.end,
                    cluster=args.cluster,
                    database=args.database,
                    excluded_user_agents=selected_user_agents,
                    output=str(background_path),
                )
                background_ua_sample_in = str(background_path)
            except SystemExit:
                if args.background_query == "required":
                    raise
                print(
                    "WARNING: background UA sample query unavailable; confidence background rates marked unavailable.",
                    file=sys.stderr,
                )
        baseline_ua_timeseries_in = args.baseline_ua_timeseries_in
        if baseline_ua_timeseries_in is None and args.baseline_significance_query in {"auto", "required"}:
            baseline_ua_path = sample_dir / "threat_hunt-baseline-ua-timeseries.json"
            try:
                export_baseline_ua_timeseries(
                    baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
                    baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
                    user_agents=selected_user_agents,
                    cluster=args.cluster,
                    database=args.database,
                    output=str(baseline_ua_path),
                    granularity="hour" if (end - baseline_start).total_seconds() <= 172800 else "day",
                )
                baseline_ua_timeseries_in = str(baseline_ua_path)
            except SystemExit:
                if args.baseline_significance_query == "required":
                    raise
                print(
                    "WARNING: baseline UA timeseries query unavailable; baseline z-scores marked unavailable.",
                    file=sys.stderr,
                )
        artifact = build_threat_hunt_artifact(
            cluster=args.cluster,
            database=args.database,
            summary_parquet_glob=args.summary_parquet_glob,
            start=args.start,
            end=args.end,
            baseline_start=baseline_start.isoformat().replace("+00:00", "Z"),
            baseline_end=baseline_end.isoformat().replace("+00:00", "Z"),
            raw_actor_dir=raw_actor_dir,
            top_n=args.top_n,
            geoip_asn_v4=args.geoip_asn_v4,
            geoip_asn_v6=args.geoip_asn_v6,
            cooccurrence_in=args.cooccurrence_in,
            cooccurrence_path_in=args.cooccurrence_path_in,
            scraper_drilldown_in=args.scraper_drilldown_in,
            scraper_hourly_in=args.scraper_hourly_in,
            fanout_in=fanout_in,
            fanout_strategy=fanout_strategy,
            ua_fanout_in=args.ua_fanout_in,
            ua_fanout_query=args.ua_fanout_query,
            iat_sample_in=args.iat_sample_in,
            background_ua_sample_in=background_ua_sample_in,
            background_query=args.background_query,
            baseline_ua_timeseries_in=baseline_ua_timeseries_in,
            baseline_significance_query=args.baseline_significance_query,
            edge_response_in=args.edge_response_in,
            bot_manager_context_in=args.bot_manager_context_in,
            bot_manager_exact_ua_in=args.bot_manager_exact_ua_in,
            cost_estimate_config=args.cost_estimate_config,
            hydrolix_log_ingest_usagemeter_in=hydrolix_log_ingest_usagemeter_in,
            hydrolix_log_ingest_project_deployment_id=args.hydrolix_log_ingest_usagemeter_project_deployment_id,
            hydrolix_log_ingest_table_name=args.hydrolix_log_ingest_usagemeter_table_name,
        )
        artifact_path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if args.mode == "evidence":
            output_path.write_text(
                json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.mode == "template":
            output_path.write_text(
                "# Threat Hunt Interpretation\n\n"
                "Summarize only the deterministic evidence in this artifact. "
                "Do not claim malicious intent, operator identity, or cross-customer reuse.\n",
                encoding="utf-8",
            )
        else:
            wrapper = build_report_wrapper(
                args=args,
                artifacts=[artifact],
                analyst_note=analyst_note_from_args(args),
            )
            wrapper_path.write_text(
                json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            run(
                render_report_command(
                    wrapper_path=wrapper_path,
                    output_path=output_path,
                    output_format=args.format,
                    config_path=args.config,
                    title=args.title,
                ),
                cwd=PUBLIC_SKILLS,
            )
        print(
            json.dumps(
                {
                    "artifact": str(artifact_path),
                    "cluster": args.cluster,
                    "database": args.database,
                    "mode": args.mode,
                    "output": str(output_path),
                    "raw_actor_dir": raw_actor_dir,
                    "rows": len(artifact.get("endpoints") or []),
                    "table_used": "local_summary_parquet",
                },
                sort_keys=True,
            )
        )
        return 0

    raw_path = sample_dir / f"{args.report}-raw.json"
    artifact_path = sample_dir / f"{args.report}-artifact.json"
    timeseries_raw_path = sample_dir / f"{args.report}-timeseries-raw.json"
    timeseries_artifact_path = sample_dir / f"{args.report}-timeseries.json"
    path_raw_path = sample_dir / f"{args.report}-path-raw.json"
    path_artifact_path = sample_dir / f"{args.report}-path-artifact.json"
    wrapper_path = sample_dir / f"{args.report}-wrapper.json"
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.report == "executive_posture":
        sql = executive_posture_sql(args.database, start, end, baseline_start)
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = "posture"
    elif args.report == "control_review":
        sql = control_review_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.policy_id,
            args.control_source,
        )
        granularity = choose_granularity(start, end)
        if args.control_source == "posture":
            table_used = f"{args.database}.bi_summary_{granularity}"
        else:
            table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = "control"
    elif args.report == "scorecard_brief":
        sql = scorecard_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "soc_triage":
        sql = scorecard_soc_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_siem_policy_summary_{granularity}"
        compare_schema = None
    elif args.report == "crawler_governance":
        sql = scorecard_crawler_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    elif args.report == "edge_ops_impact":
        sql = scorecard_edge_ops_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
        )
        granularity = choose_granularity(start, end)
        table_used = f"{args.database}.bi_summary_{granularity}"
        compare_schema = None
    else:
        raise AssertionError(args.report)

    capture_summary: dict[str, object] = {"rows": None}
    raw_timeseries_value: dict | None = None
    raw_path_value: dict | None = None
    if args.raw_input:
        raw_value = load_raw_query_result(Path(args.raw_input).expanduser().resolve())
        if args.report == "control_review" and timeseries_raw_path.exists():
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact":
            if args.raw_path_input:
                raw_path_value = load_raw_query_result(
                    Path(args.raw_path_input).expanduser().resolve()
                )
            elif args.include_paths:
                print(
                    "WARNING: --raw-path-input not supplied for edge_ops_impact; "
                    "path-grain artifact will be omitted.",
                    file=sys.stderr,
                )
    else:
        try:
            capture_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    sql,
                    "--output",
                    str(raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
        except SystemExit as exc:
            # SOC triage depends on bi_siem_policy_summary_<granularity>,
            # which is not deployed on every cluster. Without SIEM data the
            # script cannot produce a SOC report, so warn clearly and exit
            # cleanly rather than crash with a raw capture traceback.
            if args.report == "soc_triage":
                print(
                    "WARNING: SOC capture failed; "
                    f"{table_used} may not be deployed on this cluster ({exc}). "
                    "soc_triage requires SIEM policy summary data; skipping report.",
                    file=sys.stderr,
                )
                return 0
            raise
        try:
            capture_summary = json.loads(capture_summary_text)
        except json.JSONDecodeError as exc:
            raise SystemExit("Capture did not return machine-readable JSON.") from exc
        if (
            isinstance(capture_summary, dict)
            and capture_summary.get("schema_version") == HANDOFF_SCHEMA
        ):
            report_context = capture_summary.get("report_context")
            if not isinstance(report_context, dict):
                report_context = {}
            report_context.update(
                {
                    "report": args.report,
                    "mode": args.mode,
                    "start": args.start,
                    "end": args.end,
                    "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
                    "table_used": table_used,
                    "granularity": granularity,
                }
            )
            if args.report in {
                "scorecard_brief",
                "soc_triage",
                "crawler_governance",
                "edge_ops_impact",
            }:
                report_context.update(
                    {
                        "entity_type": args.entity_type,
                        "entity_value": args.entity_value,
                        "producer_limit": args.scorecard_limit,
                        "analysis_domains": args.domains,
                    }
                )
            if args.report == "edge_ops_impact":
                report_context["artifact"] = "scorecard"
            capture_summary["report_context"] = report_context
            print(json.dumps(capture_summary, sort_keys=True))
            return NEEDS_MCP_EXIT
        raw_value = load_raw_query_result(raw_path)
        if args.report == "control_review":
            timeseries_sql = control_review_timeseries_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.policy_id,
                args.control_source,
            )
            timeseries_summary_text = run(
                [
                    sys.executable,
                    str(CAPTURE),
                    "--cluster",
                    args.cluster,
                    "--database",
                    args.database,
                    "--sql",
                    timeseries_sql,
                    "--output",
                    str(timeseries_raw_path),
                ],
                allowed_returncodes=(NEEDS_MCP_EXIT,),
            )
            try:
                timeseries_summary = json.loads(timeseries_summary_text)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    "Timeseries capture did not return machine-readable JSON."
                ) from exc
            if (
                isinstance(timeseries_summary, dict)
                and timeseries_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                report_context = timeseries_summary.get("report_context")
                if not isinstance(report_context, dict):
                    report_context = {}
                report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "timeseries",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": table_used,
                        "granularity": granularity,
                    }
                )
                timeseries_summary["report_context"] = report_context
                print(json.dumps(timeseries_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            raw_timeseries_value = load_raw_query_result(timeseries_raw_path)
        if args.report == "edge_ops_impact" and args.include_paths:
            path_grain_sql = cache_origin_path_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.host,
                args.scorecard_limit,
            )
            path_table_used = f"{args.database}.bot_agg_path_{granularity}"
            try:
                path_capture_text = run(
                    [
                        sys.executable,
                        str(CAPTURE),
                        "--cluster",
                        args.cluster,
                        "--database",
                        args.database,
                        "--sql",
                        path_grain_sql,
                        "--output",
                        str(path_raw_path),
                    ],
                    allowed_returncodes=(NEEDS_MCP_EXIT,),
                )
            except SystemExit as exc:
                # Path-grain summary table may not exist on every cluster
                # (bot_agg_path_* is optional infrastructure). Degrade
                # gracefully to entity-grain only. The reader-facing
                # warning is humanized (no raw table name) so that an
                # LLM consuming stderr alongside the evidence packet
                # doesn't paste internal table identifiers into prose;
                # the raw exception text is kept on a separate
                # debug-prefix line for operator triage.
                print(
                    "WARNING: per-path cache data is not available on "
                    "this cluster; the path artifact will be omitted.",
                    file=sys.stderr,
                )
                print(
                    f"DEBUG: path-grain capture failed ({exc}); "
                    f"path table used was {path_table_used}.",
                    file=sys.stderr,
                )
                path_capture_text = ""
            try:
                path_capture_summary = json.loads(path_capture_text) if path_capture_text else {}
            except json.JSONDecodeError:
                print(
                    "WARNING: per-path cache data could not be parsed; "
                    "the path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_capture_summary = {}
            if (
                isinstance(path_capture_summary, dict)
                and path_capture_summary.get("schema_version") == HANDOFF_SCHEMA
            ):
                path_report_context = path_capture_summary.get("report_context")
                if not isinstance(path_report_context, dict):
                    path_report_context = {}
                path_report_context.update(
                    {
                        "report": args.report,
                        "mode": args.mode,
                        "artifact": "path",
                        "start": args.start,
                        "end": args.end,
                        "baseline_start": baseline_start.isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "table_used": path_table_used,
                        "granularity": granularity,
                    }
                )
                path_capture_summary["report_context"] = path_report_context
                print(json.dumps(path_capture_summary, sort_keys=True))
                return NEEDS_MCP_EXIT
            if path_raw_path.exists():
                raw_path_value = load_raw_query_result(path_raw_path)

    if args.report == "executive_posture":
        raw_value = add_report_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        raw_value = add_control_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        raw_value = add_scorecard_metadata(
            raw_value=raw_value,
            args=args,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    else:
        raise AssertionError(args.report)
    raw_path.write_text(
        json.dumps(raw_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        scorecard_cmd = [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/scorecard.py",
            "--file",
            str(raw_path),
            "--entity-type",
            args.entity_type,
            "--limit",
            str(args.scorecard_limit),
        ]
        if args.domains:
            scorecard_cmd.extend(["--domains", args.domains])
        run(scorecard_cmd, stdout_path=artifact_path, cwd=PUBLIC_SKILLS)
    else:
        run(
            [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/compare_posture.py",
                "--file",
                str(raw_path),
                "--schema",
                compare_schema,
            ],
            stdout_path=artifact_path,
            cwd=PUBLIC_SKILLS,
        )

    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise SystemExit(f"Expected {artifact_path} to contain an artifact object.")
    companion_artifacts: list[dict] = []
    path_artifact: dict | None = None
    if args.report == "edge_ops_impact" and raw_path_value is not None:
        path_raw_path.write_text(
            json.dumps(raw_path_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        try:
            path_cmd = [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/cache_origin_impact.py",
                "--file",
                str(path_raw_path),
            ]
            run(path_cmd, stdout_path=path_artifact_path, cwd=PUBLIC_SKILLS)
            path_artifact = json.loads(path_artifact_path.read_text(encoding="utf-8"))
            if not isinstance(path_artifact, dict) or not path_artifact.get(
                "candidates"
            ):
                print(
                    "WARNING: path-grain artifact has no candidates; "
                    "path artifact will be omitted.",
                    file=sys.stderr,
                )
                path_artifact = None
        except Exception as exc:  # noqa: BLE001
            print(
                f"WARNING: path-grain processing failed ({exc}); "
                "path artifact will be omitted.",
                file=sys.stderr,
            )
            path_artifact = None
    if args.report == "control_review" and raw_timeseries_value is not None:
        timeseries_artifact = build_timeseries_artifact(
            args=args,
            raw_value=raw_timeseries_value,
            control_artifact=artifact,
            table_used=table_used,
            granularity=granularity,
        )
        if timeseries_artifact.get("metrics"):
            timeseries_artifact_path.write_text(
                json.dumps(timeseries_artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            companion_artifacts.append(timeseries_artifact)
    if args.report == "executive_posture":
        evidence_packet = build_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report == "control_review":
        evidence_packet = build_control_evidence_packet(
            args=args,
            artifact=artifact,
            raw_path=raw_path,
            artifact_path=artifact_path,
            granularity=granularity,
            table_used=table_used,
            baseline_start=baseline_start,
        )
    elif args.report in {
        "scorecard_brief",
        "soc_triage",
        "crawler_governance",
        "edge_ops_impact",
    }:
        if args.report == "scorecard_brief" and args.fleet:
            # Fleet evidence packet — different shape from the
            # single-entity packet (fleet aggregates instead of
            # selected_entity + evaluated_feature_evidence) so the
            # LLM's prose matches the multi-entity render.
            evidence_packet = build_scorecard_fleet_evidence_packet(
                args=args,
                artifacts=artifact,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
        else:
            selected_card = select_scorecard(
                artifact,
                entity_type=args.entity_type if args.entity_value else None,
                entity_value=args.entity_value,
            )
            evidence_packet = build_scorecard_evidence_packet(
                args=args,
                artifacts=artifact,
                selected_card=selected_card,
                raw_path=raw_path,
                artifact_path=artifact_path,
                granularity=granularity,
                table_used=table_used,
                baseline_start=baseline_start,
            )
    else:
        raise AssertionError(args.report)

    # Enrich every emitted evidence packet with reader-friendly
    # ``*_label`` fields and append the label-preference rule to the
    # interpretation_contract. The transformation is additive — every
    # raw identifier is preserved next to its label so the deterministic
    # cross-reference back to the producer artifact still works.
    evidence_packet = humanize_evidence_packet(evidence_packet)

    if args.mode == "evidence":
        output_path.write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif args.mode == "template":
        output_path.write_text(
            render_template_packet(evidence_packet), encoding="utf-8"
        )
    else:
        if args.report == "scorecard_brief":
            if args.fleet:
                # Fleet view: keep every emitted scorecard so the
                # engine renders the multi-entity scorecard_brief
                # template (queue table, triage strip, fleet
                # coverage, score landscape) instead of auto-
                # promoting to scorecard_entity_review. The engine's
                # _maybe_promote_singleton only fires when
                # ``len(scorecards) == 1``; including every card
                # keeps the wrapper above that threshold and the
                # ``scorecard_brief`` report_type is preserved.
                scorecards = [
                    card
                    for card in (artifact.get("scorecards") or [])
                    if isinstance(card, dict)
                ]
                if not scorecards:
                    raise SystemExit(
                        "Scorecard artifacts did not contain any "
                        "emitted scorecards; --fleet has nothing to "
                        "render."
                    )
                render_artifacts = []
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
                render_artifacts.extend(scorecards)
            else:
                selected_card = select_scorecard(
                    artifact,
                    entity_type=args.entity_type if args.entity_value else None,
                    entity_value=args.entity_value,
                )
                render_artifacts = [selected_card]
                if isinstance(artifact.get("index"), dict):
                    render_artifacts.append(artifact["index"])
        elif args.report in {"soc_triage", "crawler_governance"}:
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
        elif args.report == "edge_ops_impact":
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            scorecards = artifact.get("scorecards")
            if isinstance(scorecards, list):
                render_artifacts.extend(
                    card for card in scorecards if isinstance(card, dict)
                )
            if path_artifact is not None:
                render_artifacts.append(path_artifact)
        else:
            render_artifacts = [artifact, *companion_artifacts]
        wrapper = build_report_wrapper(
            args=args,
            artifacts=render_artifacts,
            analyst_note=analyst_note_from_args(args),
        )
        wrapper_path.write_text(
            json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        run(
            render_report_command(
                wrapper_path=wrapper_path,
                output_path=output_path,
                output_format=args.format,
                config_path=args.config,
                title=args.title,
            ),
            cwd=PUBLIC_SKILLS,
        )

    print(
        json.dumps(
            {
                "artifact": str(artifact_path),
                "cluster": args.cluster,
                "database": args.database,
                "granularity": granularity,
                "mode": args.mode,
                "raw": str(raw_path),
                "output": str(output_path),
                "rows": capture_summary.get("rows"),
                "table_used": table_used,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
