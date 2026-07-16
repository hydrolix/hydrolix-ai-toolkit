from __future__ import annotations

from pathlib import Path

from .part_01 import *


SCORECARD_REPORTS = {
    "scorecard_brief",
    "soc_triage",
    "crawler_governance",
    "edge_ops_impact",
}


def prepare_cli_context(args):
    from config import load_thresholds, set_active_thresholds

    set_active_thresholds(load_thresholds(args.config))
    start = parse_time(args.start, "start")
    end = parse_time(args.end, "end")
    window = end - start
    baseline_start = (
        parse_time(args.baseline_start, "baseline-start")
        if args.baseline_start
        else start - window
    )
    baseline_end = (
        parse_time(args.baseline_end, "baseline-end")
        if args.baseline_end
        else start
    )
    validate_windows(args, start, end, baseline_start, baseline_end, window)
    validate_report_args(args)
    apply_report_defaults(args)
    sample_dir = (
        Path(args.sample_dir).expanduser().resolve()
        if args.sample_dir
        else DEFAULT_SAMPLE_ROOT / args.cluster
    )
    sample_dir.mkdir(parents=True, exist_ok=True)
    return start, end, baseline_start, baseline_end, sample_dir


def validate_windows(args, start, end, baseline_start, baseline_end, window) -> None:
    if baseline_start >= baseline_end:
        raise SystemExit("--baseline-start must be earlier than --baseline-end")
    if baseline_end > start:
        raise SystemExit("--baseline-end must be earlier than or equal to --start")
    if baseline_end - baseline_start != window:
        raise SystemExit("--baseline window must match the current window duration")
    if args.baseline_end:
        raise SystemExit("--baseline-end is not supported for the available reports.")


def validate_report_args(args) -> None:
    if args.scorecard_limit < 0:
        raise SystemExit("--scorecard-limit must be zero or a positive integer.")
    if args.report not in SCORECARD_REPORTS and args.entity_value:
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
    validate_scorecard_entity_type(args)
    if args.raw_path_input and not args.raw_input:
        raise SystemExit(
            "--raw-path-input requires --raw-input to also be supplied "
            "(both raw inputs must be provided to resume an edge_ops_impact run)."
        )
    if args.raw_path_input and args.report != "edge_ops_impact":
        raise SystemExit("--raw-path-input is only valid with --report edge_ops_impact.")


def validate_scorecard_entity_type(args) -> None:
    if args.report == "soc_triage" and args.entity_type not in SOC_ENTITY_SQL:
        raise SystemExit(
            "--entity-type "
            + args.entity_type
            + " is not supported for soc_triage; use one of "
            + ", ".join(sorted(SOC_ENTITY_SQL))
        )
    if args.report == "crawler_governance" and args.entity_type not in CRAWLER_ENTITY_SQL:
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


def apply_report_defaults(args) -> None:
    if args.report == "soc_triage" and not args.domains:
        args.domains = "security_evidence"
    if args.report == "crawler_governance" and not args.domains:
        args.domains = "crawler_governance"
    if args.report == "edge_ops_impact" and not args.domains:
        args.domains = "cache_busting,origin_impact"



__all__ = [name for name in globals() if not name.startswith("__")]
