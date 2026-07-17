from __future__ import annotations

import json
import sys
from pathlib import Path

from producers.runtime import CAPTURE, HANDOFF_SCHEMA, NEEDS_MCP_EXIT
from producers.sql.control_review import control_review_timeseries_sql
from producers.sql.scorecard import cache_origin_path_sql


def capture_standard_inputs(
    args,
    paths,
    plan,
    *,
    start,
    end,
    baseline_start,
    run_func,
    load_raw_query_result_func,
):
    capture_summary: dict[str, object] = {"rows": None}
    raw_timeseries_value: dict | None = None
    raw_path_value: dict | None = None
    if args.raw_input:
        raw_value = load_raw_query_result_func(Path(args.raw_input).expanduser().resolve())
        if args.report == "control_review" and paths["timeseries_raw"].exists():
            raw_timeseries_value = load_raw_query_result_func(paths["timeseries_raw"])
        if args.report == "edge_ops_impact":
            raw_path_value = _load_edge_raw_path(args, load_raw_query_result_func)
        return capture_summary, raw_value, raw_timeseries_value, raw_path_value
    capture_text = _run_primary_capture(args, paths, plan, run_func)
    if capture_text in {NEEDS_MCP_EXIT, 0}:
        return capture_text, None, None, None
    capture_summary = _parse_capture_summary(capture_text, "Capture")
    handoff = _emit_handoff_if_needed(args, capture_summary, plan, baseline_start)
    if handoff:
        return NEEDS_MCP_EXIT, None, None, None
    raw_value = load_raw_query_result_func(paths["raw"])
    if args.report == "control_review":
        raw_timeseries_value = _capture_control_timeseries(
            args,
            paths,
            plan,
            start,
            end,
            baseline_start,
            run_func,
            load_raw_query_result_func,
        )
        if raw_timeseries_value == NEEDS_MCP_EXIT:
            return NEEDS_MCP_EXIT, None, None, None
    if args.report == "edge_ops_impact" and args.include_paths:
        raw_path_value = _capture_edge_paths(
            args,
            paths,
            plan,
            start,
            end,
            baseline_start,
            run_func,
            load_raw_query_result_func,
        )
        if raw_path_value == NEEDS_MCP_EXIT:
            return NEEDS_MCP_EXIT, None, None, None
    return capture_summary, raw_value, raw_timeseries_value, raw_path_value


def _load_edge_raw_path(args, load_raw_query_result_func):
    if args.raw_path_input:
        return load_raw_query_result_func(Path(args.raw_path_input).expanduser().resolve())
    if args.include_paths:
        print(
            "WARNING: --raw-path-input not supplied for edge_ops_impact; "
            "path-grain artifact will be omitted.",
            file=sys.stderr,
        )
    return None


def _run_primary_capture(args, paths, plan, run_func):
    try:
        return run_func(
            [
                sys.executable,
                str(CAPTURE),
                "--cluster",
                args.cluster,
                "--database",
                args.database,
                "--sql",
                str(plan["sql"]),
                "--output",
                str(paths["raw"]),
            ],
            allowed_returncodes=(NEEDS_MCP_EXIT,),
        )
    except SystemExit as exc:
        if args.report == "soc_triage":
            print(
                "WARNING: SOC capture failed; "
                f"{plan['table_used']} may not be deployed on this cluster ({exc}). "
                "soc_triage requires SIEM policy summary data; skipping report.",
                file=sys.stderr,
            )
            return 0
        raise


def _parse_capture_summary(text, label: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{label} did not return machine-readable JSON.") from exc


def _emit_handoff_if_needed(args, summary, plan, baseline_start, *, artifact=None) -> bool:
    if not (isinstance(summary, dict) and summary.get("schema_version") == HANDOFF_SCHEMA):
        return False
    report_context = summary.get("report_context")
    if not isinstance(report_context, dict):
        report_context = {}
    report_context.update(
        {
            "report": args.report,
            "mode": args.mode,
            "start": args.start,
            "end": args.end,
            "baseline_start": baseline_start.isoformat().replace("+00:00", "Z"),
            "table_used": plan["table_used"],
            "granularity": plan["granularity"],
        }
    )
    if args.report in {"scorecard_brief", "soc_triage", "crawler_governance", "edge_ops_impact"}:
        report_context.update(
            {
                "entity_type": args.entity_type,
                "entity_value": args.entity_value,
                "producer_limit": args.scorecard_limit,
                "analysis_domains": args.domains,
            }
        )
    if artifact is None and args.report == "edge_ops_impact":
        artifact = "scorecard"
    if artifact:
        report_context["artifact"] = artifact
    summary["report_context"] = report_context
    print(json.dumps(summary, sort_keys=True))
    return True


def _capture_control_timeseries(
    args,
    paths,
    plan,
    start,
    end,
    baseline_start,
    run_func,
    load_raw_query_result_func,
):
    timeseries_sql = control_review_timeseries_sql(
        args.database, start, end, baseline_start, args.policy_id, args.control_source
    )
    text = run_func(
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
            str(paths["timeseries_raw"]),
        ],
        allowed_returncodes=(NEEDS_MCP_EXIT,),
    )
    summary = _parse_capture_summary(text, "Timeseries capture")
    if _emit_handoff_if_needed(args, summary, plan, baseline_start, artifact="timeseries"):
        return NEEDS_MCP_EXIT
    return load_raw_query_result_func(paths["timeseries_raw"])


def _capture_edge_paths(
    args,
    paths,
    plan,
    start,
    end,
    baseline_start,
    run_func,
    load_raw_query_result_func,
):
    path_table_used = f"{args.database}.bot_agg_path_{plan['granularity']}"
    path_plan = {**plan, "table_used": path_table_used}
    path_sql = cache_origin_path_sql(
        args.database, start, end, baseline_start, args.host, args.scorecard_limit
    )
    try:
        text = run_func(
            [
                sys.executable,
                str(CAPTURE),
                "--cluster",
                args.cluster,
                "--database",
                args.database,
                "--sql",
                path_sql,
                "--output",
                str(paths["path_raw"]),
            ],
            allowed_returncodes=(NEEDS_MCP_EXIT,),
        )
    except SystemExit as exc:
        print(
            "WARNING: per-path cache data is not available on this cluster; "
            "the path artifact will be omitted.",
            file=sys.stderr,
        )
        print(
            f"DEBUG: path-grain capture failed ({exc}); path table used was {path_table_used}.",
            file=sys.stderr,
        )
        text = ""
    try:
        summary = json.loads(text) if text else {}
    except json.JSONDecodeError:
        print(
            "WARNING: per-path cache data could not be parsed; the path artifact will be omitted.",
            file=sys.stderr,
        )
        summary = {}
    if _emit_handoff_if_needed(args, summary, path_plan, baseline_start, artifact="path"):
        return NEEDS_MCP_EXIT
    if paths["path_raw"].exists():
        return load_raw_query_result_func(paths["path_raw"])
    return None


__all__ = [name for name in globals() if not name.startswith("__")]
