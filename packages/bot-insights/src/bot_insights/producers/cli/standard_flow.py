from __future__ import annotations

import json
from pathlib import Path

from producers.runtime import result_rows
from producers.sql.summary_columns import (
    DEFAULT_PATH_PATTERN_COLUMN,
    resolve_path_pattern_column,
    summary_columns_query,
)

from .part_01 import *
from .standard_capture import capture_standard_inputs


def _resolve_standard_path_pattern_column(args, *, granularity, sample_dir, run_func) -> str:
    """Resolve the physical path-pattern column for the path scorecard entity.

    The posture summary renamed ``requestPathPattern`` -> ``reqPathPattern`` in
    bot_insights_cdn/1.1, so the ``request_path_norm`` scorecard entity must
    target whichever name the cluster exposes. Best-effort: when summary
    columns are reachable (direct execution) we resolve from them; on an MCP
    handoff, capture error, or any non-row result we fall back to the
    currently-deployed default rather than starting a second handoff chain.
    """
    if not (
        args.report == "scorecard_brief"
        and getattr(args, "entity_type", None) == "request_path_norm"
    ):
        return DEFAULT_PATH_PATTERN_COLUMN
    columns_path = sample_dir / f"{args.report}-columns-summary.json"
    sql = summary_columns_query(args.database, f"bi_summary_{granularity}")
    try:
        capture_text = run_func(
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
                str(columns_path),
                "--no-require-time-range",
            ],
            allowed_returncodes=(NEEDS_MCP_EXIT,),
        )
    except SystemExit:
        return DEFAULT_PATH_PATTERN_COLUMN
    try:
        summary = json.loads(capture_text) if capture_text else {}
    except json.JSONDecodeError:
        return DEFAULT_PATH_PATTERN_COLUMN
    if isinstance(summary, dict) and summary.get("schema_version") == HANDOFF_SCHEMA:
        return DEFAULT_PATH_PATTERN_COLUMN
    try:
        rows = result_rows(load_raw_query_result(columns_path))
    except (OSError, ValueError):
        return DEFAULT_PATH_PATTERN_COLUMN
    columns = {row.get("name") for row in rows if isinstance(row, dict) and row.get("name")}
    return resolve_path_pattern_column(columns)


def run_standard_flow(
    args,
    *,
    start,
    end,
    baseline_start,
    sample_dir: Path,
    run_func,
    load_raw_query_result_func,
) -> int:
    paths = _standard_paths(args, sample_dir)
    path_pattern_column = _resolve_standard_path_pattern_column(
        args,
        granularity=choose_granularity(start, end),
        sample_dir=sample_dir,
        run_func=run_func,
    )
    plan = _report_plan(
        args, start, end, baseline_start, path_pattern_column=path_pattern_column
    )
    capture_summary, raw_value, raw_timeseries_value, raw_path_value = capture_standard_inputs(
        args,
        paths,
        plan,
        start=start,
        end=end,
        baseline_start=baseline_start,
        run_func=run_func,
        load_raw_query_result_func=load_raw_query_result_func,
    )
    if isinstance(capture_summary, int) and capture_summary in {NEEDS_MCP_EXIT, 0}:
        return capture_summary
    raw_value = _add_metadata(args, raw_value, plan, baseline_start)
    paths["raw"].write_text(
        json.dumps(raw_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _build_primary_artifact(args, paths, plan, run_func)
    artifact = _read_artifact(paths["artifact"])
    companion_artifacts, path_artifact = _build_companion_artifacts(
        args,
        paths,
        artifact,
        raw_timeseries_value,
        raw_path_value,
        plan,
        run_func,
    )
    evidence_packet = _build_evidence_packet(
        args,
        artifact,
        paths,
        plan,
        baseline_start,
    )
    _write_or_render_standard(
        args,
        paths,
        artifact,
        companion_artifacts,
        path_artifact,
        evidence_packet,
        run_func,
    )
    _print_standard_summary(args, paths, plan, capture_summary)
    return 0


def _standard_paths(args, sample_dir: Path) -> dict[str, Path]:
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return {
        "raw": sample_dir / f"{args.report}-raw.json",
        "artifact": sample_dir / f"{args.report}-artifact.json",
        "timeseries_raw": sample_dir / f"{args.report}-timeseries-raw.json",
        "timeseries_artifact": sample_dir / f"{args.report}-timeseries.json",
        "path_raw": sample_dir / f"{args.report}-path-raw.json",
        "path_artifact": sample_dir / f"{args.report}-path-artifact.json",
        "wrapper": sample_dir / f"{args.report}-wrapper.json",
        "output": output_path,
    }


def _report_plan(
    args, start, end, baseline_start, path_pattern_column=DEFAULT_PATH_PATTERN_COLUMN
) -> dict[str, object]:
    granularity = choose_granularity(start, end)
    if args.report == "executive_posture":
        return {
            "sql": executive_posture_sql(args.database, start, end, baseline_start),
            "granularity": granularity,
            "table_used": f"{args.database}.bi_summary_{granularity}",
            "compare_schema": "posture",
        }
    if args.report == "control_review":
        table_prefix = (
            "bi_summary" if args.control_source == "posture" else "bi_siem_policy_summary"
        )
        return {
            "sql": control_review_sql(
                args.database,
                start,
                end,
                baseline_start,
                args.policy_id,
                args.control_source,
            ),
            "granularity": granularity,
            "table_used": f"{args.database}.{table_prefix}_{granularity}",
            "compare_schema": "control",
        }
    if args.report == "scorecard_brief":
        sql = scorecard_sql(
            args.database,
            start,
            end,
            baseline_start,
            args.entity_type,
            args.scorecard_limit,
            path_pattern_column=path_pattern_column,
        )
    elif args.report == "soc_triage":
        sql = scorecard_soc_sql(
            args.database, start, end, baseline_start, args.entity_type, args.scorecard_limit
        )
    elif args.report == "crawler_governance":
        sql = scorecard_crawler_sql(
            args.database, start, end, baseline_start, args.entity_type, args.scorecard_limit
        )
    elif args.report == "edge_ops_impact":
        sql = scorecard_edge_ops_sql(
            args.database, start, end, baseline_start, args.entity_type, args.scorecard_limit
        )
    else:
        raise AssertionError(args.report)
    table_family = "bi_siem_policy_summary" if args.report == "soc_triage" else "bi_summary"
    return {
        "sql": sql,
        "granularity": granularity,
        "table_used": f"{args.database}.{table_family}_{granularity}",
        "compare_schema": None,
    }


def _add_metadata(args, raw_value, plan, baseline_start):
    kwargs = {
        "raw_value": raw_value,
        "args": args,
        "granularity": plan["granularity"],
        "table_used": plan["table_used"],
        "baseline_start": baseline_start,
    }
    if args.report == "executive_posture":
        return add_report_metadata(**kwargs)
    if args.report == "control_review":
        return add_control_metadata(**kwargs)
    if args.report in {"scorecard_brief", "soc_triage", "crawler_governance", "edge_ops_impact"}:
        return add_scorecard_metadata(**kwargs)
    raise AssertionError(args.report)


def _build_primary_artifact(args, paths, plan, run_func) -> None:
    if args.report in {"scorecard_brief", "soc_triage", "crawler_governance", "edge_ops_impact"}:
        scorecard_cmd = [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/scorecard.py",
            "--file",
            str(paths["raw"]),
            "--entity-type",
            args.entity_type,
            "--limit",
            str(args.scorecard_limit),
        ]
        if args.domains:
            scorecard_cmd.extend(["--domains", args.domains])
        run_func(scorecard_cmd, stdout_path=paths["artifact"], cwd=PUBLIC_SKILLS)
        return
    run_func(
        [
            "uv",
            "run",
            "python",
            "skills/bot-insights/scripts/compare_posture.py",
            "--file",
            str(paths["raw"]),
            "--schema",
            str(plan["compare_schema"]),
        ],
        stdout_path=paths["artifact"],
        cwd=PUBLIC_SKILLS,
    )


def _read_artifact(path: Path) -> dict:
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise SystemExit(f"Expected {path} to contain an artifact object.")
    return artifact


def _build_companion_artifacts(args, paths, artifact, raw_timeseries_value, raw_path_value, plan, run_func):
    companion_artifacts: list[dict] = []
    path_artifact: dict | None = None
    if args.report == "edge_ops_impact" and raw_path_value is not None:
        path_artifact = _build_path_artifact(paths, raw_path_value, run_func)
    if args.report == "control_review" and raw_timeseries_value is not None:
        timeseries_artifact = build_timeseries_artifact(
            args=args,
            raw_value=raw_timeseries_value,
            control_artifact=artifact,
            table_used=plan["table_used"],
            granularity=plan["granularity"],
        )
        if timeseries_artifact.get("metrics"):
            paths["timeseries_artifact"].write_text(
                json.dumps(timeseries_artifact, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            companion_artifacts.append(timeseries_artifact)
    return companion_artifacts, path_artifact


def _build_path_artifact(paths, raw_path_value, run_func) -> dict | None:
    paths["path_raw"].write_text(
        json.dumps(raw_path_value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        run_func(
            [
                "uv",
                "run",
                "python",
                "skills/bot-insights/scripts/cache_origin_impact.py",
                "--file",
                str(paths["path_raw"]),
            ],
            stdout_path=paths["path_artifact"],
            cwd=PUBLIC_SKILLS,
        )
        path_artifact = _read_artifact(paths["path_artifact"])
        if not path_artifact.get("candidates"):
            print(
                "WARNING: path-grain artifact has no candidates; path artifact will be omitted.",
                file=sys.stderr,
            )
            return None
        return path_artifact
    except Exception as exc:  # noqa: BLE001
        print(
            f"WARNING: path-grain processing failed ({exc}); path artifact will be omitted.",
            file=sys.stderr,
        )
        return None


def _build_evidence_packet(args, artifact, paths, plan, baseline_start):
    kwargs = {
        "args": args,
        "raw_path": paths["raw"],
        "artifact_path": paths["artifact"],
        "granularity": plan["granularity"],
        "table_used": plan["table_used"],
        "baseline_start": baseline_start,
    }
    if args.report == "executive_posture":
        evidence_packet = build_evidence_packet(artifact=artifact, **kwargs)
    elif args.report == "control_review":
        evidence_packet = build_control_evidence_packet(artifact=artifact, **kwargs)
    elif args.report == "scorecard_brief" and args.fleet:
        evidence_packet = build_scorecard_fleet_evidence_packet(artifacts=artifact, **kwargs)
    elif args.report in {"scorecard_brief", "soc_triage", "crawler_governance", "edge_ops_impact"}:
        selected_card = select_scorecard(
            artifact,
            entity_type=args.entity_type if args.entity_value else None,
            entity_value=args.entity_value,
        )
        evidence_packet = build_scorecard_evidence_packet(
            artifacts=artifact,
            selected_card=selected_card,
            **kwargs,
        )
    else:
        raise AssertionError(args.report)
    return humanize_evidence_packet(evidence_packet)


def _write_or_render_standard(
    args,
    paths,
    artifact,
    companion_artifacts,
    path_artifact,
    evidence_packet,
    run_func,
) -> None:
    if args.mode == "evidence":
        paths["output"].write_text(
            json.dumps(evidence_packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return
    if args.mode == "template":
        paths["output"].write_text(render_template_packet(evidence_packet), encoding="utf-8")
        return
    render_artifacts = _render_artifacts(args, artifact, companion_artifacts, path_artifact)
    wrapper = build_report_wrapper(
        args=args,
        artifacts=render_artifacts,
        analyst_note=analyst_note_from_args(args),
    )
    paths["wrapper"].write_text(
        json.dumps(wrapper, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    run_func(
        render_report_command(
            wrapper_path=paths["wrapper"],
            output_path=paths["output"],
            output_format=args.format,
            config_path=args.config,
            title=args.title,
        ),
        cwd=PUBLIC_SKILLS,
    )


def _render_artifacts(args, artifact, companion_artifacts, path_artifact):
    if args.report == "scorecard_brief":
        if args.fleet:
            scorecards = [card for card in (artifact.get("scorecards") or []) if isinstance(card, dict)]
            if not scorecards:
                raise SystemExit(
                    "Scorecard artifacts did not contain any emitted scorecards; "
                    "--fleet has nothing to render."
                )
            render_artifacts = []
            if isinstance(artifact.get("index"), dict):
                render_artifacts.append(artifact["index"])
            render_artifacts.extend(scorecards)
            return render_artifacts
        selected_card = select_scorecard(
            artifact,
            entity_type=args.entity_type if args.entity_value else None,
            entity_value=args.entity_value,
        )
        render_artifacts = [selected_card]
        if isinstance(artifact.get("index"), dict):
            render_artifacts.append(artifact["index"])
        return render_artifacts
    if args.report in {"soc_triage", "crawler_governance", "edge_ops_impact"}:
        render_artifacts = []
        if isinstance(artifact.get("index"), dict):
            render_artifacts.append(artifact["index"])
        scorecards = artifact.get("scorecards")
        if isinstance(scorecards, list):
            render_artifacts.extend(card for card in scorecards if isinstance(card, dict))
        if args.report == "edge_ops_impact" and path_artifact is not None:
            render_artifacts.append(path_artifact)
        return render_artifacts
    return [artifact, *companion_artifacts]


def _print_standard_summary(args, paths, plan, capture_summary) -> None:
    print(
        json.dumps(
            {
                "artifact": str(paths["artifact"]),
                "cluster": args.cluster,
                "database": args.database,
                "granularity": plan["granularity"],
                "mode": args.mode,
                "raw": str(paths["raw"]),
                "output": str(paths["output"]),
                "rows": capture_summary.get("rows"),
                "table_used": plan["table_used"],
            },
            sort_keys=True,
        )
    )


__all__ = [name for name in globals() if not name.startswith("__")]
