from __future__ import annotations

import json
import sys
from pathlib import Path

from .part_01 import *


def run_threat_hunt_flow(
    args,
    *,
    start,
    end,
    baseline_start,
    baseline_end,
    sample_dir: Path,
    run_func,
) -> int:
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path = sample_dir / "threat_hunt-artifact.json"
    wrapper_path = sample_dir / "threat_hunt-wrapper.json"
    raw_actor_dir = _ensure_raw_actor_dir(args, baseline_start, baseline_end, sample_dir)
    usagemeter_in = _ensure_usagemeter_input(args, sample_dir)
    fanout_strategy, fanout_in = _ensure_fanout_input(args, raw_actor_dir, sample_dir)
    selected_user_agents = _selected_user_agents(raw_actor_dir, args.top_n)
    background_ua_sample_in = _ensure_background_input(
        args, selected_user_agents, sample_dir
    )
    baseline_ua_timeseries_in = _ensure_baseline_ua_input(
        args,
        selected_user_agents,
        start=start,
        end=end,
        baseline_start=baseline_start,
        baseline_end=baseline_end,
        sample_dir=sample_dir,
    )
    artifact = build_threat_hunt_artifact(
        cluster=args.cluster,
        database=args.database,
        summary_parquet_glob=args.summary_parquet_glob,
        start=args.start,
        end=args.end,
        baseline_start=_iso_z(baseline_start),
        baseline_end=_iso_z(baseline_end),
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
        hydrolix_log_ingest_usagemeter_in=usagemeter_in,
        hydrolix_log_ingest_project_deployment_id=(
            args.hydrolix_log_ingest_usagemeter_project_deployment_id
        ),
        hydrolix_log_ingest_table_name=args.hydrolix_log_ingest_usagemeter_table_name,
    )
    _merge_impact_lanes(args, artifact, baseline_start, baseline_end, sample_dir)
    artifact_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_or_render_output(args, artifact, wrapper_path, output_path, run_func)
    _print_summary(args, artifact, artifact_path, output_path, raw_actor_dir)
    return 0


def _iso_z(value) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _ensure_raw_actor_dir(args, baseline_start, baseline_end, sample_dir: Path) -> str:
    raw_actor_dir = args.raw_actor_dir
    if raw_actor_dir is not None:
        return raw_actor_dir
    raw_actor_dir = str(sample_dir / "threat_hunt-actors")
    export_raw_actor_fixtures(
        actor_dir=raw_actor_dir,
        start=args.start,
        end=args.end,
        baseline_start=_iso_z(baseline_start),
        baseline_end=_iso_z(baseline_end),
        cluster=args.cluster,
        database=args.database,
        top_n=args.top_n,
        hydrolix_log_ingest_bytes_column=args.hydrolix_log_ingest_bytes_column,
        chunk_seconds=args.raw_actor_chunk_seconds,
        extraction_mode=args.raw_actor_extraction_mode,
        hash_buckets=args.raw_actor_hash_buckets,
        topk_candidate_multiplier=args.raw_actor_topk_candidate_multiplier,
    )
    return raw_actor_dir


def _ensure_usagemeter_input(args, sample_dir: Path) -> str | None:
    usagemeter_in = args.hydrolix_log_ingest_usagemeter_in
    if (
        usagemeter_in is not None
        or not args.hydrolix_log_ingest_usagemeter_project_deployment_id
    ):
        return usagemeter_in
    usagemeter_path = sample_dir / "threat_hunt-hydrolix-usagemeter.json"
    export_hydrolix_usagemeter_ingest_estimate(
        output=str(usagemeter_path),
        start=args.start,
        end=args.end,
        cluster=args.cluster,
        project_deployment_id=args.hydrolix_log_ingest_usagemeter_project_deployment_id,
        table_name=args.hydrolix_log_ingest_usagemeter_table_name,
    )
    return str(usagemeter_path)


def _ensure_fanout_input(args, raw_actor_dir: str, sample_dir: Path) -> tuple[str, str | None]:
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
    return fanout_strategy, fanout_in


def _selected_user_agents(raw_actor_dir: str, top_n: int) -> list[str]:
    selected_user_agents: list[str] = []
    current_ua_path = Path(raw_actor_dir) / "expedia-actors-current-user_agent.json"
    if not current_ua_path.exists():
        return selected_user_agents
    try:
        rows = json.loads(current_ua_path.read_text(encoding="utf-8"))
        if isinstance(rows, list):
            rows = sorted(
                [row for row in rows if isinstance(row, dict)],
                key=lambda row: (
                    -float(row.get("requests") or 0),
                    str(row.get("user_agent") or row.get("value") or ""),
                ),
            )
            selected_user_agents = [
                str(row.get("user_agent") or row.get("value"))
                for row in rows[:top_n]
                if row.get("user_agent") or row.get("value")
            ]
    except (OSError, ValueError, TypeError):
        selected_user_agents = []
    return selected_user_agents


def _ensure_background_input(args, selected_user_agents, sample_dir: Path) -> str | None:
    background_ua_sample_in = args.background_ua_sample_in
    if background_ua_sample_in is not None or args.background_query not in {"auto", "required"}:
        return background_ua_sample_in
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
    return background_ua_sample_in


def _ensure_baseline_ua_input(
    args,
    selected_user_agents,
    *,
    start,
    end,
    baseline_start,
    baseline_end,
    sample_dir: Path,
) -> str | None:
    baseline_ua_timeseries_in = args.baseline_ua_timeseries_in
    if (
        baseline_ua_timeseries_in is not None
        or args.baseline_significance_query not in {"auto", "required"}
    ):
        return baseline_ua_timeseries_in
    baseline_ua_path = sample_dir / "threat_hunt-baseline-ua-timeseries.json"
    try:
        export_baseline_ua_timeseries(
            baseline_start=_iso_z(baseline_start),
            baseline_end=_iso_z(baseline_end),
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
    return baseline_ua_timeseries_in


def _merge_impact_lanes(args, artifact, baseline_start, baseline_end, sample_dir: Path) -> None:
    if args.impact_lane_query == "off":
        return
    impact_lane_required = args.impact_lane_query == "required"
    lane_totals_in = args.impact_lane_totals_in
    lane_scoped_in = args.impact_lane_scoped_hunt_in
    try:
        if lane_totals_in is None:
            lane_totals_path = sample_dir / "threat_hunt-impact-lane-totals.json"
            export_impact_lane_totals(
                output=str(lane_totals_path),
                start=args.start,
                end=args.end,
                baseline_start=_iso_z(baseline_start),
                baseline_end=_iso_z(baseline_end),
                cluster=args.cluster,
                database=args.database,
            )
            lane_totals_in = str(lane_totals_path)
        if lane_scoped_in is None:
            lane_scoped_path = sample_dir / "threat_hunt-impact-lane-scoped-hunt.json"
            hunt_user_agents = [
                str(ua)
                for ua in (((artifact.get("impact_assessment") or {}).get("hunt") or {}).get("user_agents") or [])
                if str(ua)
            ]
            export_impact_lane_scoped_hunt(
                output=str(lane_scoped_path),
                start=args.start,
                end=args.end,
                baseline_start=_iso_z(baseline_start),
                baseline_end=_iso_z(baseline_end),
                cluster=args.cluster,
                database=args.database,
                user_agents=hunt_user_agents,
            )
            lane_scoped_in = str(lane_scoped_path)
        merge_impact_lanes_into_artifact(
            artifact,
            total_rows=read_impact_lane_rows(lane_totals_in),
            scoped_hunt_rows=read_impact_lane_rows(lane_scoped_in),
            required=impact_lane_required,
        )
    except SystemExit:
        if impact_lane_required:
            raise
        print(
            "WARNING: raw-log impact lane export/merge unavailable; keeping summary-derived impact lanes.",
            file=sys.stderr,
        )


def _write_or_render_output(args, artifact, wrapper_path: Path, output_path: Path, run_func) -> None:
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
        run_func(
            render_report_command(
                wrapper_path=wrapper_path,
                output_path=output_path,
                output_format=args.format,
                config_path=args.config,
                title=args.title,
            ),
            cwd=PUBLIC_SKILLS,
        )


def _print_summary(args, artifact, artifact_path: Path, output_path: Path, raw_actor_dir: str) -> None:
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


__all__ = [name for name in globals() if not name.startswith("__")]
