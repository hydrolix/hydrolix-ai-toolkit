from __future__ import annotations

from pathlib import Path

from .part_01 import *
from .part_02 import parse_args
from .standard_flow import run_standard_flow
from .threat_hunt_flow import run_threat_hunt_flow
from .validation import prepare_cli_context


def main() -> int:
    # Late-bind through the historical shim so tests that patch
    # bot_insights_report.run/load_raw_query_result keep intercepting
    # subprocess and raw-result behavior after the flow split.
    import bot_insights_report as _bir

    run_func = _bir.run
    load_raw_query_result_func = _bir.load_raw_query_result

    args = parse_args()
    start, end, baseline_start, baseline_end, sample_dir = prepare_cli_context(args)

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
        return run_threat_hunt_flow(
            args,
            start=start,
            end=end,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            sample_dir=sample_dir,
            run_func=run_func,
        )

    return run_standard_flow(
        args,
        start=start,
        end=end,
        baseline_start=baseline_start,
        sample_dir=sample_dir,
        run_func=run_func,
        load_raw_query_result_func=load_raw_query_result_func,
    )


__all__ = [name for name in globals() if not name.startswith("__")]
