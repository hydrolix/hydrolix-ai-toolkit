#!/usr/bin/env python3
"""Export complete UA x hour request profiles for threat-hunt timing."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from producers.threat_hunt import (  # noqa: E402
    _raw_scraper_hourly_sql,
    _top_scraper_user_agents,
    _cooccurrence_rows,
    export_scraper_hourly_profiles,
    load_raw_actor_rows,
    parse_time,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="threat-hunt-scraper-hourly-export",
        description=(
            "Export complete user_agent x hour request rollups from akamai.logs "
            "for top threat-hunt scraper leads."
        ),
    )
    parser.add_argument("--cluster", required=True, help="Hydrolix mux cluster alias.")
    parser.add_argument("--database", default="akamai", help="Hydrolix database/project.")
    parser.add_argument("--actor-dir", required=True, help="Directory with current raw actor JSON files.")
    parser.add_argument("--cooccurrence-in", help="Optional exact UA/IP cooccurrence JSON or CSV artifact.")
    parser.add_argument("--start", required=True, help="Inclusive ISO-8601 window start.")
    parser.add_argument("--end", required=True, help="Exclusive ISO-8601 window end.")
    parser.add_argument(
        "--top-leads",
        type=int,
        default=25,
        help="Number of top user-agent leads to include in the hourly query.",
    )
    parser.add_argument(
        "--chunk-seconds",
        type=int,
        default=21600,
        help="Maximum seconds per raw-log query chunk.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview selected UAs and SQL without querying.",
    )
    parser.add_argument("--output", help="Destination JSON row file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.dry_run and not args.output:
        raise SystemExit("--output is required unless --dry-run is supplied.")
    if args.top_leads <= 0:
        raise SystemExit("--top-leads must be positive.")
    if args.chunk_seconds <= 0:
        raise SystemExit("--chunk-seconds must be positive.")

    if args.dry_run:
        actor_rows = load_raw_actor_rows(args.actor_dir)
        cooccurrence = _cooccurrence_rows(args.cooccurrence_in, "ua") if args.cooccurrence_in else []
        user_agents = _top_scraper_user_agents(actor_rows, cooccurrence, args.top_leads)
        summary = {
            "cluster": args.cluster,
            "database": args.database,
            "dry_run": True,
            "top_leads": args.top_leads,
            "selected_user_agents": user_agents,
            "chunk_seconds": args.chunk_seconds,
            "hourly_sql": _raw_scraper_hourly_sql(
                database=args.database,
                start=parse_time(args.start, "start"),
                end=min(
                    parse_time(args.end, "end"),
                    parse_time(args.start, "start") + timedelta(seconds=args.chunk_seconds),
                ),
                user_agents=user_agents,
            )
            if user_agents
            else "",
        }
        if args.output:
            output_path = Path(args.output).expanduser().resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            summary["output"] = str(output_path)
        print(json.dumps(summary, sort_keys=True))
        return 0

    run_summary: dict[str, object] = {}
    rows = export_scraper_hourly_profiles(
        actor_dir=args.actor_dir,
        cooccurrence_in=args.cooccurrence_in,
        start=args.start,
        end=args.end,
        cluster=args.cluster,
        database=args.database,
        top_leads=args.top_leads,
        output=args.output,
        chunk_seconds=args.chunk_seconds,
        run_summary=run_summary,
    )
    print(
        json.dumps(
            {
                "cluster": args.cluster,
                "database": args.database,
                "output": str(Path(args.output).expanduser().resolve()),
                "rows": len(rows),
                "top_leads": args.top_leads,
                "selected_user_agents": run_summary.get("selected_user_agents", []),
                "chunks": run_summary.get("chunks"),
                "chunk_row_counts": run_summary.get("chunk_row_counts", []),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
