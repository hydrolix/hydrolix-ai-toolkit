#!/usr/bin/env python3
"""Export bounded raw scraper drilldown rows for threat-hunt reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from producers.threat_hunt import (  # noqa: E402
    export_scraper_drilldowns,
    scraper_drilldown_scope,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="threat-hunt-scraper-drilldown-export",
        description=(
            "Export bounded user_agent x client_ip x endpoint x hour rows from "
            "akamai.logs for top threat-hunt scraper leads."
        ),
    )
    parser.add_argument("--cluster", required=True, help="Hydrolix mux cluster alias.")
    parser.add_argument("--database", default="akamai", help="Hydrolix database/project.")
    parser.add_argument("--actor-dir", required=True, help="Directory with current raw actor JSON files.")
    parser.add_argument("--cooccurrence-in", required=True, help="Exact UA/IP cooccurrence JSON or CSV artifact.")
    parser.add_argument("--start", required=True, help="Inclusive ISO-8601 window start.")
    parser.add_argument("--end", required=True, help="Exclusive ISO-8601 window end.")
    parser.add_argument(
        "--top-leads",
        type=int,
        default=5,
        help="Number of top user-agent leads to scope into the drilldown query.",
    )
    parser.add_argument(
        "--chunk-seconds",
        type=int,
        default=3600,
        help="Maximum seconds per raw-log query chunk.",
    )
    parser.add_argument(
        "--row-limit-per-chunk",
        type=int,
        default=100000,
        help="LIMIT appended to each chunk query after ORDER BY requests DESC.",
    )
    parser.add_argument(
        "--include-non-public-ips",
        action="store_true",
        help="Include loopback, private, reserved, and other non-public client IPs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview selected UAs/IPs, chunk count, and first SQL without querying.",
    )
    parser.add_argument("--output", help="Destination JSON row file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.dry_run and not args.output:
        raise SystemExit("--output is required unless --dry-run is supplied.")
    if args.chunk_seconds <= 0:
        raise SystemExit("--chunk-seconds must be positive.")
    if args.row_limit_per_chunk <= 0:
        raise SystemExit("--row-limit-per-chunk must be positive.")

    if args.dry_run:
        scope = scraper_drilldown_scope(
            actor_dir=args.actor_dir,
            cooccurrence_in=args.cooccurrence_in,
            start=args.start,
            end=args.end,
            database=args.database,
            top_leads=args.top_leads,
            chunk_seconds=args.chunk_seconds,
            row_limit_per_chunk=args.row_limit_per_chunk,
            include_non_public_ips=args.include_non_public_ips,
        )
        summary = {
            "cluster": args.cluster,
            "database": args.database,
            "dry_run": True,
            "top_leads": args.top_leads,
            "selected_user_agents": scope["selected_user_agents"],
            "selected_client_ips": scope["selected_client_ips"],
            "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
            "chunks": len(scope["chunks"]),
            "first_sql": scope["first_sql"],
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
    rows = export_scraper_drilldowns(
        actor_dir=args.actor_dir,
        cooccurrence_in=args.cooccurrence_in,
        start=args.start,
        end=args.end,
        cluster=args.cluster,
        database=args.database,
        top_leads=args.top_leads,
        output=args.output,
        chunk_seconds=args.chunk_seconds,
        row_limit_per_chunk=args.row_limit_per_chunk,
        include_non_public_ips=args.include_non_public_ips,
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
                "selected_client_ips": run_summary.get("selected_client_ips", []),
                "excluded_non_public_client_ips": run_summary.get(
                    "excluded_non_public_client_ips", []
                ),
                "chunks": run_summary.get("chunks"),
                "chunk_row_counts": run_summary.get("chunk_row_counts", []),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
