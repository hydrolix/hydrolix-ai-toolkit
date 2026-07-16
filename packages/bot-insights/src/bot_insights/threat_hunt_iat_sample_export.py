#!/usr/bin/env python3
"""Export bounded request-level timing samples for threat-hunt reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from producers.threat_hunt import (  # noqa: E402
    export_iat_samples,
    iat_sample_scope,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="threat-hunt-iat-sample-export",
        description=(
            "Export bounded user_agent x client_ip request timestamp samples from "
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
        default=25,
        help="Number of top user-agent leads to scope into the timing sample query.",
    )
    parser.add_argument(
        "--sample-limit-per-ua",
        type=int,
        default=5000,
        help="Maximum request-level timestamp rows retained per selected user agent.",
    )
    parser.add_argument(
        "--include-non-public-ips",
        action="store_true",
        help="Include loopback, private, reserved, and other non-public client IPs.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview selected UAs/IPs and sample SQL without querying.",
    )
    parser.add_argument("--output", help="Destination JSON row file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.dry_run and not args.output:
        raise SystemExit("--output is required unless --dry-run is supplied.")
    if args.sample_limit_per_ua <= 0:
        raise SystemExit("--sample-limit-per-ua must be positive.")

    if args.dry_run:
        scope = iat_sample_scope(
            actor_dir=args.actor_dir,
            cooccurrence_in=args.cooccurrence_in,
            start=args.start,
            end=args.end,
            database=args.database,
            top_leads=args.top_leads,
            sample_limit_per_ua=args.sample_limit_per_ua,
            include_non_public_ips=args.include_non_public_ips,
        )
        summary = {
            "cluster": args.cluster,
            "database": args.database,
            "dry_run": True,
            "top_leads": args.top_leads,
            "sample_limit_per_ua": args.sample_limit_per_ua,
            "selected_user_agents": scope["selected_user_agents"],
            "selected_client_ips": scope["selected_client_ips"],
            "excluded_non_public_client_ips": scope["excluded_non_public_client_ips"],
            "sample_sql": scope["sample_sql"],
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
    rows = export_iat_samples(
        actor_dir=args.actor_dir,
        cooccurrence_in=args.cooccurrence_in,
        start=args.start,
        end=args.end,
        cluster=args.cluster,
        database=args.database,
        top_leads=args.top_leads,
        sample_limit_per_ua=args.sample_limit_per_ua,
        output=args.output,
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
                "sample_limit_per_ua": args.sample_limit_per_ua,
                "selected_user_agents": run_summary.get("selected_user_agents", []),
                "selected_client_ips": run_summary.get("selected_client_ips", []),
                "excluded_non_public_client_ips": run_summary.get(
                    "excluded_non_public_client_ips", []
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
