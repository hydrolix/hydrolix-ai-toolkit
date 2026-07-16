#!/usr/bin/env python3
"""Export bounded raw UA/IP cooccurrence cells for threat-hunt reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from producers.threat_hunt import (  # noqa: E402
    DEFAULT_COOCCURRENCE_TOP_N,
    export_raw_ua_cooccurrence,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="threat-hunt-cooccurrence-export",
        description="Export top client_ip x user_agent cooccurrence cells from akamai.logs in 6-hour chunks.",
    )
    parser.add_argument("--cluster", required=True, help="Hydrolix mux cluster alias.")
    parser.add_argument("--database", default="akamai", help="Hydrolix database/project.")
    parser.add_argument("--actor-dir", required=True, help="Directory with current raw actor JSON files.")
    parser.add_argument("--start", required=True, help="Inclusive ISO-8601 window start.")
    parser.add_argument("--end", required=True, help="Exclusive ISO-8601 window end.")
    parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_COOCCURRENCE_TOP_N,
        help="Number of current client_ip and user_agent actors to include on each axis.",
    )
    parser.add_argument("--output", required=True, help="Destination JSON row file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = export_raw_ua_cooccurrence(
        actor_dir=args.actor_dir,
        start=args.start,
        end=args.end,
        cluster=args.cluster,
        database=args.database,
        top_n=args.top_n,
        output=args.output,
    )
    print(
        json.dumps(
            {
                "cluster": args.cluster,
                "database": args.database,
                "output": str(Path(args.output).expanduser().resolve()),
                "rows": len(rows),
                "top_n": args.top_n,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
