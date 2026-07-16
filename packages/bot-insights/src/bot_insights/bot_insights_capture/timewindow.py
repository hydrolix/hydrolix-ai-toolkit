from __future__ import annotations

import argparse
from datetime import datetime, timezone


def parse_time(value: str, *, label: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SystemExit(f"--{label} must be an ISO-8601 timestamp with timezone.") from exc
    if parsed.tzinfo is None:
        raise SystemExit(f"--{label} must include a timezone, for example 2026-05-08T00:00:00Z.")
    return parsed.astimezone(timezone.utc)


def sql_timestamp(value: datetime) -> str:
    text = value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f"toDateTime('{text}', 'UTC')"


def duration_minutes(start: datetime, end: datetime) -> float:
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        raise SystemExit("--end must be later than --start.")
    return seconds / 60


def selected_granularity(start: datetime, end: datetime, requested: str) -> str:
    if requested != "auto":
        return requested
    minutes = duration_minutes(start, end)
    if minutes < 180:
        return "minute"
    if minutes < 2880:
        return "hour"
    return "day"


def selected_table(database: str, surface: str, granularity: str) -> str:
    if surface == "posture":
        return f"{database}.bi_summary_{granularity}"
    if surface == "siem-policy":
        return f"{database}.bi_siem_policy_summary_{granularity}"
    raise AssertionError(surface)


def selected_time_column(surface: str) -> str:
    if surface == "posture":
        return "reqTimeSec"
    if surface == "siem-policy":
        return "timestamp"
    raise AssertionError(surface)


def require_time_window(args: argparse.Namespace) -> tuple[datetime, datetime]:
    if not args.start or not args.end:
        raise SystemExit("--start and --end are required for Bot Insights capture presets.")
    start = parse_time(args.start, label="start")
    end = parse_time(args.end, label="end")
    duration_minutes(start, end)
    return start, end


def time_context(args: argparse.Namespace) -> dict[str, str]:
    if not args.start or not args.end:
        return {}
    start = parse_time(args.start, label="start")
    end = parse_time(args.end, label="end")
    duration_minutes(start, end)
    surface = "siem-policy" if args.preset and args.preset.startswith("siem-") else "posture"
    time_column = selected_time_column(surface)
    granularity = selected_granularity(start, end, args.granularity)
    table = selected_table(args.database, surface, granularity)
    time_filter = f"{time_column} >= {sql_timestamp(start)} AND {time_column} < {sql_timestamp(end)}"
    return {
        "start": sql_timestamp(start),
        "end": sql_timestamp(end),
        "database": args.database,
        "table": table,
        "time_column": time_column,
        "time_filter": time_filter,
        "granularity": granularity,
        "surface": surface,
    }


def apply_time_window_to_sql(sql: str, args: argparse.Namespace) -> str:
    context = time_context(args)
    for key, value in context.items():
        sql = sql.replace(f"{{{{{key}}}}}", value)
    return sql
