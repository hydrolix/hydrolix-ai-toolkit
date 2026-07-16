from __future__ import annotations

from ._shared import *

"""Capture vetted Bot Insights Hydrolix query JSON to disk."""


import argparse

import base64

import json

import os

import re

import shutil

import ssl

import subprocess

import sys

import tempfile

import urllib.error

import urllib.request

from dataclasses import dataclass

from datetime import datetime, timezone

from pathlib import Path

from typing import Any

from reportkit.extract import hydrolix as hdx

TIME_PREDICATE_RE = re.compile(
    r"(?:\b(?:timestamp|reqTimeSec)\b|`toStartOf(?:Minute|Hour|Day)\(reqTimeSec\)`)\s*(?:=|!=|<>|>=|<=|>|<|BETWEEN|IN)(?:\s|\(|'|$)",
    re.IGNORECASE,
)

FORMAT_RE = re.compile(r"\bFORMAT\s+\w+\b", re.IGNORECASE)

PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}|\$\{[^}]+\}")

SENTINEL_ENV = "BOT_INSIGHTS_CAPTURE_OP_RUN"

CLUSTER_DIR_ENV = ("BOT_INSIGHTS_CLUSTER_DIR", "HYDROLIX_CLUSTER_DIR", "HDX_CLUSTER_DIR")

NEEDS_MCP_EXIT = 42

HANDOFF_SCHEMA = "bot_hydrolix_mcp_query_request.v1"

PRESET_CHOICES = (
    "posture-overview",
    "posture-by-asn",
    "posture-by-path",
    "siem-policy",
)

@dataclass(frozen=True)
class QueryConfig:
    url: str
    headers: dict[str, str]
    verify_tls: bool
    auth_mode: str

@dataclass(frozen=True)
class CredentialState:
    configured: bool
    host: str | None
    auth_mode: str | None
    missing: tuple[str, ...]
    unresolved_op: tuple[str, ...]
    env_file: str | None
    op_resolution: str

def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        value = raw_value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values

def cluster_env_dir(env: dict[str, str] | None = None) -> Path:
    source = env or os.environ
    for key in CLUSTER_DIR_ENV:
        if source.get(key):
            return Path(source[key]).expanduser()
    return Path.home() / ".config/hydrolix/clusters"

def cluster_env_path(alias: str, env: dict[str, str] | None = None) -> Path:
    path = Path(alias).expanduser()
    if path.suffix == ".env" or path.is_absolute() or "/" in alias:
        return path
    return cluster_env_dir(env) / f"{alias}.env"

def file_may_need_op(path: Path) -> bool:
    return path.exists() and "op://" in path.read_text(encoding="utf-8")

def should_reexec_with_op(path: Path, env: dict[str, str] | None = None) -> bool:
    source = env or os.environ
    return (
        path.exists()
        and source.get(SENTINEL_ENV) != "1"
        and file_may_need_op(path)
        and shutil.which("op") is not None
    )

def reexec_with_op(path: Path) -> None:
    env = dict(os.environ)
    env[SENTINEL_ENV] = "1"
    command = [
        "op",
        "run",
        "--env-file",
        str(path),
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        *sys.argv[1:],
    ]
    os.execvpe("op", command, env)

def resolved_cluster_env_path(cluster: str | None) -> Path | None:
    if not cluster:
        return None
    env_path = cluster_env_path(cluster)
    if env_path.exists():
        return env_path
    if "/" in cluster or cluster.endswith(".env"):
        raise SystemExit(f"Cluster env file does not exist: {env_path}")
    return None

def merged_environment(cluster: str | None) -> tuple[dict[str, str], Path | None]:
    env_file_values: dict[str, str] = {}
    env_path = resolved_cluster_env_path(cluster)
    if env_path:
        if should_reexec_with_op(env_path):
            reexec_with_op(env_path)
        env_file_values = parse_env_file(env_path)

    merged = dict(env_file_values)
    merged.update(os.environ)
    return merged, env_path

def first_env(env: dict[str, str], *names: str) -> str | None:
    for name in names:
        value = env.get(name)
        if value:
            return value
    return None

def is_unresolved_secret(value: str | None) -> bool:
    return bool(value and value.strip().startswith("op://"))

def secret_error(name: str) -> SystemExit:
    return SystemExit(
        f"{name} is an unresolved op:// reference. Install/sign in to 1Password CLI "
        "or provide literal credentials in the current environment."
    )

def credential_state(env: dict[str, str], env_path: Path | None = None) -> CredentialState:
    host = first_env(env, "HYDROLIX_HOST", "HDX_HOSTNAME")
    token = first_env(env, "HYDROLIX_TOKEN", "HDX_TOKEN")
    user = first_env(env, "HYDROLIX_USER", "HDX_USERNAME")
    password = first_env(env, "HYDROLIX_PASSWORD", "HDX_PASSWORD")

    unresolved: list[str] = []
    for label, value in (
        ("HYDROLIX_HOST/HDX_HOSTNAME", host),
        ("HYDROLIX_TOKEN/HDX_TOKEN", token),
        ("HYDROLIX_USER/HDX_USERNAME", user),
        ("HYDROLIX_PASSWORD/HDX_PASSWORD", password),
    ):
        if is_unresolved_secret(value):
            unresolved.append(label)

    missing: list[str] = []
    if not host:
        missing.append("HYDROLIX_HOST/HDX_HOSTNAME")

    auth_mode: str | None = None
    if token:
        auth_mode = "bearer"
    elif user and password:
        auth_mode = "basic"
    else:
        missing.append(
            "HYDROLIX_TOKEN/HDX_TOKEN or HYDROLIX_USER/HYDROLIX_PASSWORD or HDX_USERNAME/HDX_PASSWORD"
        )

    configured = bool(host and auth_mode and not unresolved)
    if unresolved:
        configured = False

    op_resolution = "not_required"
    if unresolved:
        op_resolution = "unresolved"
    elif env_path and file_may_need_op(env_path):
        op_resolution = "resolved_by_op_run" if os.environ.get(SENTINEL_ENV) == "1" else "resolved"

    return CredentialState(
        configured=configured,
        host=host,
        auth_mode=auth_mode if configured else None,
        missing=tuple(missing),
        unresolved_op=tuple(unresolved),
        env_file=str(env_path) if env_path else None,
        op_resolution=op_resolution,
    )

def normalize_query_url(host: str, scheme: str = "https") -> str:
    cleaned = host.strip()
    if not cleaned:
        raise SystemExit("HYDROLIX_HOST or HDX_HOSTNAME is required.")
    if "://" not in cleaned:
        cleaned = f"{scheme}://{cleaned}"
    cleaned = cleaned.rstrip("/")
    if cleaned.endswith("/query"):
        return f"{cleaned}/"
    if cleaned.endswith("/query/"):
        return cleaned
    return f"{cleaned}/query/"

def bool_env(value: str | None) -> bool:
    return bool(value and value.strip().lower() in {"1", "true", "yes", "on"})

def build_query_config(env: dict[str, str]) -> QueryConfig:
    host = first_env(env, "HYDROLIX_HOST", "HDX_HOSTNAME")
    if is_unresolved_secret(host):
        raise secret_error("HYDROLIX_HOST/HDX_HOSTNAME")
    if not host:
        raise SystemExit("HYDROLIX_HOST or HDX_HOSTNAME is required.")

    scheme = first_env(env, "HDX_SCHEME") or "https"
    url = normalize_query_url(host, scheme)
    headers = {"Content-Type": "text/plain; charset=utf-8", "Accept": "application/json"}

    token = first_env(env, "HYDROLIX_TOKEN", "HDX_TOKEN")
    if token:
        if is_unresolved_secret(token):
            raise secret_error("HYDROLIX_TOKEN/HDX_TOKEN")
        headers["Authorization"] = f"Bearer {token}"
        auth_mode = "bearer"
    else:
        user = first_env(env, "HYDROLIX_USER", "HDX_USERNAME")
        password = first_env(env, "HYDROLIX_PASSWORD", "HDX_PASSWORD")
        if is_unresolved_secret(user):
            raise secret_error("HYDROLIX_USER/HDX_USERNAME")
        if is_unresolved_secret(password):
            raise secret_error("HYDROLIX_PASSWORD/HDX_PASSWORD")
        if not user or not password:
            raise SystemExit(
                "Provide HYDROLIX_TOKEN/HDX_TOKEN or HYDROLIX_USER/HYDROLIX_PASSWORD "
                "(HDX_USERNAME/HDX_PASSWORD also accepted)."
            )
        encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        auth_mode = "basic"

    return QueryConfig(
        url=url,
        headers=headers,
        verify_tls=not bool_env(first_env(env, "HDX_INSECURE_TLS")),
        auth_mode=auth_mode,
    )

def ensure_format_json(sql: str) -> str:
    if FORMAT_RE.search(sql.rstrip()):
        return sql
    return f"{sql.rstrip(';')} FORMAT JSON"

def reject_invalid_sql(sql: str, *, require_time_range: bool) -> None:
    compact = sql.strip()
    if not compact:
        raise SystemExit("SQL is empty.")
    body = re.sub(r"\bFORMAT\s+\w+\s*$", "", compact, flags=re.IGNORECASE).strip()
    statements = [part.strip() for part in body.split(";") if part.strip()]
    if len(statements) > 1:
        raise SystemExit("SQL must contain exactly one SELECT statement.")
    if not re.match(r"^(?:WITH\b[\s\S]+?\bSELECT\b|SELECT\b)", statements[0], re.IGNORECASE):
        raise SystemExit("Only SELECT SQL is allowed.")
    if PLACEHOLDER_RE.search(compact):
        raise SystemExit("SQL contains unresolved placeholders.")
    if require_time_range and not TIME_PREDICATE_RE.search(compact):
        raise SystemExit("SQL must include a timestamp or reqTimeSec predicate.")

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

def read_sql(args: argparse.Namespace) -> str:
    if args.preset:
        if args.sql or args.sql_file:
            raise SystemExit("Use either --preset or --sql/--sql-file, not both.")
        sql = render_preset_sql(args)
    else:
        if args.sql and args.sql_file:
            raise SystemExit("Use either --sql or --sql-file, not both.")
        if args.sql:
            sql = args.sql
        elif args.sql_file:
            sql = Path(args.sql_file).read_text(encoding="utf-8")
        elif not sys.stdin.isatty():
            sql = sys.stdin.read()
        else:
            raise SystemExit("Provide SQL with --preset, --sql, --sql-file, or stdin.")
        sql = apply_time_window_to_sql(sql.strip(), args)
    sql = ensure_format_json(sql)
    reject_invalid_sql(sql, require_time_range=args.require_time_range)
    return sql

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

__all__ = [name for name in globals() if not name.startswith("__")]
