"""Hydrolix capture primitives used by report producers."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TIME_PREDICATE_RE = re.compile(
    r"(?:\b(?:timestamp|reqTimeSec)\b|`toStartOf(?:Minute|Hour|Day)\(reqTimeSec\)`)\s*(?:=|!=|<>|>=|<=|>|<|BETWEEN|IN)(?:\s|\(|'|$)",
    re.IGNORECASE,
)
FORMAT_RE = re.compile(r"\bFORMAT\s+\w+\b", re.IGNORECASE)
PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}|\$\{[^}]+\}")
SENTINEL_ENV = "REPORTKIT_CAPTURE_OP_RUN"
CLUSTER_DIR_ENV = ("HYDROLIX_CLUSTER_DIR", "HDX_CLUSTER_DIR")
DEFAULT_HANDOFF_SCHEMA = "hydrolix_mcp_query_request.v1"


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


def cluster_env_dir(
    env: dict[str, str] | None = None,
    *,
    cluster_dir_env: tuple[str, ...] = CLUSTER_DIR_ENV,
) -> Path:
    source = env or os.environ
    for key in cluster_dir_env:
        if source.get(key):
            return Path(source[key]).expanduser()
    return Path.home() / ".config/hydrolix/clusters"


def cluster_env_path(
    alias: str,
    env: dict[str, str] | None = None,
    *,
    cluster_dir_env: tuple[str, ...] = CLUSTER_DIR_ENV,
) -> Path:
    path = Path(alias).expanduser()
    if path.suffix == ".env" or path.is_absolute() or "/" in alias:
        return path
    return cluster_env_dir(env, cluster_dir_env=cluster_dir_env) / f"{alias}.env"


def file_may_need_op(path: Path) -> bool:
    return path.exists() and "op://" in path.read_text(encoding="utf-8")


def should_reexec_with_op(
    path: Path,
    env: dict[str, str] | None = None,
    *,
    sentinel_env: str = SENTINEL_ENV,
) -> bool:
    source = env or os.environ
    return (
        path.exists()
        and source.get(sentinel_env) != "1"
        and file_may_need_op(path)
        and shutil.which("op") is not None
    )


def reexec_with_op(path: Path, *, sentinel_env: str = SENTINEL_ENV) -> None:
    env = dict(os.environ)
    env[sentinel_env] = "1"
    command = [
        "op",
        "run",
        "--env-file",
        str(path),
        "--",
        sys.executable,
        str(Path(sys.argv[0]).resolve()),
        *sys.argv[1:],
    ]
    os.execvpe("op", command, env)


def resolved_cluster_env_path(
    cluster: str | None,
    *,
    cluster_dir_env: tuple[str, ...] = CLUSTER_DIR_ENV,
) -> Path | None:
    if not cluster:
        return None
    env_path = cluster_env_path(cluster, cluster_dir_env=cluster_dir_env)
    if env_path.exists():
        return env_path
    if "/" in cluster or cluster.endswith(".env"):
        raise SystemExit(f"Cluster env file does not exist: {env_path}")
    return None


def merged_environment(
    cluster: str | None,
    *,
    cluster_dir_env: tuple[str, ...] = CLUSTER_DIR_ENV,
    sentinel_env: str = SENTINEL_ENV,
) -> tuple[dict[str, str], Path | None]:
    env_file_values: dict[str, str] = {}
    env_path = resolved_cluster_env_path(cluster, cluster_dir_env=cluster_dir_env)
    if env_path:
        if should_reexec_with_op(env_path, sentinel_env=sentinel_env):
            reexec_with_op(env_path, sentinel_env=sentinel_env)
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


def credential_state(
    env: dict[str, str],
    env_path: Path | None = None,
    *,
    sentinel_env: str = SENTINEL_ENV,
) -> CredentialState:
    host = first_env(env, "HYDROLIX_HOST", "HDX_HOSTNAME")
    token = first_env(env, "HYDROLIX_TOKEN", "HDX_TOKEN")
    user = first_env(env, "HYDROLIX_USER", "HDX_USERNAME")
    password = first_env(env, "HYDROLIX_PASSWORD", "HDX_PASSWORD")

    unresolved = [
        label
        for label, value in (
            ("HYDROLIX_HOST/HDX_HOSTNAME", host),
            ("HYDROLIX_TOKEN/HDX_TOKEN", token),
            ("HYDROLIX_USER/HDX_USERNAME", user),
            ("HYDROLIX_PASSWORD/HDX_PASSWORD", password),
        )
        if is_unresolved_secret(value)
    ]

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
    op_resolution = "not_required"
    if unresolved:
        configured = False
        op_resolution = "unresolved"
    elif env_path and file_may_need_op(env_path):
        op_resolution = "resolved_by_op_run" if os.environ.get(sentinel_env) == "1" else "resolved"

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


def split_sql_statements(sql: str) -> list[str]:
    statements: list[str] = []
    start = 0
    in_single_quote = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            if in_single_quote and i + 1 < len(sql) and sql[i + 1] == "'":
                i += 2
                continue
            in_single_quote = not in_single_quote
        elif ch == ";" and not in_single_quote:
            statement = sql[start:i].strip()
            if statement:
                statements.append(statement)
            start = i + 1
        i += 1
    tail = sql[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def reject_invalid_sql(sql: str, *, require_time_range: bool) -> None:
    compact = sql.strip()
    if not compact:
        raise SystemExit("SQL is empty.")
    body = re.sub(r"\bFORMAT\s+\w+\s*$", "", compact, flags=re.IGNORECASE).strip()
    statements = split_sql_statements(body)
    if len(statements) > 1:
        raise SystemExit("SQL must contain exactly one SELECT statement.")
    if not re.match(r"^(?:WITH\b[\s\S]+?\bSELECT\b|SELECT\b)", statements[0], re.IGNORECASE):
        raise SystemExit("Only SELECT SQL is allowed.")
    if PLACEHOLDER_RE.search(compact):
        raise SystemExit("SQL contains unresolved placeholders.")
    if require_time_range and not TIME_PREDICATE_RE.search(compact):
        raise SystemExit("SQL must include a timestamp or reqTimeSec predicate.")


def query_hydrolix(sql: str, config: QueryConfig) -> tuple[dict[str, Any], dict[str, Any]]:
    context = None
    if config.url.startswith("https://") and not config.verify_tls:
        context = ssl._create_unverified_context()
    request = urllib.request.Request(
        config.url,
        data=sql.encode("utf-8"),
        headers=config.headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context) as response:
            body = response.read()
            headers = dict(response.headers.items())
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise SystemExit(f"Hydrolix query failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Hydrolix query failed: {exc.reason}") from exc

    try:
        parsed = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit("Hydrolix query did not return valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("Hydrolix query JSON was not a ClickHouse object.")
    return parsed, {"status": status, "headers": headers, "response_bytes": len(body)}


def shape_output(response: Any, shape: str) -> Any:
    if shape == "clickhouse":
        return response
    if shape == "rows":
        if isinstance(response, dict) and isinstance(response.get("data"), list):
            return response["data"]
        if isinstance(response, dict) and isinstance(response.get("rows"), list):
            return response["rows"]
        if isinstance(response, list):
            return response
        raise SystemExit("Cannot shape Hydrolix response as rows: JSON has no data or rows array.")
    raise AssertionError(shape)


def write_json_atomic(path: Path, data: Any) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp_path.replace(path)
    return path.stat().st_size


def response_row_count(response: Any, shaped: Any) -> int | None:
    if isinstance(shaped, list):
        return len(shaped)
    if isinstance(response, dict):
        rows = response.get("rows")
        if isinstance(rows, int):
            return rows
        data = response.get("data")
        if isinstance(data, list):
            return len(data)
    return None


def extract_query_stats(meta: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    if isinstance(response.get("statistics"), dict):
        stats["statistics"] = response["statistics"]
    headers = meta.get("headers") or {}
    for key, value in headers.items():
        if key.lower() == "x-hdx-query-stats":
            try:
                stats["hdx_query_stats"] = json.loads(value)
            except json.JSONDecodeError:
                stats["hdx_query_stats"] = value
    return stats


def build_handoff_packet(
    *,
    cluster: str | None,
    database: str | None,
    sql: str,
    credentials: CredentialState,
    output_path: Path,
    shape: str,
    schema_version: str = DEFAULT_HANDOFF_SCHEMA,
    preset: str | None = None,
    report_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    instruction = (
        "Run Hydrolix MCP run_select_query with the supplied cluster and validated_sql, "
        f"then save the complete JSON result to {output_path}."
    )
    return {
        "schema_version": schema_version,
        "cluster": cluster,
        "database": database,
        "preset": preset,
        "report_context": {
            key: value for key, value in (report_context or {}).items() if value is not None
        },
        "validated_sql": sql,
        "expected_output_shape": shape,
        "target_raw_output_path": str(output_path),
        "mcp": {
            "server": "hydrolix_mux",
            "tool": "run_select_query",
            "arguments": {
                "cluster": cluster,
                "query": sql,
            },
        },
        "instruction": instruction,
        "credential_status": {
            "configured": False,
            "missing": list(credentials.missing),
            "unresolved_op": list(credentials.unresolved_op),
            "env_file": credentials.env_file,
            "op_resolution": credentials.op_resolution,
        },
    }
