from __future__ import annotations

from pathlib import Path

from reportkit.extract import hydrolix as hdx

from .constants import CLUSTER_DIR_ENV, SENTINEL_ENV


QueryConfig = hdx.QueryConfig


CredentialState = hdx.CredentialState


parse_env_file = hdx.parse_env_file


file_may_need_op = hdx.file_may_need_op


normalize_query_url = hdx.normalize_query_url


bool_env = hdx.bool_env


first_env = hdx.first_env


is_unresolved_secret = hdx.is_unresolved_secret


secret_error = hdx.secret_error


build_query_config = hdx.build_query_config


ensure_format_json = hdx.ensure_format_json


reject_invalid_sql = hdx.reject_invalid_sql


query_hydrolix = hdx.query_hydrolix


shape_output = hdx.shape_output


write_json_atomic = hdx.write_json_atomic


response_row_count = hdx.response_row_count


extract_query_stats = hdx.extract_query_stats


def cluster_env_dir(env: dict[str, str] | None = None) -> Path:
    return hdx.cluster_env_dir(env, cluster_dir_env=CLUSTER_DIR_ENV)


def cluster_env_path(alias: str, env: dict[str, str] | None = None) -> Path:
    return hdx.cluster_env_path(alias, env, cluster_dir_env=CLUSTER_DIR_ENV)


def should_reexec_with_op(path: Path, env: dict[str, str] | None = None) -> bool:
    return hdx.should_reexec_with_op(path, env, sentinel_env=SENTINEL_ENV)


def reexec_with_op(path: Path) -> None:
    return hdx.reexec_with_op(path, sentinel_env=SENTINEL_ENV)


def resolved_cluster_env_path(cluster: str | None) -> Path | None:
    return hdx.resolved_cluster_env_path(cluster, cluster_dir_env=CLUSTER_DIR_ENV)


def merged_environment(cluster: str | None) -> tuple[dict[str, str], Path | None]:
    return hdx.merged_environment(
        cluster,
        cluster_dir_env=CLUSTER_DIR_ENV,
        sentinel_env=SENTINEL_ENV,
    )


def credential_state(
    env: dict[str, str],
    env_path: Path | None = None,
) -> CredentialState:
    return hdx.credential_state(env, env_path, sentinel_env=SENTINEL_ENV)
