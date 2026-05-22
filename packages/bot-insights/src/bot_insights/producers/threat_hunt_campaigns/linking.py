"""Campaign linking and connected-component helpers."""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable

from .numbers import _cosine, _pearson


def _link_edge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any] | None:
    shared_ips = sorted(left["client_ips"] & right["client_ips"])
    path_cosine = _cosine(left["paths"], right["paths"])
    asn_cosine = _cosine(left["asns"], right["asns"])
    country_cosine = _cosine(left["countries"], right["countries"])
    temporal_correlation = _pearson(left["hours"], right["hours"])
    shared_paths = sorted(set(left["paths"]) & set(right["paths"]))
    link_types = []

    if len(shared_ips) >= 3:
        link_types.append("shared_ips")
    if path_cosine is not None and path_cosine >= 0.85 and len(shared_paths) >= 3:
        link_types.append("shared_endpoint_profile")
    if (
        temporal_correlation is not None
        and temporal_correlation <= -0.6
        and asn_cosine is not None
        and asn_cosine >= 0.7
    ):
        link_types.append("temporal_rotation_asn_similarity")
    if (
        temporal_correlation is not None
        and temporal_correlation >= 0.75
        and path_cosine is not None
        and path_cosine >= 0.7
    ):
        link_types.append("synchronized_timing_endpoint_similarity")

    if not link_types:
        return None

    return {
        "left_user_agent": left["user_agent"],
        "right_user_agent": right["user_agent"],
        "link_types": link_types,
        "shared_ip_count": len(shared_ips),
        "shared_ip_samples": shared_ips[:5],
        "path_cosine": path_cosine,
        "asn_cosine": asn_cosine,
        "country_cosine": country_cosine,
        "temporal_correlation": temporal_correlation,
        "shared_path_count": len(shared_paths),
        "shared_path_samples": shared_paths[:5],
        "path_similarity_available": path_cosine is not None,
        "temporal_similarity_available": temporal_correlation is not None,
        "asn_similarity_available": asn_cosine is not None,
    }


def _connected_components(nodes: Iterable[str], edges: list[dict[str, Any]]) -> list[list[str]]:
    graph: dict[str, set[str]] = {node: set() for node in nodes}
    for edge in edges:
        left = str(edge["left_user_agent"])
        right = str(edge["right_user_agent"])
        graph.setdefault(left, set()).add(right)
        graph.setdefault(right, set()).add(left)
    seen: set[str] = set()
    components = []
    for node in sorted(graph):
        if node in seen:
            continue
        queue: deque[str] = deque([node])
        seen.add(node)
        component = []
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbor in sorted(graph[current]):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        if len(component) >= 2:
            components.append(sorted(component))
    return components


def _campaign_sophistication(edges: list[dict[str, Any]], unique_asns: int, unique_countries: int) -> str:
    link_types = {link_type for edge in edges for link_type in edge.get("link_types", [])}
    if len(link_types) >= 3 or (unique_asns >= 3 and unique_countries >= 3):
        return "high"
    if len(link_types) >= 2 or unique_asns >= 2:
        return "moderate"
    return "basic"


def _temporal_pattern(edges: list[dict[str, Any]]) -> str:
    link_types = {link_type for edge in edges for link_type in edge.get("link_types", [])}
    if "temporal_rotation_asn_similarity" in link_types:
        return "rotating"
    if "synchronized_timing_endpoint_similarity" in link_types:
        return "synchronized"
    return "not_established"
