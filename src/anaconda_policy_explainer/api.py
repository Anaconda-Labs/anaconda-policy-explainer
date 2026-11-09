"""Read channel policies and per-file policy results from the Anaconda API.

Parsing is kept separate from
HTTP so it can be tested against recorded responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

TIMEOUT = 10.0
PAGE = 200


@dataclass(frozen=True)
class ChannelPolicy:
    name: str
    summary: str


@dataclass(frozen=True)
class FileStatus:
    subdir: str
    name: str
    version: str
    build: str
    build_number: int
    depends: tuple[str, ...]
    removed: bool
    reason: str | None


def _render(node: dict[str, Any]) -> str:
    if node.get("type") == "simple":
        return f"{node['facet']} {node['comparator']} {node['criterion']}"
    operator = node.get("operator", "or")
    parts: list[str] = []
    for child in node.get("subfilters", []):
        text = _render(child)
        nested = child.get("type") == "compound" and child.get("operator") != operator
        if nested and len(child.get("subfilters", [])) > 1:
            text = f"({text})"
        if text and text not in parts:
            parts.append(text)
    return f" {operator} ".join(parts)


def summarize_filter(raw_filter: dict[str, Any], schema_version: int = 1) -> str:
    """One-line summary of what a policy removes and what it keeps anyway.

    Schema v2 names its sections; schema v1 is positional: the first
    subfilter removes packages, the second adds them back.
    """
    if schema_version == 2 and "remove_packages" in raw_filter:
        removes = raw_filter.get("remove_packages") or {}
        keeps = raw_filter.get("add_packages") or {}
    else:
        sections = raw_filter.get("subfilters", [])
        removes = sections[0] if sections else {}
        keeps = sections[1] if len(sections) > 1 else {}
    parts = []
    if text := _render(removes) if removes else "":
        parts.append(f"removes {text}")
    if text := _render(keeps) if keeps else "":
        parts.append(f"keeps {text}")
    return "; ".join(parts)


def parse_versions(payload: dict[str, Any], name: str) -> list[str] | None:
    """Versions the unfiltered source has for ``name``, newest first.

    None means the package does not exist upstream at all.
    """
    for item in payload.get("items", []):
        if item.get("name") == name:
            return list(item.get("available_versions", []))
    return None


def parse_files(payload: dict[str, Any]) -> list[FileStatus]:
    files = []
    for item in payload.get("items", []):
        record = item.get("metadata", {}).get("repodata_record.json", {})
        files.append(
            FileStatus(
                subdir=record.get("subdir") or item["ckey"].split("/")[0],
                name=record["name"],
                version=record["version"],
                build=record["build"],
                build_number=record.get("build_number") or 0,
                depends=tuple(record.get("depends") or ()),
                removed=bool(item.get("removed_by_policy")),
                reason=item.get("removed_reason"),
            )
        )
    return files


def default_site_domain() -> str:
    from anaconda_auth.config import AnacondaAuthSitesConfig

    return str(AnacondaAuthSitesConfig.load_site().domain)


class PolicyApi:
    """Authenticated client for one auth domain, configured by anaconda-auth."""

    def __init__(self, domain: str) -> None:
        from anaconda_auth.client import BaseClient

        self._client = BaseClient(domain=domain)

    def _get(self, path: str, **params: Any) -> Any:
        response = self._client.get(path, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def channel_policy(self, org: str, channel: str) -> ChannelPolicy | None:
        current = self._get(
            f"/api/organizations/{org}/channel-policies/{org}/{channel}/current"
        )
        policy_id = current.get("policy_id")
        if not policy_id:
            return None
        # repo-policies/v2/{id} rejects schema v1 policies; the unversioned
        # route returns either schema.
        policy = self._get(f"/api/organizations/{org}/repo-policies/{policy_id}")
        summary = summarize_filter(
            policy.get("filter") or {}, policy.get("schema_version") or 1
        )
        return ChannelPolicy(policy.get("name") or current["policy_name"], summary)

    def versions(self, org: str, channel: str, name: str) -> list[str] | None:
        payload = self._get(
            f"/api/organizations/{org}/channels/{org}/{channel}/artifacts",
            only_names=name,
        )
        return parse_versions(payload, name)

    def files(
        self, org: str, channel: str, name: str, version: str
    ) -> list[FileStatus]:
        path = (
            f"/api/organizations/{org}/channels/{org}/{channel}"
            f"/artifacts/conda/{name}/files"
        )
        payload = self._get(path, version=version, limit=PAGE)
        total = payload.get("total_count", 0)
        if total > len(payload.get("items", [])):
            payload = self._get(path, version=version, limit=total)
        return parse_files(payload)
