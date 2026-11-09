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
    lines: tuple[str, ...]


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


GROUP_WORDS = {"or": "any of", "and": "all of"}


def _rule(node: dict[str, Any]) -> str:
    rule = f"{node['facet']} {node['comparator']} {node['criterion']}"
    return f"{rule} days" if node["facet"] == "package_age" else rule


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Children of a group, with same-operator subgroups merged into it and
    single-child subgroups replaced by their child."""
    children: list[dict[str, Any]] = []
    for child in node.get("subfilters", []):
        child = _collapse(child)
        if child.get("type") == "compound" and child.get("operator") == node.get(
            "operator"
        ):
            children.extend(_children(child))
        elif child not in children:
            children.append(child)
    return children


def _collapse(node: dict[str, Any]) -> dict[str, Any]:
    if node.get("type") != "compound":
        return node
    children = _children(node)
    if len(children) == 1:
        return children[0]
    return {**node, "subfilters": children}


def _group_lines(children: list[dict[str, Any]], depth: int) -> list[str]:
    lines = []
    for child in children:
        pad = "  " * depth
        if child.get("type") == "compound":
            lines.append(f"{pad}{GROUP_WORDS.get(child.get('operator', 'or'))}:")
            lines.extend(_group_lines(child["subfilters"], depth + 1))
        else:
            lines.append(f"{pad}{_rule(child)}")
    return lines


def _section(verb: str, node: dict[str, Any]) -> list[str]:
    node = _collapse(node)
    if node.get("type") == "compound":
        if not node.get("subfilters"):
            return []
        word = GROUP_WORDS.get(node.get("operator", "or"))
        return [f"{verb} packages where {word}:", *_group_lines(node["subfilters"], 1)]
    return [f"{verb} packages where:", f"  {_rule(node)}"]


def policy_lines(raw_filter: dict[str, Any], schema_version: int = 1) -> list[str]:
    """The policy as indented lines, one rule per line, in evaluation order.

    Schema v1 is positional: the first subfilter removes packages, the second
    keeps some of those anyway. Schema v2 names its sections: add_packages
    selects packages, remove_packages removes from that selection.
    """
    if schema_version == 2 and "remove_packages" in raw_filter:
        sections = [
            ("adds", raw_filter.get("add_packages")),
            ("removes", raw_filter.get("remove_packages")),
        ]
    else:
        subfilters = raw_filter.get("subfilters", [])
        sections = [
            ("removes", subfilters[0] if subfilters else None),
            ("keeps", subfilters[1] if len(subfilters) > 1 else None),
        ]
    return [line for verb, node in sections if node for line in _section(verb, node)]


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
        lines = policy_lines(
            policy.get("filter") or {}, policy.get("schema_version") or 1
        )
        name = policy.get("name") or current["policy_name"]
        return ChannelPolicy(name, tuple(lines))

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
