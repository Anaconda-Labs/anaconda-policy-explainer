"""Read channel policies and per-file policy results from the Anaconda API.

Parsing is kept separate from
HTTP so it can be tested against recorded responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .channels import PolicyChannel

TIMEOUT = 10.0
PAGE = 200


@dataclass(frozen=True)
class ChannelPolicy:
    name: str
    lines: tuple[str, ...]
    # The channel the policy filters, e.g. "main"; None for upload channels.
    source: str | None


@dataclass(frozen=True)
class FileStatus:
    subdir: str
    fn: str
    removed: bool
    reason: str | None
    cve_statuses: tuple[str, ...] = ()


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


@dataclass(frozen=True)
class ChannelDetails:
    policy_id: str | None
    policy_name: str | None
    source: str | None


def parse_details(payload: dict[str, Any]) -> ChannelDetails:
    policy = payload.get("assigned_policy") or {}
    sources = payload.get("sources") or []
    return ChannelDetails(
        policy.get("id"), policy.get("name"), sources[0] if sources else None
    )


def parse_anaconda_details(channels: list[dict[str, Any]], name: str) -> ChannelDetails:
    """Policy of the Anaconda channel ``name`` from an organization's channel list.

    The per-channel details route reports no policy for Anaconda channels;
    the list does.
    """
    for entry in channels:
        if entry.get("type") == "anaconda" and entry.get("name") == name:
            return parse_details(entry)
    return ChannelDetails(None, None, None)


def parse_files(payload: dict[str, Any]) -> list[FileStatus]:
    files = []
    for item in payload.get("items", []):
        subdir, _, fn = item["ckey"].partition("/")
        cves = (item.get("metadata") or {}).get("cves") or []
        files.append(
            FileStatus(
                subdir=subdir,
                fn=fn,
                removed=bool(item.get("removed_by_policy")),
                reason=item.get("removed_reason"),
                cve_statuses=tuple(c.get("status") or "unknown" for c in cves),
            )
        )
    return files


def repo_org_id(channel_url: str) -> str | None:
    """Organization the repo applies to the user's credentials for a channel.

    The repo names it in an ``x-auth-org-id`` response header; a HEAD request
    for the noarch index is enough. Uses conda's session, so the credentials
    are the ones conda used.
    """
    from conda.gateways.connection.session import get_session

    url = f"{channel_url.rstrip('/')}/noarch/repodata.json"
    response = get_session(url).head(url, timeout=TIMEOUT)
    return response.headers.get("x-auth-org-id") or None


def default_site_domain() -> str:
    from anaconda_auth.config import AnacondaAuthSitesConfig

    return str(AnacondaAuthSitesConfig.load_site().domain)


class PolicyApi:
    """Authenticated client for one auth domain, configured by anaconda-auth."""

    def __init__(self, domain: str) -> None:
        from anaconda_auth.client import BaseClient

        self._client = BaseClient(domain=domain)

    def _get(self, path: str, **params: Any) -> Any:
        """GET with one retry for server errors, rate limiting and connection
        problems."""
        import requests

        for attempt in range(2):
            try:
                response = self._client.get(path, params=params, timeout=TIMEOUT)
                response.raise_for_status()
                return response.json()
            except requests.RequestException as error:
                status = error.response.status_code if error.response is not None else 0
                if attempt or 400 <= status < 500 and status != 429:
                    raise

    def org_name(self, org_id: str) -> str | None:
        name = self._get(f"/api/auth/organizations/{org_id}").get("name")
        return str(name) if name else None

    def channel_policy(self, channel: PolicyChannel) -> ChannelPolicy | None:
        org = channel.org
        if channel.anaconda:
            channels = self._get(f"/api/organizations/{org}/channels")
            details = parse_anaconda_details(channels, channel.channel)
        else:
            details = parse_details(self._get(f"{channel.api_path}/details"))
        if not details.policy_id:
            return None
        # repo-policies/v2/{id} rejects schema v1 policies; the unversioned
        # route returns either schema.
        policy = self._get(
            f"/api/organizations/{org}/repo-policies/{details.policy_id}"
        )
        lines = policy_lines(
            policy.get("filter") or {}, policy.get("schema_version") or 1
        )
        name = policy.get("name") or details.policy_name or details.policy_id
        return ChannelPolicy(name, tuple(lines), details.source)

    def files(
        self, channel: PolicyChannel, name: str, version: str
    ) -> list[FileStatus]:
        path = f"{channel.api_path}/artifacts/conda/{name}/files"
        payload = self._get(path, version=version, limit=PAGE)
        total = payload.get("total_count", 0)
        if total > len(payload.get("items", [])):
            payload = self._get(path, version=version, limit=total)
        return parse_files(payload)
