"""Explain a failed solve: find blocked specs, ask the API why, render."""

from __future__ import annotations

import os
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from conda.base.context import context
from conda.core.prefix_data import PrefixData
from conda.core.subdir_data import SubdirData
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from .api import PolicyApi
from .api import default_site_domain
from .candidates import Query
from .candidates import find_blocked
from .channels import PolicyChannel
from .channels import policy_channels
from .report import Blocked
from .report import Entry
from .report import group
from .report import pick_versions
from .report import render
from .report import version_result

WORKERS = 8


def _specs(
    requested: Iterable[MatchSpec], packages: Iterable[object]
) -> list[MatchSpec]:
    specs: dict[str, MatchSpec] = {}
    for item in (*requested, *packages):
        spec = item if isinstance(item, MatchSpec) else MatchSpec(str(item))
        specs.setdefault(str(spec), spec)
    return list(specs.values())


def _query(subdirs: Sequence[str]) -> Query:
    installed: list[PackageRecord] = []
    prefix = context.target_prefix
    if prefix and os.path.isdir(os.path.join(prefix, "conda-meta")):
        installed = list(PrefixData(prefix).iter_records())

    def query(spec: MatchSpec) -> Iterator[PackageRecord]:
        yield from SubdirData.query_all(
            spec, channels=context.channels, subdirs=subdirs
        )
        yield from (record for record in installed if spec.match(record))

    return query


def _entry(
    api: PolicyApi, channel: PolicyChannel, blocked: Blocked, subdirs: Sequence[str]
) -> Entry:
    versions = api.versions(channel.org, channel.channel, blocked.name) or []
    results = []
    for version, spec in pick_versions(blocked.specs, versions):
        files = api.files(channel.org, channel.channel, blocked.name, version)
        result = version_result(spec, version, files, subdirs)
        if result is not None:
            results.append(result)
    return Entry(blocked.label, blocked.why, tuple(results))


def _note(channel: PolicyChannel) -> str | None:
    default = default_site_domain()
    if default == channel.auth_domain:
        return None
    return (
        f"channel authenticates against {channel.auth_domain};"
        f" your default anaconda-auth site is {default}"
    )


def explain(requested: Iterable[MatchSpec], packages: Iterable[object]) -> list[str]:
    """Report sections, one per channel policy that explains the failure."""
    channels = policy_channels(context.channels, context.channel_settings)
    if not channels:
        return []
    subdirs = (context.subdir, "noarch")
    findings = find_blocked(_specs(requested, packages), _query(subdirs))
    wanted = group(findings)
    if not wanted:
        return []

    sections = []
    for channel in channels:
        api = PolicyApi(channel.auth_domain)
        policy = api.channel_policy(channel.org, channel.channel)
        if policy is None:
            continue
        with ThreadPoolExecutor(WORKERS) as pool:
            entries = list(pool.map(lambda b: _entry(api, channel, b, subdirs), wanted))
        section = render(channel, policy, entries, _note(channel))
        if section:
            sections.append(section)
    return sections
