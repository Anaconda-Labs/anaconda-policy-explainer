"""Explain a failed solve: find blocked specs, ask the API why, render."""

from __future__ import annotations

import os
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait

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
BUDGET = 30.0  # seconds for API lookups per channel


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


def _site_note(channel: PolicyChannel) -> list[str]:
    default = default_site_domain()
    if default == channel.auth_domain:
        return []
    return [
        f"channel authenticates against {channel.auth_domain};"
        f" your default anaconda-auth site is {default}"
    ]


def _lookup(
    api: PolicyApi,
    channel: PolicyChannel,
    wanted: list[Blocked],
    subdirs: Sequence[str],
) -> tuple[list[Entry], int]:
    """Entries looked up within the time budget, and how many were not."""
    pool = ThreadPoolExecutor(WORKERS)
    futures = [pool.submit(_entry, api, channel, b, subdirs) for b in wanted]
    done, pending = wait(futures, timeout=BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    entries = [f.result() for f in futures if f in done and f.exception() is None]
    return entries, len(pending)


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
        entries, unchecked = _lookup(api, channel, wanted, subdirs)
        notes = _site_note(channel)
        if unchecked:
            notes.append(f"{unchecked} more packages not checked within {BUDGET:.0f}s")
        section = render(channel, policy, entries, notes)
        if section:
            sections.append(section)
    return sections
