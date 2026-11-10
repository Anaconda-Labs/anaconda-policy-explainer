"""Explain a failed solve by re-solving with the unfiltered channels."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from dataclasses import dataclass

from conda.base.context import context
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from .api import ChannelPolicy
from .api import PolicyApi
from .api import default_site_domain
from .channels import PolicyChannel
from .channels import policy_channels
from .plugin import Solve
from .report import Entry
from .report import dist
from .report import file_status
from .report import render
from .report import why
from .resolve import taken_from
from .resolve import unfiltered_solve
from .source import local_channel
from .source import unfiltered_url

log = logging.getLogger(__name__)

WORKERS = 8
BUDGET = 30.0  # seconds for API lookups per channel


@dataclass(frozen=True)
class _Policed:
    channel: PolicyChannel
    policy: ChannelPolicy
    api: PolicyApi
    source_url: str


def _policed(channels: Iterable[PolicyChannel]) -> list[_Policed]:
    found = []
    for channel in channels:
        api = PolicyApi(channel.auth_domain)
        policy = api.channel_policy(channel.org, channel.channel)
        source_url = unfiltered_url(channel, policy.source) if policy else None
        if policy and source_url:
            found.append(_Policed(channel, policy, api, source_url))
    return found


def _site_note(channel: PolicyChannel) -> list[str]:
    default = default_site_domain()
    if default == channel.auth_domain:
        return []
    return [
        f"channel authenticates against {channel.auth_domain};"
        f" your default anaconda-auth site is {default}"
    ]


def _entries(
    policed: _Policed,
    records: list[PackageRecord],
    solution: tuple[PackageRecord, ...],
    requested: list[MatchSpec],
) -> list[Entry]:
    """One entry per record; records the API could not check within the time
    budget are kept, marked as not checked."""

    def entry(record: PackageRecord) -> Entry:
        files = policed.api.files(
            policed.channel.org, policed.channel.channel, record.name, record.version
        )
        status = file_status(record, files)
        return Entry(
            dist(record),
            why(record, solution, requested),
            bool(status and status.removed),
            status.reason if status else None,
            status.cve_statuses if status else (),
        )

    def unchecked(record: PackageRecord, cause: str) -> Entry:
        log.debug("could not check %s: %s", dist(record), cause)
        reason = f"not checked ({cause})"
        return Entry(dist(record), why(record, solution, requested), False, reason)

    pool = ThreadPoolExecutor(WORKERS)
    futures = {pool.submit(entry, record): record for record in records}
    done, _ = wait(futures, timeout=BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    entries = []
    for future, record in futures.items():
        if future not in done:
            entries.append(unchecked(record, f"no answer within {BUDGET:.0f}s"))
        elif error := future.exception():
            entries.append(unchecked(record, type(error).__name__))
        else:
            entries.append(future.result())
    return entries


def explain(solve: Solve) -> list[str]:
    """Report sections, one per channel policy that explains the failure."""
    channels = solve.channels or tuple(context.channels)
    prefix = solve.prefix or str(context.target_prefix)
    subdirs = solve.subdirs or tuple(context.subdirs)
    requested = solve.specs_to_add
    policed = _policed(policy_channels(channels, context.channel_settings))
    if not policed:
        return []
    local = {
        url: local_channel(url, subdirs)
        for url in dict.fromkeys(p.source_url for p in policed)
    }
    solution = unfiltered_solve(
        prefix, channels, local.values(), subdirs, requested, solve.specs_to_remove
    )
    sections = []
    for p in policed:
        records = taken_from(solution, local[p.source_url])
        entries = _entries(p, records, solution, requested)
        notes = _site_note(p.channel)
        color = sys.stderr.isatty() and not context.json
        section = render(p.channel, p.policy, entries, notes, color=color)
        if section:
            sections.append(section)
    return sections
