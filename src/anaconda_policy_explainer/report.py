"""Turn the packages an unfiltered solve needed into one section per policy."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from .api import ChannelPolicy
from .api import FileStatus
from .channels import PolicyChannel

INDENT = " " * 6  # aligns under conda's "  - (hint_code) " hint prefix

_CVE_REASON = re.compile(r"CVE score of ([\d.]+) is greater than ([\d.]+)")


@dataclass(frozen=True)
class Entry:
    """A package the solve needed from outside the policy channel."""

    label: str
    why: str
    removed: bool
    reason: str | None


def dist(record: PackageRecord) -> str:
    return f"{record.name}-{record.version}-{record.build}"


def why(
    record: PackageRecord,
    solution: Iterable[PackageRecord],
    requested: Iterable[MatchSpec],
) -> str:
    """ "requested", or which packages in the solution depend on ``record``."""
    if any(spec.name == record.name and spec.match(record) for spec in requested):
        return "requested"
    parents = sorted(
        dist(other)
        for other in solution
        if other is not record
        and any(
            (spec := MatchSpec(dep)).name == record.name and spec.match(record)
            for dep in other.depends
        )
    )
    if not parents:
        return "needed"
    others = len(parents) - 1
    return f"needed by {parents[0]}" + (f" and {others} others" if others else "")


def file_status(
    record: PackageRecord, files: Iterable[FileStatus]
) -> FileStatus | None:
    """The API's entry for exactly this file, or its other package format."""
    stem = record.fn.removesuffix(".conda").removesuffix(".tar.bz2")
    same_subdir = [f for f in files if f.subdir == record.subdir]
    exact = [f for f in same_subdir if f.fn == record.fn]
    other_format = [f for f in same_subdir if f.fn.startswith(stem + ".")]
    matches = exact or other_format
    return matches[0] if matches else None


def shorten(reasons: Iterable[str]) -> str:
    """Compact reasons: CVE thresholds collapse to the highest score."""
    cves: list[tuple[float, str]] = []
    other: list[str] = []
    for reason in reasons:
        match = _CVE_REASON.fullmatch(reason)
        if match:
            cves.append((float(match[1]), f"CVE {match[1]} > {match[2]}"))
        elif reason not in other:
            other.append(reason)
    if cves:
        other.insert(0, max(cves)[1])
    return "; ".join(other)


def render(
    channel: PolicyChannel,
    policy: ChannelPolicy,
    entries: Iterable[Entry],
    notes: Iterable[str] = (),
) -> str | None:
    """Report section for one channel policy, or None if it explains nothing."""
    ordered = sorted(entries, key=lambda e: (e.why != "requested", e.label))
    removed = [e for e in ordered if e.removed]
    absent = [e for e in ordered if not e.removed]
    if not removed and not absent:
        return None
    lines = [
        f'{channel.org}/{channel.channel} is filtered by policy "{policy.name}"',
        *(f"{INDENT}{line}" for line in policy.lines),
    ]
    if removed:
        lines.append(f"{INDENT}blocked:")
        for e in removed:
            reason = f": {shorten([e.reason])}" if e.reason else ""
            lines.append(f"{INDENT}  {e.label} ({e.why}){reason}")
    if absent:
        lines.append(f"{INDENT}not in the channel yet:")
        lines.extend(f"{INDENT}  {e.label} ({e.why})" for e in absent)
    lines.extend(f"{INDENT}note: {note}" for note in notes)
    return "\n".join(lines)
