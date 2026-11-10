"""Turn the packages an unfiltered solve needed into one section per policy."""

from __future__ import annotations

import io
import re
import shutil
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord
from rich import box
from rich.console import Console
from rich.table import Table

from .api import ChannelPolicy
from .api import FileStatus
from .channels import PolicyChannel

INDENT = " " * 6  # aligns under conda's "  - (hint_code) " hint prefix
REQUESTED = "your request"

_CVE_REASON = re.compile(r"CVE score of ([\d.]+) is greater than ([\d.]+)")


@dataclass(frozen=True)
class Entry:
    """A package the solve needed from outside the policy channel."""

    label: str
    why: str
    removed: bool
    reason: str | None
    cve_statuses: tuple[str, ...] = ()


def dist(record: PackageRecord) -> str:
    return f"{record.name}-{record.version}-{record.build}"


def why(
    record: PackageRecord,
    solution: Iterable[PackageRecord],
    requested: Iterable[MatchSpec],
) -> str:
    """REQUESTED, or the packages in the solution that depend on ``record``."""
    if any(spec.name == record.name and spec.match(record) for spec in requested):
        return REQUESTED
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
        return "dependency"
    others = len(parents) - 1
    return parents[0] + (f" (+{others})" if others else "")


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


STATUS_ORDER = ("active", "reported", "mitigated", "cleared")


def cve_summary(statuses: Iterable[str]) -> str:
    """CVE counts by status, one status per line."""
    counts = Counter(statuses)
    order = [*STATUS_ORDER, *sorted(set(counts) - set(STATUS_ORDER))]
    return "\n".join(f"{counts[status]} {status}" for status in order if counts[status])


def _table(entries: list[Entry], width: int, color: bool) -> list[str]:
    table = Table(box=box.SQUARE, show_lines=True, border_style="dim")
    table.add_column("Package", overflow="fold")
    table.add_column("Required by", overflow="fold")
    table.add_column("Reason")
    table.add_column("CVEs", no_wrap=True)
    for e in entries:
        if e.removed:
            reason = shorten([e.reason]) if e.reason else "removed by policy"
        else:
            reason = e.reason or "not in channel yet"
        table.add_row(e.label, e.why, reason, cve_summary(e.cve_statuses))
    out = io.StringIO()
    console = Console(
        file=out,
        width=width,
        color_system="standard" if color else None,
        force_terminal=color,
        highlight=False,
    )
    console.print(table)
    return out.getvalue().rstrip("\n").splitlines()


def render(
    channel: PolicyChannel,
    policy: ChannelPolicy,
    entries: Iterable[Entry],
    notes: Iterable[str] = (),
    width: int | None = None,
    color: bool = False,
) -> str | None:
    """Report section for one channel policy, or None if it explains nothing.

    conda prints hint text as given, so styling (dim grid lines) is only
    added when ``color`` is set, i.e. when conda writes to a terminal.
    """
    ordered = sorted(
        entries, key=lambda e: (not e.removed, e.why != REQUESTED, e.label)
    )
    if not ordered:
        return None
    if width is None:
        width = shutil.get_terminal_size((100, 24)).columns - len(INDENT)
    lines = [
        f'{channel.org}/{channel.channel} is filtered by policy "{policy.name}"',
        *(f"{INDENT}{line}" for line in policy.lines),
        *(f"{INDENT}{line}" for line in _table(ordered, width, color)),
        *(f"{INDENT}note: {note}" for note in notes),
    ]
    return "\n".join(lines)
