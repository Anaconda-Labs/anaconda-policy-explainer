"""Turn policy results into one report section per channel policy."""

from __future__ import annotations

import re
from collections.abc import Iterable
from collections.abc import Sequence
from dataclasses import dataclass

from conda.models.match_spec import MatchSpec

from .api import ChannelPolicy
from .api import FileStatus
from .channels import PolicyChannel

# Newest matching versions to look up per spec.
MAX_VERSIONS = 3
INDENT = " " * 6  # aligns under conda's "  - (hint_code) " hint prefix

_CVE_REASON = re.compile(r"CVE score of ([\d.]+) is greater than ([\d.]+)")


@dataclass(frozen=True)
class VersionResult:
    version: str
    removed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Entry:
    """A blocked spec, why it was needed, and what the policy did to it."""

    spec: MatchSpec
    why: str
    results: tuple[VersionResult, ...]


def matching_versions(
    spec: MatchSpec, versions: Iterable[str], limit: int = MAX_VERSIONS
) -> list[str]:
    """Newest ``limit`` versions (input is newest first) that satisfy ``spec``."""
    version_spec = spec.get_raw_value("version")
    by_version = (
        MatchSpec(name=spec.name, version=version_spec)
        if version_spec
        else MatchSpec(name=spec.name)
    )
    found = []
    for version in versions:
        candidate = {
            "name": spec.name,
            "version": version,
            "build": "",
            "build_number": 0,
        }
        if by_version.match(candidate):
            found.append(version)
            if len(found) == limit:
                break
    return found


def version_result(
    spec: MatchSpec, version: str, files: Iterable[FileStatus], subdirs: Sequence[str]
) -> VersionResult | None:
    """Policy result for the files of one version that ``spec`` would accept."""
    relevant = [
        f
        for f in files
        if f.subdir in subdirs
        and spec.match(
            {
                "name": f.name,
                "version": f.version,
                "build": f.build,
                "build_number": f.build_number,
            }
        )
    ]
    if not relevant:
        return None
    removed = [f for f in relevant if f.removed]
    reasons = tuple(sorted({f.reason for f in removed if f.reason}))
    return VersionResult(version, len(removed) == len(relevant), reasons)


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
    note: str | None = None,
) -> str | None:
    """Report section for one channel policy, or None if it explains nothing."""
    lines = []
    for entry in entries:
        removed = [r for r in entry.results if r.removed]
        if not removed:
            continue
        spec = getattr(entry.spec, "original_spec_str", None) or str(entry.spec)
        lines.append(f"{INDENT}{spec} ({entry.why})")
        for result in removed:
            lines.append(
                f"{INDENT}  {result.version} removed: {shorten(result.reasons)}"
            )
    if not lines:
        return None
    header = f'{channel.org}/{channel.channel} is filtered by policy "{policy.name}"'
    if policy.summary:
        header += f": {policy.summary}"
    if note:
        lines.append(f"{INDENT}note: {note}")
    return "\n".join([header, *lines])
