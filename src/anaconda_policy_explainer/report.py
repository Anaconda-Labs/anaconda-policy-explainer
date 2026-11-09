"""Turn policy results into one report section per channel policy."""

from __future__ import annotations

import re
from collections.abc import Iterable
from collections.abc import Sequence
from dataclasses import dataclass

from conda.models.match_spec import MatchSpec

from .api import ChannelPolicy
from .api import FileStatus
from .candidates import Findings
from .channels import PolicyChannel

# Newest matching versions to look up per package.
MAX_VERSIONS = 3
BLOCKED_WHY = "requested; available builds depend on removed packages"
INDENT = " " * 6  # aligns under conda's "  - (hint_code) " hint prefix

_CVE_REASON = re.compile(r"CVE score of ([\d.]+) is greater than ([\d.]+)")


@dataclass(frozen=True)
class VersionResult:
    version: str
    removed: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Blocked:
    """A blocked package: the specs it was needed as, and why it was needed."""

    name: str
    specs: tuple[MatchSpec, ...]
    why: str

    @property
    def label(self) -> str:
        if len(self.specs) == 1:
            spec = self.specs[0]
            return getattr(spec, "original_spec_str", None) or str(spec)
        return self.name


@dataclass(frozen=True)
class Entry:
    """A blocked package and what the policy did to its newest versions."""

    label: str
    why: str
    results: tuple[VersionResult, ...]


def group(findings: Findings) -> list[Blocked]:
    """One entry per package name: requested, then needed, then blocked.

    Blocked specs pinned to an exact version are left out: that version
    survived the policy, its dependencies are reported on their own.
    """
    specs: dict[str, list[MatchSpec]] = {}
    requested: set[str] = set()
    needed_by: dict[str, list[str]] = {}
    for missing in findings.missing:
        name = missing.spec.name
        if missing.spec not in specs.setdefault(name, []):
            specs[name].append(missing.spec)
        if missing.requested:
            requested.add(name)
        parents = needed_by.setdefault(name, [])
        parents.extend(p for p in missing.needed_by if p not in parents)
    for spec in findings.blocked:
        if spec.get_exact_value("version") is None:
            specs.setdefault(spec.name, [spec])

    def why(name: str) -> str:
        if name in requested:
            return "requested"
        parents = needed_by.get(name, [])
        if not parents:
            return BLOCKED_WHY
        others = len(parents) - 1
        return f"needed by {parents[0]}" + (f" and {others} others" if others else "")

    def rank(name: str) -> int:
        return 0 if name in requested else 1 if needed_by.get(name) else 2

    names = sorted(specs, key=rank)
    return [Blocked(name, tuple(specs[name]), why(name)) for name in names]


def pick_versions(
    specs: Sequence[MatchSpec], versions: Iterable[str], limit: int = MAX_VERSIONS
) -> list[tuple[str, MatchSpec]]:
    """Newest ``limit`` versions accepted by any of ``specs``, with that spec."""
    picked = []
    for version in versions:
        spec = next((s for s in specs if matching_versions(s, [version])), None)
        if spec is not None:
            picked.append((version, spec))
            if len(picked) == limit:
                break
    return picked


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
    notes: Iterable[str] = (),
) -> str | None:
    """Report section for one channel policy, or None if it explains nothing."""
    blocked = []
    for entry in entries:
        removed = [r for r in entry.results if r.removed]
        if not removed:
            continue
        blocked.append(f"{INDENT}  {entry.label} ({entry.why})")
        for result in removed:
            blocked.append(
                f"{INDENT}    {result.version} removed: {shorten(result.reasons)}"
            )
    if not blocked:
        return None
    return "\n".join(
        [
            f'{channel.org}/{channel.channel} is filtered by policy "{policy.name}"',
            *(f"{INDENT}{line}" for line in policy.lines),
            f"{INDENT}blocked:",
            *blocked,
            *(f"{INDENT}note: {note}" for note in notes),
        ]
    )
