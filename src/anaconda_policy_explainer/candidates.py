"""Find which specs a filtered channel can no longer satisfy.

A spec is *blocked* when no available record matches it, or when every
record that matches it is itself blocked by one of its dependencies.
"Available" means what conda could see during the solve: the filtered
channel repodata plus records installed in the target prefix.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field

from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

Query = Callable[[MatchSpec], Iterable[PackageRecord]]


@dataclass(frozen=True)
class Missing:
    """A spec with no available match; ``needed_by`` is None when requested."""

    spec: MatchSpec
    needed_by: str | None


@dataclass(frozen=True)
class AllBlocked:
    """A spec whose available records all depend on something missing."""

    spec: MatchSpec


Cause = Missing | AllBlocked


@dataclass
class Findings:
    missing: list[Missing] = field(default_factory=list)
    # Specs whose surviving records are all blocked; the versions a policy
    # removed for these names may explain the failure as well.
    blocked: list[AllBlocked] = field(default_factory=list)


def _dist(record: PackageRecord) -> str:
    return f"{record.name}-{record.version}-{record.build}"


def find_blocked(specs: Iterable[MatchSpec], query: Query) -> Findings:
    memo: dict[str, tuple[Cause, ...]] = {}
    in_progress: set[str] = set()

    def causes(spec: MatchSpec, needed_by: str | None) -> tuple[Cause, ...]:
        key = str(spec)
        if spec.name.startswith("__"):  # virtual packages are not in repodata
            return ()
        if key in memo:
            return memo[key]
        if key in in_progress:  # dependency cycle: let the outer frame decide
            return ()
        in_progress.add(key)
        records = list(query(spec))
        result: tuple[Cause, ...] = ()
        if not records:
            result = (Missing(spec, needed_by),)
        else:
            per_record: list[tuple[Cause, ...]] = []
            for record in records:
                found = tuple(
                    cause
                    for dep in record.depends
                    for cause in causes(MatchSpec(dep), _dist(record))
                )
                if not found:  # one usable record makes the spec satisfiable
                    per_record = []
                    break
                per_record.append(found)
            if per_record:
                result = (AllBlocked(spec), *(c for f in per_record for c in f))
        in_progress.discard(key)
        memo[key] = result
        return result

    findings = Findings()
    seen: set[Cause] = set()
    for spec in specs:
        for cause in causes(spec, None):
            if cause in seen:
                continue
            seen.add(cause)
            if isinstance(cause, Missing):
                findings.missing.append(cause)
            else:
                findings.blocked.append(cause)
    return findings
