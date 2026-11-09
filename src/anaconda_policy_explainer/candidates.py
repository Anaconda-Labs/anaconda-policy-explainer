"""Find which specs a filtered channel can no longer satisfy.

A spec is *blocked* when no available record matches it, or when every
record of its newest versions is itself blocked by one of its dependencies.
"Available" means what conda could see during the solve: the filtered
channel repodata plus records installed in the target prefix.

Following only the newest versions keeps the walk (and the report) to what
a solver would try first instead of every historical build.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field

from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord
from conda.models.version import VersionOrder

Query = Callable[[MatchSpec], Iterable[PackageRecord]]

NEWEST_VERSIONS = 3


@dataclass(frozen=True)
class Missing:
    """A spec with no available match, and what needed it."""

    spec: MatchSpec
    requested: bool
    needed_by: tuple[str, ...]


@dataclass
class Findings:
    missing: list[Missing] = field(default_factory=list)
    # Requested specs that have records, all of them blocked by missing
    # dependencies; the versions a policy removed may explain these too.
    blocked: list[MatchSpec] = field(default_factory=list)


def _newest(
    records: Iterable[PackageRecord], versions: int = NEWEST_VERSIONS
) -> list[PackageRecord]:
    """Records of the newest ``versions`` versions, newest first."""
    ordered = sorted(
        records, key=lambda r: (VersionOrder(r.version), r.build_number), reverse=True
    )
    kept: list[PackageRecord] = []
    seen: list[str] = []
    for record in ordered:
        if record.version not in seen:
            if len(seen) == versions:
                break
            seen.append(record.version)
        kept.append(record)
    return kept


def _dist(record: PackageRecord) -> str:
    return f"{record.name}-{record.version}-{record.build}"


def find_blocked(specs: Iterable[MatchSpec], query: Query) -> Findings:
    specs_by_key: dict[str, MatchSpec] = {}
    parents: dict[str, list[str]] = {}
    has_records: dict[str, bool] = {}
    memo: dict[str, frozenset[str]] = {}
    in_progress: set[str] = set()

    def missing_under(spec: MatchSpec, parent: str | None) -> frozenset[str]:
        """Keys of the missing specs that block ``spec`` (itself, if missing)."""
        key = str(spec)
        if spec.name.startswith("__"):  # virtual packages are not in repodata
            return frozenset()
        if key not in memo and key not in in_progress:
            in_progress.add(key)
            specs_by_key[key] = spec
            records = _newest(query(spec))
            has_records[key] = bool(records)
            blocking: set[str] = set() if records else {key}
            for record in records:
                found: set[str] = set()
                for dep in record.depends:
                    found |= missing_under(MatchSpec(dep), _dist(record))
                if not found:  # one usable record makes the spec satisfiable
                    blocking = set()
                    break
                blocking |= found
            in_progress.discard(key)
            memo[key] = frozenset(blocking)
        result = memo.get(key, frozenset())  # cycle: let the outer frame decide
        if parent is not None and key in result and not has_records[key]:
            if parent not in parents.setdefault(key, []):
                parents[key].append(parent)
        return result

    requested: list[str] = []
    order: list[str] = []
    findings = Findings()
    for spec in specs:
        key = str(spec)
        blocked_by = missing_under(spec, None)
        if not blocked_by:
            continue
        if has_records[key]:
            findings.blocked.append(spec)
        else:
            requested.append(key)
        order.extend(k for k in sorted(blocked_by) if k not in order)
    findings.missing = [
        Missing(specs_by_key[k], k in requested, tuple(parents.get(k, ())))
        for k in sorted(order, key=lambda k: k not in requested)
    ]
    return findings
