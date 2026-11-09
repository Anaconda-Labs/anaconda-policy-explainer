"""Candidate detection against a small filtered channel on disk.

The channel stands in for a policy-filtered channel: jinja2 and every
python other than 3.14 have been removed, and the only surviving urllib3
build needs python 3.15.
"""

from pathlib import Path

import pytest
from conda.core.subdir_data import SubdirData
from conda.models.channel import Channel
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from anaconda_policy_explainer.candidates import AllBlocked
from anaconda_policy_explainer.candidates import Missing
from anaconda_policy_explainer.candidates import find_blocked

CHANNEL = Channel((Path(__file__).parent / "data" / "filtered-channel").as_uri())
SUBDIRS = ("linux-64", "noarch")


def query_with(installed: list[PackageRecord]):
    def query(spec: MatchSpec):
        yield from SubdirData.query_all(spec, channels=(CHANNEL,), subdirs=SUBDIRS)
        yield from (record for record in installed if spec.match(record))

    return query


def record(name: str, version: str, build: str = "h0_0") -> PackageRecord:
    return PackageRecord(
        name=name, version=version, build=build, build_number=0, channel="installed"
    )


def blocked(*specs: str, installed: list[PackageRecord] | None = None):
    return find_blocked([MatchSpec(s) for s in specs], query_with(installed or []))


def test_requested_name_removed():
    findings = blocked("jinja2")
    assert findings.missing == [Missing(MatchSpec("jinja2"), None)]
    assert findings.blocked == []


def test_requested_version_removed():
    findings = blocked("python=3.13")
    assert findings.missing == [Missing(MatchSpec("python=3.13"), None)]


def test_satisfiable_spec_has_no_findings():
    findings = blocked("python", "pandas")
    assert findings.missing == []
    assert findings.blocked == []


def test_dependency_removed():
    findings = blocked("altair")
    assert findings.missing == [Missing(MatchSpec("jinja2"), "altair-6.0.0-py314h0_0")]
    assert findings.blocked == [AllBlocked(MatchSpec("altair"))]


def test_surviving_build_needs_removed_dependency():
    findings = blocked("urllib3")
    assert findings.missing == [
        Missing(
            MatchSpec("python >=3.15,<3.16.0a0"),
            "urllib3-2.6.3-py315h0_1",
        )
    ]
    assert findings.blocked == [AllBlocked(MatchSpec("urllib3"))]


def test_blocked_transitively():
    findings = blocked("requests")
    assert [m.spec for m in findings.missing] == [MatchSpec("python >=3.15,<3.16.0a0")]
    assert findings.blocked == [
        AllBlocked(MatchSpec("requests")),
        AllBlocked(MatchSpec("urllib3 >=1.26")),
    ]


def test_installed_record_satisfies_removed_dependency():
    findings = blocked("altair", installed=[record("jinja2", "3.1.6")])
    assert findings.missing == []
    assert findings.blocked == []


def test_one_usable_build_keeps_spec_satisfiable():
    # pandas 2.2.0 needs a removed python, pandas 2.3.0 does not
    findings = blocked("pandas")
    assert findings.missing == []


def test_only_newest_versions_are_followed():
    # oldlib 1.0 is usable, but a solver would try 4.0, 3.0 and 2.0 first
    assert blocked("oldlib").blocked == [AllBlocked(MatchSpec("oldlib"))]
    assert blocked("oldlib <2").blocked == []


@pytest.mark.parametrize("spec", ["python=3.13", "jinja2"])
def test_causes_are_reported_once(spec):
    findings = blocked(spec, spec)
    assert len(findings.missing) == 1
