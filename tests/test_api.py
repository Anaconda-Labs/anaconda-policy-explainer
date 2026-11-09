"""Parsing of recorded Anaconda API responses (tests/data/api)."""

import json
from collections import Counter
from pathlib import Path

from anaconda_policy_explainer.api import parse_files
from anaconda_policy_explainer.api import parse_versions
from anaconda_policy_explainer.api import summarize_filter

DATA = Path(__file__).parent / "data" / "api"


def load(name: str):
    return json.loads((DATA / f"{name}.json").read_text())


def test_summarize_single_rule_policy():
    policy = load("policy")
    assert summarize_filter(policy["filter"], policy["schema_version"]) == (
        "removes cve_score > 7"
    )


def test_summarize_policy_with_overrides():
    policy = load("policy-multi")
    assert summarize_filter(policy["filter"], policy["schema_version"]) == (
        "removes license_family == AGPL or license_family == Proprietary"
        " or cve_score >= 9 or platform != linux-64 or platform != noarch"
        "; keeps conda_spec == airflow>2.0"
    )


def test_versions_newest_first():
    versions = parse_versions(load("artifacts-urllib3"), "urllib3")
    assert versions is not None
    assert versions[:3] == ["2.8.0", "2.7.0", "2.6.3"]


def test_unknown_package_has_no_versions():
    assert parse_versions(load("artifacts-notapkg123"), "notapkg123") is None


def test_files_carry_policy_result():
    files = parse_files(load("files-urllib3-2.6.3"))
    linux = [f for f in files if f.subdir in ("linux-64", "noarch")]
    survivors = [f for f in linux if not f.removed]
    assert {f.build for f in survivors} == {"py315h06a4308_1"}
    assert all(f.reason is None for f in survivors)
    assert all(
        f.reason and f.reason.startswith("CVE score of") for f in linux if f.removed
    )
    assert any(dep.startswith("python >=3.15") for dep in survivors[0].depends)


def test_fully_removed_version():
    files = parse_files(load("files-urllib3-2.6.0"))
    assert files and all(f.removed for f in files)
    assert Counter(f.reason for f in files).most_common(1)[0][0] == (
        "CVE score of 8.9 is greater than 7"
    )
