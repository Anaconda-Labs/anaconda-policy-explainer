"""Parsing of recorded Anaconda API responses (tests/data/api)."""

import json
from collections import Counter
from pathlib import Path

from anaconda_policy_explainer.api import ChannelDetails
from anaconda_policy_explainer.api import parse_details
from anaconda_policy_explainer.api import parse_files
from anaconda_policy_explainer.api import policy_lines

DATA = Path(__file__).parent / "data" / "api"


def load(name: str):
    return json.loads((DATA / f"{name}.json").read_text())


def lines_of(name: str) -> list[str]:
    policy = load(name)
    return policy_lines(policy["filter"], policy["schema_version"])


def test_single_rule_policy():
    assert lines_of("policy") == [
        "removes packages where:",
        "  cve_score > 7",
    ]


def test_single_group_is_not_nested():
    assert lines_of("policy-platform-and") == [
        "removes packages where all of:",
        "  platform != osx-arm64",
        "  platform != noarch",
    ]


def test_nested_groups_with_keeps():
    assert lines_of("policy-nested") == [
        "removes packages where any of:",
        "  all of:",
        "    cve_score > 7",
        "    cve_status == active",
        "  all of:",
        "    cve_score > 4",
        "    cve_status == reported",
        "keeps packages where:",
        "  conda_spec == numpy >=1.8",
    ]


def test_rules_are_literal_and_not_merged():
    assert lines_of("policy-multi") == [
        "removes packages where any of:",
        "  license_family == AGPL",
        "  license_family == Proprietary",
        "  cve_score >= 9",
        "  platform != linux-64",
        "  platform != noarch",
        "keeps packages where:",
        "  conda_spec == airflow>2.0",
    ]


def test_schema_v2_sections_in_evaluation_order():
    rule = {
        "type": "simple",
        "facet": "package_age",
        "comparator": ">",
        "criterion": 30,
    }
    raw = {
        "add_packages": {"type": "compound", "operator": "or", "subfilters": [rule]},
        "remove_packages": {
            "type": "compound",
            "operator": "and",
            "subfilters": [
                {
                    "type": "simple",
                    "facet": "cve_score",
                    "comparator": ">",
                    "criterion": 7,
                },
                {
                    "type": "simple",
                    "facet": "platform",
                    "comparator": "!=",
                    "criterion": "noarch",
                },
            ],
        },
    }
    assert policy_lines(raw, 2) == [
        "adds packages where:",
        "  package_age > 30 days",
        "removes packages where all of:",
        "  cve_score > 7",
        "  platform != noarch",
    ]


def test_channel_details_policy_and_source():
    assert parse_details(load("channel-details")) == ChannelDetails(
        "00000000-0000-0000-0000-000000000001", "secure", "main"
    )


def test_upload_channel_has_no_source():
    details = parse_details({"type": "default", "sources": [], "assigned_policy": None})
    assert details == ChannelDetails(None, None, None)


def test_files_carry_policy_result():
    files = parse_files(load("files-urllib3-2.6.3"))
    linux = [f for f in files if f.subdir in ("linux-64", "noarch")]
    survivors = [f for f in linux if not f.removed]
    assert {f.fn for f in survivors} == {
        "urllib3-2.6.3-py315h06a4308_1.conda",
        "urllib3-2.6.3-py315h06a4308_1.tar.bz2",
    }
    assert all(f.reason is None for f in survivors)
    assert all(
        f.reason and f.reason.startswith("CVE score of") for f in linux if f.removed
    )


def test_fully_removed_version():
    files = parse_files(load("files-urllib3-2.6.0"))
    assert files and all(f.removed for f in files)
    assert Counter(f.reason for f in files).most_common(1)[0][0] == (
        "CVE score of 8.9 is greater than 7"
    )
