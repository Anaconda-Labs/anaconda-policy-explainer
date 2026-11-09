"""Report building from recorded API responses (tests/data/api)."""

import json
from pathlib import Path

from conda.models.match_spec import MatchSpec

from anaconda_policy_explainer.api import ChannelPolicy
from anaconda_policy_explainer.api import parse_files
from anaconda_policy_explainer.api import parse_versions
from anaconda_policy_explainer.candidates import AllBlocked
from anaconda_policy_explainer.candidates import Findings
from anaconda_policy_explainer.candidates import Missing
from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.report import BLOCKED_WHY
from anaconda_policy_explainer.report import Blocked
from anaconda_policy_explainer.report import Entry
from anaconda_policy_explainer.report import VersionResult
from anaconda_policy_explainer.report import group
from anaconda_policy_explainer.report import matching_versions
from anaconda_policy_explainer.report import pick_versions
from anaconda_policy_explainer.report import render
from anaconda_policy_explainer.report import shorten
from anaconda_policy_explainer.report import version_result

DATA = Path(__file__).parent / "data" / "api"
SUBDIRS = ("linux-64", "noarch")
CHANNEL = PolicyChannel(
    "https://repo.anaconda.cloud/repo/acme/analysts", "acme", "analysts", "anaconda.com"
)
POLICY = ChannelPolicy("secure", "removes cve_score > 7")


def files(name: str, version: str):
    payload = json.loads((DATA / f"files-{name}-{version}.json").read_text())
    return parse_files(payload)


def urllib3_versions():
    payload = json.loads((DATA / "artifacts-urllib3.json").read_text())
    return parse_versions(payload, "urllib3")


def test_matching_versions_unconstrained_takes_newest():
    assert matching_versions(MatchSpec("urllib3"), urllib3_versions()) == [
        "2.8.0",
        "2.7.0",
        "2.6.3",
    ]


def test_matching_versions_constrained():
    spec = MatchSpec("urllib3 >=2.5,<2.6.3")
    assert matching_versions(spec, urllib3_versions()) == ["2.6.1", "2.6.0", "2.5.0"]


def test_matching_versions_ignores_build_constraint():
    spec = MatchSpec("urllib3==2.6.0=py314h06a4308_0")
    assert matching_versions(spec, urllib3_versions()) == ["2.6.0"]


def test_fully_removed_version():
    result = version_result(
        MatchSpec("urllib3=2.6.0"), "2.6.0", files("urllib3", "2.6.0"), SUBDIRS
    )
    assert result is not None
    assert result.removed
    assert shorten(result.reasons) == "CVE 8.9 > 7"


def test_version_with_a_surviving_build_is_not_removed():
    result = version_result(
        MatchSpec("urllib3=2.6.3"), "2.6.3", files("urllib3", "2.6.3"), SUBDIRS
    )
    assert result is not None
    assert not result.removed


def test_build_constraint_selects_removed_build():
    spec = MatchSpec("urllib3==2.6.3=py314h06a4308_1")
    result = version_result(spec, "2.6.3", files("urllib3", "2.6.3"), SUBDIRS)
    assert result is not None
    assert result.removed


def test_version_without_files_for_platform():
    result = version_result(
        MatchSpec("urllib3=2.6.0"), "2.6.0", files("urllib3", "2.6.0"), ("win-arm64",)
    )
    assert result is None


def test_shorten_keeps_non_cve_reasons():
    assert shorten(
        ["License GPL is excluded", "CVE score of 7.5 is greater than 7"]
    ) == ("CVE 7.5 > 7; License GPL is excluded")


def test_group_by_package_requested_first():
    findings = Findings(
        missing=[
            Missing(MatchSpec("python >=3.15,<3.16.0a0"), "urllib3-2.6.3-py315h0_1"),
            Missing(MatchSpec("python >=3.13,<3.14.0a0"), "pycparser-3.12-py313h0_0"),
            Missing(MatchSpec("python >=3.15,<3.16.0a0"), "cffi-2.0-py315h0_0"),
            Missing(MatchSpec("jinja2"), None),
        ],
        blocked=[AllBlocked(MatchSpec("urllib3")), AllBlocked(MatchSpec("python"))],
    )
    assert group(findings) == [
        Blocked("jinja2", (MatchSpec("jinja2"),), "requested"),
        Blocked(
            "python",
            (
                MatchSpec("python >=3.15,<3.16.0a0"),
                MatchSpec("python >=3.13,<3.14.0a0"),
            ),
            "needed by urllib3-2.6.3-py315h0_1 and 2 others",
        ),
        Blocked("urllib3", (MatchSpec("urllib3"),), BLOCKED_WHY),
    ]


def test_group_label():
    assert Blocked("python", (MatchSpec("python >=3.15"),), "").label == "python >=3.15"
    two = (MatchSpec("python >=3.15"), MatchSpec("python <3"))
    assert Blocked("python", two, "").label == "python"


def test_pick_versions_across_specs():
    specs = (MatchSpec("urllib3 >=2.6.3,<2.7"), MatchSpec("urllib3 <2.3"))
    picked = pick_versions(specs, urllib3_versions())
    assert [(v, str(s)) for v, s in picked] == [
        ("2.6.3", str(specs[0])),
        ("2.2.3", str(specs[1])),
        ("2.2.2", str(specs[1])),
    ]


def test_render_section():
    entries = [
        Entry(
            "urllib3=2.6.0",
            "requested",
            (VersionResult("2.6.0", True, ("CVE score of 8.9 is greater than 7",)),),
        ),
        Entry(
            "python >=3.15,<3.16.0a0",
            "needed by urllib3-2.6.3-py315h06a4308_1",
            (
                VersionResult("3.15.2", True, ("CVE score of 7.5 is greater than 7",)),
                VersionResult("3.15.1", False, ()),
            ),
        ),
    ]
    assert render(CHANNEL, POLICY, entries) == "\n".join(
        [
            'acme/analysts is filtered by policy "secure": removes cve_score > 7',
            "      urllib3=2.6.0 (requested)",
            "        2.6.0 removed: CVE 8.9 > 7",
            "      python >=3.15,<3.16.0a0 (needed by urllib3-2.6.3-py315h06a4308_1)",
            "        3.15.2 removed: CVE 7.5 > 7",
        ]
    )


def test_render_note():
    entries = [Entry("jinja2", "requested", (VersionResult("3.1.6", True, ()),))]
    text = render(CHANNEL, POLICY, entries, note="channel authenticates against x")
    assert text is not None
    assert text.endswith("\n      note: channel authenticates against x")


def test_render_nothing_removed():
    entries = [Entry("jinja2", "requested", (VersionResult("3.1.6", False, ()),))]
    assert render(CHANNEL, POLICY, entries) is None
