"""Report building from solution records and recorded API responses."""

import json
from pathlib import Path

import pytest
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from anaconda_policy_explainer.api import ChannelPolicy
from anaconda_policy_explainer.api import parse_files
from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.report import REQUESTED
from anaconda_policy_explainer.report import Entry
from anaconda_policy_explainer.report import cve_summary
from anaconda_policy_explainer.report import file_status
from anaconda_policy_explainer.report import render
from anaconda_policy_explainer.report import shorten
from anaconda_policy_explainer.report import why

DATA = Path(__file__).parent / "data" / "api"
CHANNEL = PolicyChannel(
    "https://repo.anaconda.cloud/repo/acme/analysts", "acme", "analysts", "anaconda.com"
)
POLICY = ChannelPolicy("secure", ("removes packages where:", "  cve_score > 7"), "main")


def record(
    name: str, version: str, build: str, depends=(), fn: str = ""
) -> PackageRecord:
    return PackageRecord(
        name=name,
        version=version,
        build=build,
        build_number=0,
        depends=list(depends),
        subdir="linux-64",
        fn=fn or f"{name}-{version}-{build}.conda",
        channel="https://repo.anaconda.com/pkgs/main",
    )


PYTHON = record("python", "3.13.11", "hcf712cf_100_cp313")
URLLIB3 = record("urllib3", "2.6.1", "py313h06a4308_0", ["python >=3.13,<3.14.0a0"])
CFFI = record("cffi", "2.1.1", "py313h3b52fac_0", ["python >=3.13,<3.14.0a0"])
SOLUTION = (PYTHON, URLLIB3, CFFI)


def test_requested():
    assert why(URLLIB3, SOLUTION, [MatchSpec("urllib3=2.6")]) == REQUESTED


def test_needed_by_solution_records():
    assert why(PYTHON, SOLUTION, [MatchSpec("urllib3")]) == (
        "cffi-2.1.1-py313h3b52fac_0 (+1)"
    )


def test_file_status_exact_file():
    files = parse_files(json.loads((DATA / "files-urllib3-2.6.3.json").read_text()))
    built = record("urllib3", "2.6.3", "py313h06a4308_1")
    status = file_status(built, files)
    assert status is not None
    assert status.fn == "urllib3-2.6.3-py313h06a4308_1.conda"
    assert status.removed


def test_file_status_other_format():
    files = parse_files(json.loads((DATA / "files-urllib3-2.6.3.json").read_text()))
    built = record("urllib3", "2.6.3", "py315h06a4308_1", fn="x.conda")
    assert file_status(built, files) is None
    built = record("urllib3", "2.6.3", "py315h06a4308_1")
    status = file_status(built, [f for f in files if not f.fn.endswith(".conda")])
    assert status is not None
    assert status.fn.endswith(".tar.bz2")
    assert not status.removed


def test_shorten():
    assert shorten(
        ["License GPL is excluded", "CVE score of 7.5 is greater than 7"]
    ) == ("CVE 7.5 > 7; License GPL is excluded")


def test_cve_summary():
    files = parse_files(json.loads((DATA / "files-urllib3-2.6.1.json").read_text()))
    built = record("urllib3", "2.6.1", "py313h06a4308_0")
    status = file_status(built, files)
    assert status is not None
    assert cve_summary(status.cve_statuses) == "1 active\n4 reported\n9 cleared"


def test_cve_summary_none():
    assert cve_summary([]) == ""


def test_render_section():
    entries = [
        Entry(
            "python-3.13.11-hcf712cf_100_cp313",
            "cffi-2.1.1-py313h3b52fac_0",
            True,
            "CVE score of 9.8 is greater than 7",
            ("active", "active", "reported", "cleared"),
        ),
        Entry(
            "urllib3-2.6.1-py313h06a4308_0",
            REQUESTED,
            True,
            "CVE score of 8.9 is greater than 7",
            ("active", "reported", "cleared"),
        ),
        Entry("zstd-1.5.8-h0_0", "python-3.13.11-hcf712cf_100_cp313", False, None),
    ]
    expected = (Path(__file__).parent / "data" / "report-section.txt").read_text()
    assert render(CHANNEL, POLICY, entries, ["a note"], width=140) == expected.rstrip(
        "\n"
    )


@pytest.mark.parametrize("width", [100, 80])
def test_render_fits_width(width):
    entries = [
        Entry(
            "python-3.13.11-hcf712cf_100_cp313",
            "cffi-2.1.1-py313h3b52fac_0",
            True,
            "CVE score of 9.8 is greater than 7",
            ("active", "reported"),
        ),
    ]
    text = render(CHANNEL, POLICY, entries, width=width)
    assert text is not None
    assert max(len(line) for line in text.splitlines()[3:]) <= width + len("      ")


def test_render_nothing():
    assert render(CHANNEL, POLICY, []) is None


def test_grid_lines_dim_only_with_color():
    entries = [Entry("zstd-1.5.8-h0_0", REQUESTED, True, None, ("cleared",))]
    plain = render(CHANNEL, POLICY, entries, width=100)
    styled = render(CHANNEL, POLICY, entries, width=100, color=True)
    assert plain is not None and "\x1b[" not in plain
    assert styled is not None and "\x1b[2m" in styled


def test_unchecked_build_keeps_its_row():
    entries = [
        Entry("xz-5.8.4-h9596fca_0", REQUESTED, False, "not checked (HTTPError)")
    ]
    text = render(CHANNEL, POLICY, entries, width=120)
    assert text is not None
    assert "xz-5.8.4-h9596fca_0" in text
    assert "not checked (HTTPError)" in text
