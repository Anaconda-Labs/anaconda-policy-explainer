"""Report building from solution records and recorded API responses."""

import json
from pathlib import Path

from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from anaconda_policy_explainer.api import ChannelPolicy
from anaconda_policy_explainer.api import parse_files
from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.report import Entry
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
    assert why(URLLIB3, SOLUTION, [MatchSpec("urllib3=2.6")]) == "requested"


def test_needed_by_solution_records():
    assert why(PYTHON, SOLUTION, [MatchSpec("urllib3")]) == (
        "needed by cffi-2.1.1-py313h3b52fac_0 and 1 others"
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


def test_render_section():
    entries = [
        Entry(
            "python-3.13.11-hcf712cf_100_cp313",
            "needed by cffi-2.1.1-py313h3b52fac_0",
            True,
            "CVE score of 9.8 is greater than 7",
        ),
        Entry(
            "urllib3-2.6.1-py313h06a4308_0",
            "requested",
            True,
            "CVE score of 7.9 is greater than 7",
        ),
        Entry(
            "zstd-1.5.8-h0_0",
            "needed by python-3.13.11-hcf712cf_100_cp313",
            False,
            None,
        ),
    ]
    assert render(CHANNEL, POLICY, entries, ["a note"]) == "\n".join(
        [
            'acme/analysts is filtered by policy "secure"',
            "      removes packages where:",
            "        cve_score > 7",
            "      blocked:",
            "        urllib3-2.6.1-py313h06a4308_0 (requested): CVE 7.9 > 7",
            "        python-3.13.11-hcf712cf_100_cp313"
            " (needed by cffi-2.1.1-py313h3b52fac_0): CVE 9.8 > 7",
            "      not in the channel yet:",
            "        zstd-1.5.8-h0_0 (needed by python-3.13.11-hcf712cf_100_cp313)",
            "      note: a note",
        ]
    )


def test_render_nothing():
    assert render(CHANNEL, POLICY, []) is None
