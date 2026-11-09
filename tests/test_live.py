"""Real conda, real solvers, real Anaconda API.

Opt-in: these need anaconda-auth credentials and a channel with a policy.

    APE_LIVE_CHANNEL       https://repo.anaconda.cloud/repo/<org>/<channel>
    APE_LIVE_REMOVED_SPEC  a spec the channel's policy removed, e.g. urllib3=2.6.0
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from anaconda_policy_explainer.channels import parse_org_channel
from anaconda_policy_explainer.plugin import HINT_CODE

CHANNEL = os.environ.get("APE_LIVE_CHANNEL", "")
REMOVED_SPEC = os.environ.get("APE_LIVE_REMOVED_SPEC", "")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (CHANNEL and REMOVED_SPEC),
        reason="set APE_LIVE_CHANNEL and APE_LIVE_REMOVED_SPEC",
    ),
]

SOLVERS = ["libmamba", "rattler"]


def conda(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "conda", *args],
        capture_output=True,
        text=True,
        timeout=600,
    )


def channel_args() -> list[str]:
    return ["--override-channels", "--channel", CHANNEL, "--dry-run", "--yes"]


def assert_explained(result: subprocess.CompletedProcess[str]) -> None:
    org_channel = parse_org_channel(CHANNEL)
    assert org_channel is not None
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert f"({HINT_CODE}) {org_channel[0]}/{org_channel[1]} is filtered" in output
    assert "removed:" in output


@pytest.mark.parametrize("solver", SOLVERS)
def test_create_requested_spec_removed(solver: str, tmp_path: Path):
    result = conda(
        "create",
        "--prefix",
        str(tmp_path / "env"),
        "--solver",
        solver,
        *channel_args(),
        REMOVED_SPEC,
    )
    assert_explained(result)


@pytest.mark.parametrize("solver", SOLVERS)
def test_install_requested_spec_removed(solver: str, tmp_path: Path):
    prefix = tmp_path / "env"
    created = conda("create", "--prefix", str(prefix), "--yes", "--offline")
    assert created.returncode == 0, created.stderr
    result = conda(
        "install",
        "--prefix",
        str(prefix),
        "--solver",
        solver,
        *channel_args(),
        REMOVED_SPEC,
    )
    assert_explained(result)


@pytest.mark.parametrize("solver", SOLVERS)
def test_no_hint_for_unknown_package(solver: str, tmp_path: Path):
    result = conda(
        "create",
        "--prefix",
        str(tmp_path / "env"),
        "--solver",
        solver,
        *channel_args(),
        "anaconda-policy-explainer-no-such-package",
    )
    assert result.returncode != 0
    assert HINT_CODE not in result.stdout + result.stderr
