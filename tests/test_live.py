"""Real conda, real solvers, real Anaconda API.

Opt-in: these need a channel with a policy and an API key for it.

    APE_LIVE_CHANNEL       https://repo.anaconda.cloud/repo/<org>/<channel>
    APE_LIVE_REMOVED_SPEC  a spec the channel's policy removed, e.g. urllib3=2.6.0
    ANACONDA_AUTH_API_KEY  an API key for the channel's organization

conda runs with an empty HOME so that no user configuration (such as an
unfiltered default channel) can satisfy what the policy removed, and with
APE_LIVE_CHANNEL as its only default channel, which the environment files in
tests/data/environments use. Results depend on the platform's current
policy data.
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
ENVIRONMENTS = Path(__file__).parent / "data" / "environments"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (CHANNEL and REMOVED_SPEC and os.environ.get("ANACONDA_AUTH_API_KEY")),
        reason="set APE_LIVE_CHANNEL, APE_LIVE_REMOVED_SPEC, ANACONDA_AUTH_API_KEY",
    ),
]

SOLVERS = ["libmamba", "rattler"]


@pytest.fixture
def conda(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    condarc = tmp_path / "condarc"
    condarc.write_text(
        "channel_settings:\n"
        "  - channel: https://repo.anaconda.cloud/*\n"
        "    auth: anaconda-auth\n"
        f"default_channels:\n  - {CHANNEL}\n"
    )
    env = {
        **os.environ,
        "HOME": str(home),
        "CONDARC": str(condarc),
        "CONDA_PKGS_DIRS": str(tmp_path / "pkgs"),
        "COLUMNS": "200",
    }

    def run(*args: str, **extra: str) -> str:
        result = subprocess.run(
            [sys.executable, "-m", "conda", *args],
            capture_output=True,
            text=True,
            timeout=900,
            env={**env, **extra},
        )
        assert result.returncode != 0, result.stdout + result.stderr
        return result.stdout + result.stderr

    return run


def rows(output: str) -> list[list[str]]:
    """Report table rows (Package, Needed, Reason, CVEs), header excluded."""
    cells = [
        [c.strip() for c in line.strip().strip("│").split("│")]
        for line in output.splitlines()
        if line.strip().startswith("│")
    ]
    # libmamba's error message draws its problem tree with "│" too
    return [row for row in cells if len(row) == 4 and row[0] and row[0] != "Package"]


def blocked(output: str) -> list[str]:
    return [row[0] for row in rows(output) if row[2] != "not in channel yet"]


def assert_explained(output: str) -> None:
    org_channel = parse_org_channel(CHANNEL)
    assert org_channel is not None
    assert f"({HINT_CODE}) {org_channel[0]}/{org_channel[1]} is filtered" in output
    assert blocked(output)


def channel_args(prefix: Path) -> list[str]:
    return ["--prefix", str(prefix), "--override-channels", "-c", CHANNEL, "--dry-run"]


@pytest.mark.parametrize("solver", SOLVERS)
def test_create_requested_spec_removed(conda, solver: str, tmp_path: Path):
    output = conda(
        "create", *channel_args(tmp_path / "env"), "--solver", solver, REMOVED_SPEC
    )
    assert_explained(output)


@pytest.mark.parametrize("solver", SOLVERS)
def test_no_hint_for_unknown_package(conda, solver: str, tmp_path: Path):
    output = conda(
        "create",
        *channel_args(tmp_path / "env"),
        "--solver",
        solver,
        "anaconda-policy-explainer-no-such-package",
    )
    assert HINT_CODE not in output


@pytest.mark.parametrize("solver", SOLVERS)
def test_pinned_environment_blocks_only_its_pins(conda, solver: str, tmp_path: Path):
    pins = (ENVIRONMENTS / "pinned.yml").read_text().split("dependencies:\n")[1]
    pinned = {
        "-".join(line.strip().removeprefix("- ").split("="))
        for line in pins.splitlines()
    }
    output = conda(
        "env",
        "create",
        "--dry-run",
        "--file",
        str(ENVIRONMENTS / "pinned.yml"),
        "--prefix",
        str(tmp_path / "env"),
        "--solver",
        solver,
        CONDA_SUBDIR="linux-64",
        CONDA_OVERRIDE_GLIBC="2.28",
    )
    removed = blocked(output)
    assert removed
    assert set(removed) <= pinned
    assert all(row[1] == "your request" for row in rows(output) if row[0] in removed)
