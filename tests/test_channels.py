from pathlib import Path

import pytest
from conda.base.context import context
from conda.base.context import reset_context

from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.channels import auth_domain
from anaconda_policy_explainer.channels import parse_org_channel
from anaconda_policy_explainer.channels import policy_channels

ORG_URL = "https://repo.anaconda.cloud/repo/acme/analysts"


@pytest.mark.parametrize(
    "url, expected",
    [
        (ORG_URL, ("acme", "analysts")),
        (ORG_URL + "/", ("acme", "analysts")),
        ("https://repo.anaconda.cloud/repo/main", None),
        ("https://repo.anaconda.cloud/repo/acme/analysts/linux-64", None),
        ("https://repo.anaconda.com/pkgs/main", None),
        ("https://conda.anaconda.org/conda-forge", None),
    ],
)
def test_parse_org_channel(url, expected):
    assert parse_org_channel(url) == expected


def test_auth_domain_default_for_repo_host():
    assert auth_domain(ORG_URL, []) == "anaconda.com"


def test_auth_domain_channel_settings_override():
    settings = [
        {"channel": "https://repo.anaconda.cloud/*", "auth": "anaconda-auth"},
        {
            "channel": "https://repo.anaconda.cloud/repo/acme/*",
            "auth_domain": "example.org",
        },
    ]
    assert auth_domain(ORG_URL, settings) == "example.org"
    assert (
        auth_domain("https://repo.anaconda.cloud/repo/other/ch", settings)
        == "anaconda.com"
    )


@pytest.fixture
def condarc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def write(text: str) -> None:
        path = tmp_path / "condarc"
        path.write_text(text)
        monkeypatch.setenv("CONDARC", str(path))
        monkeypatch.setenv("HOME", str(tmp_path))
        reset_context()

    yield write
    monkeypatch.delenv("CONDARC")
    reset_context()


def test_policy_channels_expands_defaults(condarc):
    condarc(
        f"""
channels: [defaults, conda-forge]
default_channels:
  - {ORG_URL}
  - https://repo.anaconda.cloud/repo/main
"""
    )
    assert policy_channels(context.channels, context.channel_settings) == [
        PolicyChannel(ORG_URL, "acme", "analysts", "anaconda.com")
    ]


def test_policy_channels_explicit_url():
    assert policy_channels([ORG_URL + "/linux-64"], []) == [
        PolicyChannel(ORG_URL, "acme", "analysts", "anaconda.com")
    ]
