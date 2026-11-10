from pathlib import Path

import pytest
from conda.base.context import context
from conda.base.context import reset_context

from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.channels import auth_domain
from anaconda_policy_explainer.channels import parse_anaconda_channel
from anaconda_policy_explainer.channels import parse_org_channel
from anaconda_policy_explainer.channels import policy_channels

ORG_URL = "https://repo.anaconda.cloud/repo/acme/analysts"
MAIN_URL = "https://repo.anaconda.cloud/repo/main"


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
        PolicyChannel(ORG_URL, "acme", "analysts", "anaconda.com"),
        PolicyChannel(MAIN_URL, "", "main", "anaconda.com", anaconda=True),
    ]


def test_policy_channels_explicit_url():
    assert policy_channels([ORG_URL + "/linux-64"], []) == [
        PolicyChannel(ORG_URL, "acme", "analysts", "anaconda.com")
    ]


@pytest.mark.parametrize(
    "url, expected",
    [
        (MAIN_URL, "main"),
        (MAIN_URL + "/", "main"),
        ("https://repo.anaconda.cloud/repo/main-x", "main-x"),
        (ORG_URL, None),
        ("https://repo.anaconda.com/pkgs/main", None),
    ],
)
def test_parse_anaconda_channel(url, expected):
    assert parse_anaconda_channel(url) == expected


def test_anaconda_channel_label_and_api_path():
    main = PolicyChannel(MAIN_URL, "acme", "main", "anaconda.com", anaconda=True)
    assert main.label == 'main for organization "acme"'
    assert main.api_path == "/api/organizations/acme/channels/anaconda/main"
    org = PolicyChannel(ORG_URL, "acme", "analysts", "anaconda.com")
    assert org.label == "acme/analysts"
    assert org.api_path == "/api/organizations/acme/channels/acme/analysts"
