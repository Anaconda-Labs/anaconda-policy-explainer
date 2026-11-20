import json
from pathlib import Path
from urllib.request import urlopen

import pytest

from anaconda_policy_explainer import source
from anaconda_policy_explainer.channels import PolicyChannel
from anaconda_policy_explainer.source import local_channel
from anaconda_policy_explainer.source import unfiltered_url

PROD = PolicyChannel(
    "https://repo.anaconda.cloud/repo/acme/analysts", "acme", "analysts", "anaconda.com"
)
STAGE = PolicyChannel(
    "https://repo.example.org/repo/acme/analysts",
    "acme",
    "analysts",
    "example.org",
)


@pytest.mark.parametrize(
    "source, expected",
    [
        ("main", "https://repo.anaconda.com/pkgs/main"),
        ("conda-forge", "https://conda.anaconda.org/conda-forge"),
        ("https://conda.anaconda.org/esri/", "https://conda.anaconda.org/esri"),
        ("main-x", None),
        ("community", None),
        (None, None),
    ],
)
def test_unfiltered_url_prod(source, expected):
    assert unfiltered_url(PROD, source) == expected


def test_no_public_source_outside_prod():
    assert unfiltered_url(STAGE, "main") is None


OWN = "https://repo.anaconda.cloud/repo/acme/main-unfiltered"


@pytest.mark.parametrize(
    "configured, source, expected",
    [
        ({"main": OWN + "/"}, "main", OWN),
        ({"main-x": OWN}, "main-x", OWN),
        ({"main-x": OWN}, "main", None),
        ({"main": "https://repo.anaconda.cloud/repo/other/main"}, "main", None),
        ({"main": "https://repo.anaconda.com/pkgs/main"}, "main", None),
    ],
)
def test_configured_sources_replace_public(configured, source, expected):
    assert unfiltered_url(PROD, source, configured) == expected


def test_configured_sources_from_config_toml(tmp_path, monkeypatch):
    from anaconda_policy_explainer.config import ExplainerConfig

    toml = tmp_path / "config.toml"
    toml.write_text(f'[plugin.policy_explainer.sources]\nmain = "{OWN}"\n')
    monkeypatch.setenv("ANACONDA_CONFIG_TOML", str(toml))
    assert ExplainerConfig().sources == {"main": OWN}


UNFILTERED = (Path(__file__).parent / "data" / "unfiltered-channel").as_uri()


def test_local_channel_has_every_subdir(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "CACHE", tmp_path)
    url = local_channel(UNFILTERED, ("linux-64", "noarch"))
    for subdir in ("linux-64", "noarch"):
        with urlopen(f"{url}/{subdir}/repodata.json") as response:
            assert json.load(response)["info"]["subdir"] == subdir


def test_local_channel_path_is_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "CACHE", tmp_path)
    first = local_channel(UNFILTERED, ("linux-64", "noarch"))
    assert local_channel(UNFILTERED, ("linux-64", "noarch")) == first
    assert len(list((tmp_path / "channels").iterdir())) == 1
