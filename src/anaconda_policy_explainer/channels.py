"""Find Anaconda organization channels among the channels conda used.

Two kinds live on the repo host: organization channels
(``/repo/<org>/<channel>``) name their organization, and Anaconda channels
(``/repo/main``) are filtered by the policy of whichever organization the
user's credentials act as, which is only known after asking the repo.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from conda.models.channel import Channel

REPO_HOST = "repo.anaconda.cloud"

# Mirrors anaconda-auth's TOKEN_DOMAIN_MAP for the repo host we support:
# repo.anaconda.cloud channels authenticate against anaconda.com.
TOKEN_DOMAINS = {REPO_HOST: "anaconda.com"}

_SEGMENT = r"[A-Za-z0-9._-]+"
_ORG_CHANNEL_PATH = re.compile(
    rf"^/repo/(?P<org>{_SEGMENT})/(?P<channel>{_SEGMENT})/?$"
)
_ANACONDA_CHANNEL_PATH = re.compile(rf"^/repo/(?P<channel>{_SEGMENT})/?$")


@dataclass(frozen=True)
class PolicyChannel:
    """A channel on the repo host that may have a policy assigned.

    ``org`` is empty for an Anaconda channel until its organization is known.
    """

    url: str
    org: str
    channel: str
    auth_domain: str
    anaconda: bool = False

    @property
    def api_path(self) -> str:
        owner = "anaconda" if self.anaconda else self.org
        return f"/api/organizations/{self.org}/channels/{owner}/{self.channel}"

    @property
    def label(self) -> str:
        if self.anaconda:
            return f'{self.channel} for organization "{self.org}"'
        return f"{self.org}/{self.channel}"


def parse_org_channel(url: str) -> tuple[str, str] | None:
    """Return (org, channel) for a repo.anaconda.cloud organization channel URL."""
    parsed = urlparse(url)
    if parsed.hostname != REPO_HOST:
        return None
    match = _ORG_CHANNEL_PATH.match(parsed.path)
    if match is None:
        return None
    return match["org"], match["channel"]


def parse_anaconda_channel(url: str) -> str | None:
    """Return the channel name for a repo.anaconda.cloud Anaconda channel URL."""
    parsed = urlparse(url)
    if parsed.hostname != REPO_HOST:
        return None
    match = _ANACONDA_CHANNEL_PATH.match(parsed.path)
    return match["channel"] if match else None


def auth_domain(url: str, channel_settings: Iterable[Mapping[str, str]]) -> str:
    """Domain anaconda-auth authenticates this channel against.

    A matching ``channel_settings`` entry with ``auth_domain`` overrides the
    default for the channel's host, as in anaconda-auth's conda auth handler.
    """
    host = urlparse(url).hostname or ""
    domain = TOKEN_DOMAINS.get(host, host)
    for setting in channel_settings:
        pattern = setting.get("channel", "")
        override = setting.get("auth_domain")
        if override and fnmatch(url, pattern):
            domain = override
    return domain


def base_urls(channel_names: Iterable[str | Channel]) -> list[str]:
    """Expand channel names (including multichannels like ``defaults``) to base URLs."""
    urls: list[str] = []
    for name in channel_names:
        channel = name if isinstance(name, Channel) else Channel(name)
        for url in getattr(channel, "base_urls", None) or (channel.base_url,):
            if url and url not in urls:
                urls.append(url)
    return urls


def policy_channels(
    channel_names: Iterable[str | Channel],
    channel_settings: Iterable[Mapping[str, str]],
) -> list[PolicyChannel]:
    """Repo host channels among ``channel_names``, in channel priority order."""
    settings = list(channel_settings)
    found: list[PolicyChannel] = []
    for url in base_urls(channel_names):
        domain = auth_domain(url, settings)
        if org_channel := parse_org_channel(url):
            found.append(PolicyChannel(url, *org_channel, domain))
        elif name := parse_anaconda_channel(url):
            found.append(PolicyChannel(url, "", name, domain, anaconda=True))
    return found
