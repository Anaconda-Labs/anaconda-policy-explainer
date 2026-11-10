"""Find Anaconda organization channels among the channels conda used."""

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

_ORG_CHANNEL_PATH = re.compile(
    r"^/repo/(?P<org>[A-Za-z0-9._-]+)/(?P<channel>[A-Za-z0-9._-]+)/?$"
)


@dataclass(frozen=True)
class PolicyChannel:
    """An organization channel that may have a policy assigned."""

    url: str
    org: str
    channel: str
    auth_domain: str


def parse_org_channel(url: str) -> tuple[str, str] | None:
    """Return (org, channel) for a repo.anaconda.cloud organization channel URL."""
    parsed = urlparse(url)
    if parsed.hostname != REPO_HOST:
        return None
    match = _ORG_CHANNEL_PATH.match(parsed.path)
    if match is None:
        return None
    return match["org"], match["channel"]


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
    """Organization channels among ``channel_names``, in channel priority order."""
    settings = list(channel_settings)
    found: list[PolicyChannel] = []
    for url in base_urls(channel_names):
        org_channel = parse_org_channel(url)
        if org_channel is None:
            continue
        org, channel = org_channel
        found.append(PolicyChannel(url, org, channel, auth_domain(url, settings)))
    return found
