"""The unfiltered index a policy channel was built from, as a local channel.

The index is fetched through conda's own repodata cache and linked into a
local channel as ``<subdir>/repodata.json``.
The local channel's path is stable per source, because conda caches indexes
by channel URL.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from conda.core.subdir_data import SubdirData
from conda.models.channel import Channel
from platformdirs import user_cache_dir

from .channels import REPO_HOST
from .channels import PolicyChannel

PUBLIC_SOURCES = {
    "main": "https://repo.anaconda.com/pkgs/main",
    "r": "https://repo.anaconda.com/pkgs/r",
    "msys2": "https://repo.anaconda.com/pkgs/msys2",
    "conda-forge": "https://conda.anaconda.org/conda-forge",
}


def unfiltered_url(channel: PolicyChannel, source: str | None) -> str | None:
    """Public channel with the same packages as ``source``, if there is one.

    Source names map to Anaconda's public channels only for the production
    repo host; external mirrors already name their upstream URL.
    """
    if not source or urlparse(channel.url).hostname != REPO_HOST:
        return None
    if urlparse(source).scheme in ("http", "https"):
        return source.rstrip("/")
    return PUBLIC_SOURCES.get(source)


CACHE = Path(user_cache_dir("anaconda-policy-explainer"))


def _link(cached: Path, target: Path) -> None:
    """Point ``target`` at ``cached``, replacing it atomically."""
    staging = target.with_name(f"{target.name}.{os.getpid()}")
    try:
        os.symlink(cached, staging)
    except OSError:
        shutil.copyfile(cached, staging)
    os.replace(staging, target)


def local_channel(url: str, subdirs: Iterable[str]) -> str:
    """A file:// channel holding ``url``'s index for ``subdirs``."""
    root = CACHE / "channels" / hashlib.sha256(url.encode()).hexdigest()[:16]
    for subdir in subdirs:
        fetch = SubdirData(Channel(f"{url}/{subdir}")).repo_fetch
        cached, _ = fetch.fetch_latest_path()
        target = root / subdir
        target.mkdir(parents=True, exist_ok=True)
        _link(Path(cached), target / "repodata.json")
    return root.as_uri()
