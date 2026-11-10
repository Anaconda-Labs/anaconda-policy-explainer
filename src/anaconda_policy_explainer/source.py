"""The unfiltered index a policy channel was built from, as a local channel.

The index is fetched through conda's own repodata cache and linked into a
temporary channel as ``<subdir>/repodata.json``.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from conda.core.subdir_data import SubdirData
from conda.models.channel import Channel

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


def _link(cached: Path, target: Path) -> None:
    try:
        os.symlink(cached, target)
    except OSError:
        shutil.copyfile(cached, target)


@contextmanager
def local_channel(url: str, subdirs: Iterable[str]) -> Iterator[str]:
    """A file:// channel holding ``url``'s index for ``subdirs``."""
    with TemporaryDirectory(prefix="anaconda-policy-explainer-") as tmp:
        for subdir in subdirs:
            fetch = SubdirData(Channel(f"{url}/{subdir}")).repo_fetch
            cached, _ = fetch.fetch_latest_path()
            target = Path(tmp, subdir)
            target.mkdir()
            _link(Path(cached), target / "repodata.json")
        yield Path(tmp).as_uri()
