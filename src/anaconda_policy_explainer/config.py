"""Plugin settings from ``[plugin.policy_explainer]`` in ``~/.anaconda/config.toml``.

``sources`` maps a policy's source name (``main``, ``main-x``, ...) to an
unfiltered channel in the same organization as the filtered channel, e.g.::

    [plugin.policy_explainer.sources]
    main = "https://repo.anaconda.cloud/repo/acme/main-unfiltered"

When any source is configured, only configured sources are used.
"""

from __future__ import annotations

from anaconda_cli_base.config import AnacondaBaseSettings


class ExplainerConfig(AnacondaBaseSettings, plugin_name="policy_explainer"):
    sources: dict[str, str] = {}
