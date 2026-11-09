# anaconda-policy-explainer

> [!WARNING]
> **This project is a proof of concept.** There is no guarantee that it will be maintained, and APIs may change or disappear without notice. You are welcome to discuss it in the [github issue tracker](https://github.com/Anaconda-Labs/anaconda-policy-explainer/issues)

A conda plugin that explains solve failures caused by Anaconda channel policies.

Organization channels on `repo.anaconda.cloud` can have a policy that removes packages, for example every build with a CVE score above 7. When a solve then fails, conda reports missing packages or unsatisfiable dependencies but not why they are missing. This plugin adds the policy, the packages it removed, and the reason for each to conda's error output.

```
PackagesNotFoundInChannelsError: The following packages are not available from current channels:

  - urllib3=2.6.0

Next steps:
  - (anaconda_channel_policy) acme/analysts is filtered by policy "secure": removes cve_score > 7
      urllib3=2.6.0 (requested)
        2.6.0 removed: CVE 8.9 > 7
```

When the cause is a dependency, the report names it and what needed it:

```
LibMambaUnsatisfiableError: Encountered problems while solving:
  - nothing provides jinja2 needed by altair-6.3.0-py313h06a4308_0
...
Next steps:
  - (anaconda_channel_policy) acme/analysts is filtered by policy "secure": removes cve_score > 7
      jinja2 (needed by altair-6.3.0-py313h06a4308_0)
        3.1.6 removed: CVE 8.6 > 7
        3.1.5 removed: CVE 8.6 > 7
        3.1.4 removed: CVE 8.6 > 7
```

## Install

```
pip install anaconda-policy-explainer
```

The plugin needs conda 26.7 or newer (for the `conda_error_hints` hook) and works with the classic, libmamba and rattler solvers. It reads the channel policy with your [anaconda-auth](https://github.com/anaconda/anaconda-auth) credentials: `anaconda auth login`, or an API key in `ANACONDA_AUTH_API_KEY`.

## How it works

1. A pre-solve hook records the specs you asked for.
2. When the solve fails with `PackagesNotFoundError` or `UnsatisfiableError`, the plugin looks for organization channels (`https://repo.anaconda.cloud/repo/<org>/<channel>`) among the channels conda used.
3. It walks your specs and their dependencies through the filtered repodata conda already downloaded, plus the packages installed in the target environment, and collects the specs nothing available can satisfy. Like a solver, it only follows the newest three versions of each package.
4. For each blocked package it asks the Anaconda API which of its newest versions the channel policy removed, and why.
5. It reports one section per channel policy. Packages that do not exist upstream at all are left out.

API calls go to the domain anaconda-auth uses for the channel (`anaconda.com` for `repo.anaconda.cloud`, or a `channel_settings` `auth_domain`). If that differs from your default anaconda-auth site, the report says so. Lookups for one channel stop after 30 seconds; the report then says how many packages were not checked.

If anything goes wrong, the plugin stays silent and conda's error is shown unchanged.

## Development

The development environment is managed by [pixi](https://pixi.sh). It contains conda, both solvers and the plugin as an editable install, so `pixi run conda ...` runs conda with the plugin loaded.

```
pixi run test        # unit tests
pixi run lint
pixi run typecheck
pixi run format
```

To try it against a channel with a policy, name the channel explicitly so channels from your `~/.condarc` do not satisfy the request:

```
pixi run conda create -n try --dry-run --override-channels \
    -c https://repo.anaconda.cloud/repo/<org>/<channel> <spec>
```

The live tests run real conda with both solvers against such a channel. They are skipped unless you name the channel and a spec its policy removed:

```
APE_LIVE_CHANNEL=https://repo.anaconda.cloud/repo/<org>/<channel> \
APE_LIVE_REMOVED_SPEC=urllib3=2.6.0 \
pixi run test-live
```

## License

BSD-3-Clause
