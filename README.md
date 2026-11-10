# anaconda-policy-explainer

> [!WARNING]
> **This project is a proof of concept.** There is no guarantee that it will be maintained, and APIs may change or disappear without notice. You are welcome to discuss it in the [github issue tracker](https://github.com/Anaconda-Labs/anaconda-policy-explainer/issues)

A conda plugin that explains solve failures caused by Anaconda channel policies.

Channels on `repo.anaconda.cloud` can be filtered by an organization's policy that removes packages, for example every build with a CVE score above 7: the organization's own channels, and Anaconda channels such as `main` as served to that organization. When a solve then fails, conda reports missing packages or unsatisfiable dependencies but not why they are missing. This plugin adds the policy, the packages it removed, and the reason for each to conda's error output.

```
PackagesNotFoundInChannelsError: The following packages are not available from current channels:

  - urllib3=2.6.0

Next steps:
  - (anaconda_channel_policy) acme/analysts is filtered by policy "secure"
      removes packages where:
        cve_score > 7
      ┌───────────────────────────────┬──────────────┬─────────────┬────────────┐
      │ Package                       │ Required by  │ Reason      │ CVEs       │
      ├───────────────────────────────┼──────────────┼─────────────┼────────────┤
      │ urllib3-2.6.0-py313h06a4308_0 │ your request │ CVE 8.9 > 7 │ 1 active   │
      │                               │              │             │ 4 reported │
      │                               │              │             │ 9 cleared  │
      └───────────────────────────────┴──────────────┴─────────────┴────────────┘
```

For an environment, the table lists every build the policy removed that the environment needs, what required it, and the build's CVEs by status:

```
      ┌───────────────────────────────────┬────────────────────────────────────────┬─────────────┬────────────┐
      │ Package                           │ Required by                            │ Reason      │ CVEs       │
      ├───────────────────────────────────┼────────────────────────────────────────┼─────────────┼────────────┤
      │ jinja2-3.1.6-py313h06a4308_1      │ your request                           │ CVE 8.6 > 7 │ 4 cleared  │
      ├───────────────────────────────────┼────────────────────────────────────────┼─────────────┼────────────┤
      │ python-3.13.18-h3ef32e2_100_cp313 │ your request                           │ CVE 7.2 > 7 │ 1 reported │
      │                                   │                                        │             │ 86 cleared │
      │                                   │                                        │             │ 5 disputed │
      ├───────────────────────────────────┼────────────────────────────────────────┼─────────────┼────────────┤
      │ ncurses-6.6-hfaaeb4e_0            │ python-3.13.18-h3ef32e2_100_cp313 (+2) │ CVE 7.1 > 7 │ 14 cleared │
      ├───────────────────────────────────┼────────────────────────────────────────┼─────────────┼────────────┤
      │ zlib-1.3.2-h47b2149_0             │ sqlite-3.53.4-h795bf6d_0 (+1)          │ CVE 7.5 > 7 │ 1 reported │
      │                                   │                                        │             │ 8 cleared  │
      └───────────────────────────────────┴────────────────────────────────────────┴─────────────┴────────────┘
```

The policy is shown as it is stored, one rule per line, with nested groups indented:

```
      removes packages where any of:
        all of:
          cve_score > 7
          cve_status == active
        all of:
          cve_score > 4
          cve_status == reported
      keeps packages where:
        conda_spec == numpy >=1.8
```

## Install

```
pip install anaconda-policy-explainer
```

The plugin needs conda 26.7 or newer (for the `conda_error_hints` hook) and works with the classic, libmamba and rattler solvers. It reads channel policies with your [anaconda-auth](https://github.com/anaconda/anaconda-auth) credentials: `anaconda auth login`, or an API key in `ANACONDA_AUTH_API_KEY`.

The plugin compares your channel with the public channel it is built from, such as `https://repo.anaconda.com/pkgs/main`. Use of that channel is subject to [Anaconda's Terms of Service](https://www.anaconda.com/legal/terms/terms-of-service), which must be accepted.

## How it works

1. A pre-solve hook records what the solve was asked to do: the specs, channels, target environment and platforms.
2. When the solve fails with `PackagesNotFoundError` or `UnsatisfiableError`, the plugin looks for channels on `repo.anaconda.cloud` among those channels and reads each channel's policy and source from the Anaconda API:
   - organization channels (`https://repo.anaconda.cloud/repo/<org>/<channel>`) name their organization;
   - Anaconda channels such as `https://repo.anaconda.cloud/repo/main` are filtered by the policy of the organization your credentials act as. The plugin asks the repo which organization that is (the `x-auth-org-id` header of a HEAD request) and reads that organization's policy for the channel.
3. For a channel built from `main`, `r`, `msys2`, `conda-forge` or an external mirror, it downloads the source's index through conda's repodata cache, for your platform and `noarch`, and links it into a local channel in your user cache directory. The local channel keeps the same path between runs, so conda caches its index only once.
4. It solves again with the same solver, specs and environment, with the local channel added at the lowest priority and channel priority set to flexible. The solver only takes packages from the local channel when your channels cannot provide them, so those packages are what the environment needs from outside your channels.
5. For each of those packages it asks the Anaconda API whether the channel policy removed that exact file, why, and which CVEs the file has. Packages the policy did not remove (for example, published since the policy last ran) are listed as not in the channel yet.
6. It reports one section per channel policy.

API calls go to the domain anaconda-auth uses for the channel (`anaconda.com` for `repo.anaconda.cloud`, or a `channel_settings` `auth_domain`). If that differs from your default anaconda-auth site, the report says so. Lookups for one channel stop after 30 seconds; packages that could not be checked in time, or whose lookup failed, are still listed, marked as not checked.

If the second solve also fails, the failure is not caused by the policy alone, and the plugin stays silent. If anything else goes wrong, the plugin also stays silent and conda's error is shown unchanged.

Upload channels, channels built from sources without a public copy (such as `main-x`), and channels on repo hosts other than `repo.anaconda.cloud` are not explained yet.

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

The live tests run real conda with both solvers against such a channel, with an empty `HOME` so your own configuration cannot satisfy the request. They are skipped unless you name the channel, a spec its policy removed, and an API key:

```
APE_LIVE_CHANNEL=https://repo.anaconda.cloud/repo/<org>/<channel> \
APE_LIVE_REMOVED_SPEC=urllib3=2.6.0 \
ANACONDA_AUTH_API_KEY=$(anaconda auth api-key) \
pixi run test-live
```

For an Anaconda channel filtered by an organization policy, `APE_LIVE_MAIN_API_KEY` (a key for that organization) and `APE_LIVE_MAIN_REMOVED_SPEC` (a spec its policy on `main` removed) add a test against `https://repo.anaconda.cloud/repo/main`.

`tests/data/environments` holds environment files that use `defaults`; the live tests point `default_channels` at the channel under test.

## License

BSD-3-Clause
