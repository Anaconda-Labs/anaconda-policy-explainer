"""Re-solve with real solvers against two channels on disk.

filtered-channel stands in for a policy-filtered channel; unfiltered-channel
is its source and also has jinja2 and python 3.13.11, which the "policy"
removed.
"""

from argparse import Namespace
from pathlib import Path

import pytest
from conda.base.context import reset_context
from conda.exceptions import CondaError
from conda.models.match_spec import MatchSpec

from anaconda_policy_explainer import source
from anaconda_policy_explainer.resolve import taken_from
from anaconda_policy_explainer.resolve import unfiltered_solve

DATA = Path(__file__).parent / "data"
FILTERED = (DATA / "filtered-channel").as_uri()
UNFILTERED = (DATA / "unfiltered-channel").as_uri()
SUBDIRS = ("linux-64", "noarch")


@pytest.fixture(params=["libmamba", "rattler", "classic"])
def solver(request, monkeypatch):
    monkeypatch.setenv("CONDA_SOLVER", request.param)
    reset_context()
    yield request.param
    monkeypatch.delenv("CONDA_SOLVER")
    reset_context()


@pytest.fixture(autouse=True)
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(source, "CACHE", tmp_path / "cache")


def taken(tmp_path: Path, *specs: str, channels=(FILTERED,)) -> list[str]:
    unfiltered = source.local_channel(UNFILTERED, SUBDIRS)
    solution = unfiltered_solve(
        str(tmp_path / "env"),
        channels,
        [unfiltered],
        SUBDIRS,
        [MatchSpec(s) for s in specs],
    )
    return sorted(
        r.dist_str().split("::")[-1] for r in taken_from(solution, unfiltered)
    )


def test_removed_dependency(solver, tmp_path):
    assert taken(tmp_path, "altair") == ["jinja2-3.1.6-py314h0_0"]


def test_removed_pin(solver, tmp_path):
    assert taken(tmp_path, "python=3.13.11=h0_100_cp313", "libzstd") == [
        "python-3.13.11-h0_100_cp313"
    ]


def test_strict_priority_is_overridden(solver, tmp_path, monkeypatch):
    # strict would forbid python from the lower channel: the filtered one has python
    monkeypatch.setenv("CONDA_CHANNEL_PRIORITY", "strict")
    reset_context()
    assert taken(tmp_path, "python=3.13.11") == ["python-3.13.11-h0_100_cp313"]


def test_strict_priority_flag_is_overridden(solver, tmp_path):
    reset_context(argparse_args=Namespace(channel_priority="strict"))
    assert taken(tmp_path, "python=3.13.11") == ["python-3.13.11-h0_100_cp313"]


def test_resolve_prints_nothing(solver, tmp_path, capfd):
    taken(tmp_path, "altair")
    assert capfd.readouterr() == ("", "")


def test_filtered_channel_through_defaults(solver, tmp_path, monkeypatch):
    monkeypatch.setenv("CONDA_DEFAULT_CHANNELS", FILTERED)
    reset_context()
    assert taken(tmp_path, "altair", channels=("defaults",)) == [
        "jinja2-3.1.6-py314h0_0"
    ]


def test_filtered_channel_preferred(solver, tmp_path):
    assert taken(tmp_path, "pandas", "python") == []


def test_not_explained_by_policy(solver, tmp_path):
    with pytest.raises(CondaError):
        taken(tmp_path, "anaconda-policy-explainer-no-such-package")
