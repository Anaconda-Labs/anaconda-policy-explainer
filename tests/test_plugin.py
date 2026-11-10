"""The plugin as conda loads it, through conda's own plugin manager."""

from pathlib import Path

from conda.base.context import context
from conda.exceptions import CondaError
from conda.exceptions import PackagesNotFoundInChannelsError
from conda.models.match_spec import MatchSpec

from anaconda_policy_explainer import plugin


def test_registered_with_conda():
    names = [name for name, _ in context.plugin_manager.list_name_plugin()]
    assert "anaconda_policy_explainer.plugin" in names


def test_pre_solve_remembers_the_solve(tmp_path):
    channel = (Path(__file__).parent / "data" / "filtered-channel").as_uri()
    solver_class = context.plugin_manager.get_solver_backend()
    solver = solver_class(
        str(tmp_path / "env"),
        [channel],
        ("linux-64", "noarch"),
        specs_to_add=[MatchSpec("pandas")],
    )
    solver.solve_for_transaction()
    assert plugin._last.specs_to_add == [MatchSpec("pandas")]
    assert plugin._last.specs_to_remove == []
    assert [c.base_url for c in plugin._last.channels or ()] == [channel]
    assert plugin._last.prefix == str(tmp_path / "env")
    assert plugin._last.subdirs == ("linux-64", "noarch")


def test_no_hint_without_organization_channels():
    error = PackagesNotFoundInChannelsError(["notapkg123"], ["conda-forge"])
    hints = context.plugin_manager.get_error_hints(error)
    assert all(hint.hint_code != plugin.HINT_CODE for hint in hints)


def test_ignores_unrelated_errors():
    assert list(plugin.conda_error_hints(CondaError("unrelated"))) == []
