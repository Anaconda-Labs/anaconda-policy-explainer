"""The plugin as conda loads it, through conda's own plugin manager."""

from conda.base.context import context
from conda.exceptions import CondaError
from conda.exceptions import PackagesNotFoundInChannelsError
from conda.models.match_spec import MatchSpec

from anaconda_policy_explainer import plugin


def test_registered_with_conda():
    names = [name for name, _ in context.plugin_manager.list_name_plugin()]
    assert "anaconda_policy_explainer.plugin" in names


def test_pre_solve_remembers_requested_specs():
    specs = frozenset({MatchSpec("urllib3"), MatchSpec("jinja2")})
    context.plugin_manager.invoke_pre_solves(specs, frozenset())
    assert plugin._requested == [MatchSpec("jinja2"), MatchSpec("urllib3")]


def test_no_hint_without_organization_channels():
    error = PackagesNotFoundInChannelsError(["notapkg123"], ["conda-forge"])
    hints = context.plugin_manager.get_error_hints(error)
    assert all(hint.hint_code != plugin.HINT_CODE for hint in hints)


def test_ignores_unrelated_errors():
    assert list(plugin.conda_error_hints(CondaError("unrelated"))) == []
