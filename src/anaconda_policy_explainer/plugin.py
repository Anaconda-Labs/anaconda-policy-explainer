"""conda plugin hooks.

conda imports this module on every invocation, so it stays light; the
explanation code is imported only when a solve has failed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from conda import plugins
from conda.models.match_spec import MatchSpec
from conda.plugins.types import CondaErrorHint
from conda.plugins.types import CondaPreSolve

log = logging.getLogger(__name__)

HINT_CODE = "anaconda_channel_policy"

_requested: list[MatchSpec] = []
_to_remove: list[MatchSpec] = []


def _remember_specs(
    specs_to_add: frozenset[MatchSpec], specs_to_remove: frozenset[MatchSpec]
) -> None:
    _requested[:] = sorted(specs_to_add, key=str)
    _to_remove[:] = sorted(specs_to_remove, key=str)


@plugins.hookimpl
def conda_pre_solves() -> Iterable[CondaPreSolve]:
    yield CondaPreSolve(name="anaconda-policy-explainer", action=_remember_specs)


@plugins.hookimpl
def conda_error_hints(error: Exception) -> Iterable[CondaErrorHint]:
    from conda.exceptions import PackagesNotFoundError
    from conda.exceptions import UnsatisfiableError

    if not isinstance(error, (PackagesNotFoundError, UnsatisfiableError)):
        return
    try:
        from .explain import explain

        # Copies: the re-solve runs the pre-solve hook again.
        sections = explain(list(_requested), list(_to_remove))
    except Exception:
        log.debug("anaconda-policy-explainer failed", exc_info=True)
        return
    for section in sections:
        yield CondaErrorHint(text=section, hint_code=HINT_CODE)
