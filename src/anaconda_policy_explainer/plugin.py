"""conda plugin hooks.

conda imports this module on every invocation, so it stays light; the
explanation code is imported only when a solve has failed.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from conda import plugins
from conda.models.match_spec import MatchSpec
from conda.plugins.types import CondaErrorHint
from conda.plugins.types import CondaPreSolve

log = logging.getLogger(__name__)

HINT_CODE = "anaconda_channel_policy"


@dataclass
class Solve:
    """What the last solve was asked to do, and where."""

    specs_to_add: list[MatchSpec] = field(default_factory=list)
    specs_to_remove: list[MatchSpec] = field(default_factory=list)
    channels: tuple[Any, ...] | None = None
    prefix: str | None = None
    subdirs: tuple[str, ...] | None = None


_last = Solve()


def _calling_solver() -> Any:
    """The solver running this hook.

    The hook only receives specs, but conda calls it from
    BaseSolver.solve_for_transaction, so the solver is ``self`` up the stack.
    Its channels include those from ``conda env create`` files, which never
    reach ``context.channels``.
    """
    from conda.core.solve import BaseSolver

    frame = inspect.currentframe()
    while frame is not None:
        candidate = frame.f_locals.get("self")
        if isinstance(candidate, BaseSolver):
            return candidate
        frame = frame.f_back
    return None


def _remember_solve(
    specs_to_add: frozenset[MatchSpec], specs_to_remove: frozenset[MatchSpec]
) -> None:
    global _last
    solver = _calling_solver()
    _last = Solve(
        sorted(specs_to_add, key=str),
        sorted(specs_to_remove, key=str),
        tuple(solver.channels) if solver else None,
        str(solver.prefix) if solver else None,
        tuple(solver.subdirs) if solver else None,
    )


@plugins.hookimpl
def conda_pre_solves() -> Iterable[CondaPreSolve]:
    yield CondaPreSolve(name="anaconda-policy-explainer", action=_remember_solve)


@plugins.hookimpl
def conda_error_hints(error: Exception) -> Iterable[CondaErrorHint]:
    from conda.exceptions import PackagesNotFoundError
    from conda.exceptions import UnsatisfiableError

    if not isinstance(error, (PackagesNotFoundError, UnsatisfiableError)):
        return
    try:
        from .explain import explain

        sections = explain(_last)
    except Exception:
        log.debug("anaconda-policy-explainer failed", exc_info=True)
        return
    for section in sections:
        yield CondaErrorHint(text=section, hint_code=HINT_CODE)
