"""conda plugin hooks.

Imports here stay light: conda loads this module on every invocation.
"""

from __future__ import annotations

from collections.abc import Iterable

from conda import plugins
from conda.plugins.types import CondaErrorHint


@plugins.hookimpl
def conda_error_hints(error: Exception) -> Iterable[CondaErrorHint]:
    yield from ()
