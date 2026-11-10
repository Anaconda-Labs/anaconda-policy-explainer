"""Re-run the failed solve with unfiltered channels at the lowest priority."""

from __future__ import annotations

import io
import os
from argparse import Namespace
from collections.abc import Iterable
from collections.abc import Iterator
from contextlib import contextmanager
from contextlib import redirect_stderr
from contextlib import redirect_stdout

from conda.base.context import context
from conda.base.context import reset_context
from conda.models.channel import Channel
from conda.models.match_spec import MatchSpec
from conda.models.records import PackageRecord

from .channels import base_urls

OVERRIDES = {"CONDA_CHANNEL_PRIORITY": "flexible", "CONDA_QUIET": "true"}


@contextmanager
def _quiet_flexible_priority() -> Iterator[None]:
    """Flexible priority and no output, even against command-line flags.

    Command-line arguments outrank environment variables, so
    --strict-channel-priority is overridden on a copy of them. Output is
    captured because conda's progress reporting prints regardless of quiet.
    """
    args = getattr(context, "_argparse_args", None)
    forced = Namespace(**{**args, "channel_priority": "flexible"}) if args else None
    saved = {name: os.environ.get(name) for name in OVERRIDES}
    os.environ.update(OVERRIDES)
    reset_context(argparse_args=forced)
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        reset_context(argparse_args=args)


def unfiltered_solve(
    prefix: str,
    channels: Iterable[str | Channel],
    unfiltered: Iterable[str],
    subdirs: Iterable[str],
    specs_to_add: Iterable[MatchSpec],
    specs_to_remove: Iterable[MatchSpec] = (),
) -> tuple[PackageRecord, ...]:
    """Solve with ``unfiltered`` after ``channels`` and flexible priority.

    Uses the solver the user's command used. Records that come from an
    ``unfiltered`` channel are what the filtered channels are missing.
    """
    solver_class = context.plugin_manager.get_solver_backend()
    # Expand multichannels such as "defaults" into their URLs. Re-solving with
    # the captured "defaults" object, rattler did not use the unfiltered
    # channel for a live organization channel (not reproduced offline).
    all_channels = [Channel(url) for url in (*base_urls(channels), *unfiltered)]
    with _quiet_flexible_priority():
        solver = solver_class(
            prefix,
            all_channels,
            tuple(subdirs),
            specs_to_add=tuple(specs_to_add),
            specs_to_remove=tuple(specs_to_remove),
        )
        return tuple(solver.solve_final_state())


def taken_from(
    records: Iterable[PackageRecord], channel_url: str
) -> list[PackageRecord]:
    url = channel_url.rstrip("/")
    return [r for r in records if r.channel.base_url.rstrip("/") == url]
