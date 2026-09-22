# SPDX-License-Identifier: 0BSD
"""Helpers for testing code against Landlock policies.

probe() runs a callable in a forked child process under a ruleset, so
tests and applications can verify what a policy grants before enforcing
it for real.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .ruleset import Ruleset

__all__ = ["ProbeResult", "probe", "probe_path"]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a probe() run.

    ok is True when fn completed under the ruleset. When fn or the
    enforcement raised an OSError, errno holds its errno value such as
    EACCES or EPERM. signal is nonzero if the child was killed by a
    signal instead of exiting normally.
    """

    ok: bool
    errno: int = 0
    signal: int = 0


def probe(ruleset: Ruleset, fn: Callable[[], object]) -> ProbeResult:
    """Run fn in a forked child process restricted by ruleset.

    The ruleset must be unenforced. It is enforced in the child only, so
    the caller's copy stays usable. The return value of fn is discarded.
    The child exits with os._exit, so atexit handlers, buffered I/O and
    threads do not run there.
    """
    if ruleset.closed:
        raise RuntimeError("ruleset is closed")
    if ruleset.enforced:
        raise RuntimeError("ruleset is already enforced")

    pid = os.fork()
    if pid == 0:
        try:
            ruleset.restrict()
            fn()
        except OSError as exc:
            os._exit(exc.errno if exc.errno is not None else 1)
        except BaseException:
            os._exit(255)
        os._exit(0)

    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return ProbeResult(ok=False, signal=os.WTERMSIG(status))
    code = os.WEXITSTATUS(status)
    if code == 0:
        return ProbeResult(ok=True)
    return ProbeResult(ok=False, errno=code)


def probe_path(ruleset: Ruleset, path: str | os.PathLike[str]) -> ProbeResult:
    """Probe whether the ruleset allows reading the file at path.

    Convenience wrapper around probe() for the common case of checking
    whether a path remains readable under a policy.
    """
    return probe(ruleset, lambda: Path(path).read_bytes())
