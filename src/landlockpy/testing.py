# SPDX-License-Identifier: 0BSD
"""Helpers for testing code against Landlock policies.

probe() runs a callable in a forked child process under a ruleset, so
tests and applications can verify what a policy grants before enforcing
it for real.
"""

from __future__ import annotations

import contextlib
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
    EACCES or EPERM. For failures that are not OSError, errno is 0 and
    exception holds a "ClassName: message" string from the child. signal
    is nonzero if the child was killed by a signal instead of exiting
    normally.
    """

    ok: bool
    errno: int = 0
    signal: int = 0
    exception: str = ""


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

    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        os._exit(_probe_child(ruleset, fn, write_fd))

    os.close(write_fd)
    try:
        _, status = os.waitpid(pid, 0)
        os.set_blocking(read_fd, False)
        try:
            detail = os.read(read_fd, 4096).decode(errors="replace")
        except BlockingIOError:
            detail = ""
    finally:
        os.close(read_fd)

    if os.WIFSIGNALED(status):
        return ProbeResult(ok=False, signal=os.WTERMSIG(status))
    code = os.WEXITSTATUS(status)
    if code == 0:
        return ProbeResult(ok=True)
    if code == 255:
        return ProbeResult(ok=False, exception=detail)
    return ProbeResult(ok=False, errno=code, exception=detail)


def _probe_child(ruleset: Ruleset, fn: Callable[[], object], write_fd: int) -> int:
    """Body of the forked probe child. Returns its exit code.

    OSError maps to its errno so the parent can report it. Any other
    exception maps to 255 with a "ClassName: message" string sent over
    the pipe.
    """
    try:
        ruleset.restrict()
        fn()
    except BaseException as exc:
        with contextlib.suppress(Exception):
            os.write(write_fd, f"{type(exc).__name__}: {exc}".encode()[:4000])
        if isinstance(exc, OSError) and exc.errno is not None and 0 < exc.errno < 255:
            return exc.errno
        return 255
    return 0


def probe_path(ruleset: Ruleset, path: str | os.PathLike[str]) -> ProbeResult:
    """Probe whether the ruleset allows reading the file at path.

    Convenience wrapper around probe() for the common case of checking
    whether a path remains readable under a policy.
    """
    return probe(ruleset, lambda: Path(path).read_bytes())
