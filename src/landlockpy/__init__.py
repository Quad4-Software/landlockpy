# SPDX-License-Identifier: 0BSD
"""Python bindings for the Landlock Linux security module.

Landlock lets unprivileged processes sandbox themselves with filesystem,
network and IPC restrictions enforced by the kernel. Rulesets are scoped to
what the running kernel supports, so applications get best-effort protection
across kernel versions.
"""

import errno

from . import _syscall
from .errors import LandlockError, UnsupportedError
from .flags import (
    AccessFS,
    AccessNet,
    RestrictFlag,
    Scope,
    fs_for_abi,
    net_for_abi,
    restrict_for_abi,
    scope_for_abi,
)
from .ruleset import Ruleset

__version__ = "0.1.0"

__all__ = [
    "AccessFS",
    "AccessNet",
    "LandlockError",
    "RestrictFlag",
    "Ruleset",
    "Scope",
    "UnsupportedError",
    "__version__",
    "abi_version",
    "errata",
    "fs_for_abi",
    "net_for_abi",
    "restrict_for_abi",
    "scope_for_abi",
    "supported",
]


def abi_version() -> int:
    """Return the Landlock ABI version of the running kernel, or 0.

    A return value of 0 means the kernel is too old (ENOSYS) or Landlock is
    disabled at boot time (EOPNOTSUPP).
    """
    try:
        return _syscall.abi_version()
    except LandlockError as exc:
        if exc.errno in (errno.ENOSYS, errno.EOPNOTSUPP):
            return 0
        raise


def errata() -> int:
    """Return the errata bitmask for the current ABI version, or 0.

    Bit N set means erratum N is fixed in the running kernel. Older kernels
    without the errata mechanism report 0. Most applications should not
    check errata; best-effort enforcement is the safer default.
    """
    try:
        return _syscall.errata()
    except LandlockError as exc:
        if exc.errno in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL):
            return 0
        raise


def supported() -> bool:
    """Return whether the running kernel supports Landlock."""
    return abi_version() >= 1
