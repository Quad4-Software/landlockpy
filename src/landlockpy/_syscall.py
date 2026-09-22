# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for the Landlock syscalls and prctl.

The Landlock syscall numbers 444-446 are shared by every architecture that
implements them. All calls go through libc's syscall(2) wrapper, so no libffi
or compiler is needed.
"""

import ctypes
import ctypes.util
import errno
import os
import sys

from .errors import LandlockError, UnsupportedError

SYS_CREATE_RULESET = 444
SYS_ADD_RULE = 445
SYS_RESTRICT_SELF = 446

PR_SET_NO_NEW_PRIVS = 38

CREATE_RULESET_VERSION = 1 << 0
CREATE_RULESET_ERRATA = 1 << 1

ADD_RULE_QUIET = 1 << 0

RULE_PATH_BENEATH = 1
RULE_NET_PORT = 2


class RulesetAttr(ctypes.Structure):
    """struct landlock_ruleset_attr. The quiet fields need ABI 10."""

    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
        ("quiet_access_fs", ctypes.c_uint64),
        ("quiet_access_net", ctypes.c_uint64),
        ("quiet_scoped", ctypes.c_uint64),
    ]


class PathBeneathAttr(ctypes.Structure):
    """struct landlock_path_beneath_attr. Packed, no trailing padding."""

    _pack_ = 1
    # Explicit layout: the implicit default is deprecated since Python 3.14.
    _layout_ = "ms"
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class NetPortAttr(ctypes.Structure):
    """struct landlock_net_port_attr."""

    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("Landlock is only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
        _libc.prctl.restype = ctypes.c_int
    return _libc


def _call(nr: int, *args: object) -> int:
    ret = int(_get_libc().syscall(nr, *args))
    if ret != -1:
        return ret
    err = ctypes.get_errno()
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        raise UnsupportedError(err, os.strerror(err))
    raise LandlockError(err, os.strerror(err))


def abi_version() -> int:
    """Return the highest Landlock ABI version supported by the kernel."""
    return _call(SYS_CREATE_RULESET, None, 0, CREATE_RULESET_VERSION)


def errata() -> int:
    """Return the errata bitmask for the current ABI version."""
    return _call(SYS_CREATE_RULESET, None, 0, CREATE_RULESET_ERRATA)


def create_ruleset(attr: RulesetAttr) -> int:
    """Create a ruleset and return its file descriptor."""
    return _call(SYS_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)


def add_path_beneath(ruleset_fd: int, attr: PathBeneathAttr, flags: int = 0) -> None:
    """Add a LANDLOCK_RULE_PATH_BENEATH rule to a ruleset."""
    _call(SYS_ADD_RULE, ruleset_fd, RULE_PATH_BENEATH, ctypes.byref(attr), flags)


def add_net_port(ruleset_fd: int, attr: NetPortAttr, flags: int = 0) -> None:
    """Add a LANDLOCK_RULE_NET_PORT rule to a ruleset."""
    _call(SYS_ADD_RULE, ruleset_fd, RULE_NET_PORT, ctypes.byref(attr), flags)


def set_no_new_privs() -> None:
    """Set the no_new_privs attribute on the calling thread via prctl."""
    ret = _get_libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret == -1:
        err = ctypes.get_errno()
        raise LandlockError(err, os.strerror(err))


def restrict_self(ruleset_fd: int, flags: int = 0) -> None:
    """Enforce a ruleset on the calling thread and its future children."""
    _call(SYS_RESTRICT_SELF, ruleset_fd, flags)
