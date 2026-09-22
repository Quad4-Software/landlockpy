# SPDX-License-Identifier: 0BSD
"""Access rights, scope flags and restrict flags for Landlock rulesets.

Flag values mirror the constants in linux/landlock.h. Each flag records the
oldest Landlock ABI version that supports it; use the for_abi helpers to
compute the subset usable on a given kernel.
"""

from enum import IntFlag
from typing import TypeVar

__all__ = [
    "LATEST_ABI",
    "AccessFS",
    "AccessNet",
    "RestrictFlag",
    "Scope",
    "fs_for_abi",
    "net_for_abi",
    "restrict_for_abi",
    "scope_for_abi",
]

LATEST_ABI = 11
"""Newest Landlock ABI version known to this library."""


class AccessFS(IntFlag):
    """Filesystem access rights for handled_access_fs and path rules."""

    NONE = 0
    EXECUTE = 1 << 0
    WRITE_FILE = 1 << 1
    READ_FILE = 1 << 2
    READ_DIR = 1 << 3
    REMOVE_DIR = 1 << 4
    REMOVE_FILE = 1 << 5
    MAKE_CHAR = 1 << 6
    MAKE_DIR = 1 << 7
    MAKE_REG = 1 << 8
    MAKE_SOCK = 1 << 9
    MAKE_FIFO = 1 << 10
    MAKE_BLOCK = 1 << 11
    MAKE_SYM = 1 << 12
    REFER = 1 << 13
    TRUNCATE = 1 << 14
    IOCTL_DEV = 1 << 15
    RESOLVE_UNIX = 1 << 16


class AccessNet(IntFlag):
    """Network access rights for handled_access_net and port rules."""

    NONE = 0
    BIND_TCP = 1 << 0
    CONNECT_TCP = 1 << 1
    BIND_UDP = 1 << 2
    CONNECT_SEND_UDP = 1 << 3


class Scope(IntFlag):
    """Scope flags isolating a Landlock domain from outside IPC resources."""

    NONE = 0
    ABSTRACT_UNIX_SOCKET = 1 << 0
    SIGNAL = 1 << 1


class RestrictFlag(IntFlag):
    """Flags accepted by landlock_restrict_self."""

    NONE = 0
    LOG_SAME_EXEC_OFF = 1 << 0
    LOG_NEW_EXEC_ON = 1 << 1
    LOG_SUBDOMAINS_OFF = 1 << 2
    TSYNC = 1 << 3
    NO_NEW_PRIVS = 1 << 4


_F = TypeVar("_F", bound=IntFlag)

_FS_MIN_ABI: dict[AccessFS, int] = {
    AccessFS.EXECUTE: 1,
    AccessFS.WRITE_FILE: 1,
    AccessFS.READ_FILE: 1,
    AccessFS.READ_DIR: 1,
    AccessFS.REMOVE_DIR: 1,
    AccessFS.REMOVE_FILE: 1,
    AccessFS.MAKE_CHAR: 1,
    AccessFS.MAKE_DIR: 1,
    AccessFS.MAKE_REG: 1,
    AccessFS.MAKE_SOCK: 1,
    AccessFS.MAKE_FIFO: 1,
    AccessFS.MAKE_BLOCK: 1,
    AccessFS.MAKE_SYM: 1,
    AccessFS.REFER: 2,
    AccessFS.TRUNCATE: 3,
    AccessFS.IOCTL_DEV: 5,
    AccessFS.RESOLVE_UNIX: 9,
}

_NET_MIN_ABI: dict[AccessNet, int] = {
    AccessNet.BIND_TCP: 4,
    AccessNet.CONNECT_TCP: 4,
    AccessNet.BIND_UDP: 10,
    AccessNet.CONNECT_SEND_UDP: 10,
}

_SCOPE_MIN_ABI: dict[Scope, int] = {
    Scope.ABSTRACT_UNIX_SOCKET: 6,
    Scope.SIGNAL: 6,
}

_RESTRICT_MIN_ABI: dict[RestrictFlag, int] = {
    RestrictFlag.LOG_SAME_EXEC_OFF: 7,
    RestrictFlag.LOG_NEW_EXEC_ON: 7,
    RestrictFlag.LOG_SUBDOMAINS_OFF: 7,
    RestrictFlag.TSYNC: 8,
    RestrictFlag.NO_NEW_PRIVS: 11,
}


def _for_abi(table: dict[_F, int], flag_type: type[_F], abi: int) -> _F:
    mask = flag_type(0)
    for flag, min_abi in table.items():
        if abi >= min_abi:
            mask |= flag
    return mask


def fs_for_abi(abi: int) -> AccessFS:
    """Return the filesystem rights supported by the given ABI version."""
    return _for_abi(_FS_MIN_ABI, AccessFS, abi)


def net_for_abi(abi: int) -> AccessNet:
    """Return the network rights supported by the given ABI version."""
    return _for_abi(_NET_MIN_ABI, AccessNet, abi)


def scope_for_abi(abi: int) -> Scope:
    """Return the scope flags supported by the given ABI version."""
    return _for_abi(_SCOPE_MIN_ABI, Scope, abi)


def restrict_for_abi(abi: int) -> RestrictFlag:
    """Return the restrict flags supported by the given ABI version."""
    return _for_abi(_RESTRICT_MIN_ABI, RestrictFlag, abi)
