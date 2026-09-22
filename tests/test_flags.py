# SPDX-License-Identifier: 0BSD

from landlockpy import AccessFS, AccessNet, RestrictFlag, Scope, flags
from landlockpy.flags import (
    fs_for_abi,
    net_for_abi,
    restrict_for_abi,
    scope_for_abi,
)


def test_fs_flag_values_match_kernel_header() -> None:
    assert AccessFS.EXECUTE == 1 << 0
    assert AccessFS.WRITE_FILE == 1 << 1
    assert AccessFS.READ_FILE == 1 << 2
    assert AccessFS.READ_DIR == 1 << 3
    assert AccessFS.REMOVE_DIR == 1 << 4
    assert AccessFS.REMOVE_FILE == 1 << 5
    assert AccessFS.MAKE_CHAR == 1 << 6
    assert AccessFS.MAKE_DIR == 1 << 7
    assert AccessFS.MAKE_REG == 1 << 8
    assert AccessFS.MAKE_SOCK == 1 << 9
    assert AccessFS.MAKE_FIFO == 1 << 10
    assert AccessFS.MAKE_BLOCK == 1 << 11
    assert AccessFS.MAKE_SYM == 1 << 12
    assert AccessFS.REFER == 1 << 13
    assert AccessFS.TRUNCATE == 1 << 14
    assert AccessFS.IOCTL_DEV == 1 << 15
    assert AccessFS.RESOLVE_UNIX == 1 << 16


def test_net_flag_values_match_kernel_header() -> None:
    assert AccessNet.BIND_TCP == 1 << 0
    assert AccessNet.CONNECT_TCP == 1 << 1
    assert AccessNet.BIND_UDP == 1 << 2
    assert AccessNet.CONNECT_SEND_UDP == 1 << 3


def test_scope_flag_values_match_kernel_header() -> None:
    assert Scope.ABSTRACT_UNIX_SOCKET == 1 << 0
    assert Scope.SIGNAL == 1 << 1


def test_restrict_flag_values_match_kernel_header() -> None:
    assert RestrictFlag.LOG_SAME_EXEC_OFF == 1 << 0
    assert RestrictFlag.LOG_NEW_EXEC_ON == 1 << 1
    assert RestrictFlag.LOG_SUBDOMAINS_OFF == 1 << 2
    assert RestrictFlag.TSYNC == 1 << 3
    assert RestrictFlag.NO_NEW_PRIVS == 1 << 4


def test_every_member_has_min_abi() -> None:
    for table, flag_type in (
        (flags._FS_MIN_ABI, AccessFS),
        (flags._NET_MIN_ABI, AccessNet),
        (flags._SCOPE_MIN_ABI, Scope),
        (flags._RESTRICT_MIN_ABI, RestrictFlag),
    ):
        for member in flag_type:
            if member.value == 0:
                continue  # NONE members have no ABI floor
            assert member in table, f"{member} missing from min-ABI table"


def test_fs_for_abi_boundaries() -> None:
    abi1 = fs_for_abi(1)
    assert AccessFS.EXECUTE in abi1
    assert AccessFS.MAKE_SYM in abi1
    assert AccessFS.REFER not in abi1

    assert AccessFS.REFER in fs_for_abi(2)
    assert AccessFS.TRUNCATE not in fs_for_abi(2)
    assert AccessFS.TRUNCATE in fs_for_abi(3)
    assert AccessFS.IOCTL_DEV not in fs_for_abi(4)
    assert AccessFS.IOCTL_DEV in fs_for_abi(5)
    assert AccessFS.RESOLVE_UNIX not in fs_for_abi(8)
    assert AccessFS.RESOLVE_UNIX in fs_for_abi(9)


def test_net_for_abi_boundaries() -> None:
    assert net_for_abi(3) == AccessNet(0)
    abi4 = net_for_abi(4)
    assert abi4 == AccessNet.BIND_TCP | AccessNet.CONNECT_TCP
    abi10 = net_for_abi(10)
    assert AccessNet.BIND_UDP in abi10
    assert AccessNet.CONNECT_SEND_UDP in abi10


def test_scope_for_abi_boundaries() -> None:
    assert scope_for_abi(5) == Scope(0)
    abi6 = scope_for_abi(6)
    assert abi6 == Scope.ABSTRACT_UNIX_SOCKET | Scope.SIGNAL


def test_restrict_for_abi_boundaries() -> None:
    assert restrict_for_abi(6) == RestrictFlag(0)
    abi7 = restrict_for_abi(7)
    assert abi7 == (
        RestrictFlag.LOG_SAME_EXEC_OFF
        | RestrictFlag.LOG_NEW_EXEC_ON
        | RestrictFlag.LOG_SUBDOMAINS_OFF
    )
    assert RestrictFlag.TSYNC in restrict_for_abi(8)
    assert RestrictFlag.NO_NEW_PRIVS not in restrict_for_abi(10)
    assert RestrictFlag.NO_NEW_PRIVS in restrict_for_abi(11)


def test_latest_abi_covers_everything() -> None:
    for flag_type, full in (
        (AccessFS, fs_for_abi(flags.LATEST_ABI)),
        (AccessNet, net_for_abi(flags.LATEST_ABI)),
        (Scope, scope_for_abi(flags.LATEST_ABI)),
        (RestrictFlag, restrict_for_abi(flags.LATEST_ABI)),
    ):
        for member in flag_type:
            assert member.value == 0 or member.value & int(full), (
                f"{member} not covered at LATEST_ABI"
            )
