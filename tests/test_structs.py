# SPDX-License-Identifier: 0BSD
"""The ctypes layouts must match the kernel ABI exactly."""

import ctypes

from landlockpy import _syscall


def test_ruleset_attr_layout() -> None:
    assert ctypes.sizeof(_syscall.RulesetAttr) == 48
    assert _syscall.RulesetAttr.handled_access_fs.offset == 0
    assert _syscall.RulesetAttr.handled_access_net.offset == 8
    assert _syscall.RulesetAttr.scoped.offset == 16
    assert _syscall.RulesetAttr.quiet_access_fs.offset == 24
    assert _syscall.RulesetAttr.quiet_access_net.offset == 32
    assert _syscall.RulesetAttr.quiet_scoped.offset == 40


def test_path_beneath_attr_layout() -> None:
    # packed: u64 followed by s32 with no trailing padding
    assert ctypes.sizeof(_syscall.PathBeneathAttr) == 12
    assert _syscall.PathBeneathAttr.allowed_access.offset == 0
    assert _syscall.PathBeneathAttr.parent_fd.offset == 8


def test_net_port_attr_layout() -> None:
    assert ctypes.sizeof(_syscall.NetPortAttr) == 16
    assert _syscall.NetPortAttr.allowed_access.offset == 0
    assert _syscall.NetPortAttr.port.offset == 8


def test_syscall_numbers() -> None:
    assert _syscall.SYS_CREATE_RULESET == 444
    assert _syscall.SYS_ADD_RULE == 445
    assert _syscall.SYS_RESTRICT_SELF == 446


def test_create_flags() -> None:
    assert _syscall.CREATE_RULESET_VERSION == 1
    assert _syscall.CREATE_RULESET_ERRATA == 2
    assert _syscall.ADD_RULE_QUIET == 1
