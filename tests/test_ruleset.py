# SPDX-License-Identifier: 0BSD

import copy
import errno
import fcntl
import os
import pickle
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from landlockpy import (
    AccessFS,
    AccessNet,
    LandlockError,
    RestrictFlag,
    Ruleset,
    Scope,
    _syscall,
    abi_version,
    mute_subdomain_logs,
)
from landlockpy.errors import UnsupportedError

from .conftest import requires_landlock


@pytest.fixture
def fake_kernel(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Replace the syscall layer with a recorder and a real throwaway fd."""
    calls = SimpleNamespace(
        attr=None, rules=[], restricted=None, restricted_fd=None, nnp=0
    )

    def fake_create(attr: _syscall.RulesetAttr) -> int:
        calls.attr = attr
        return os.open("/dev/null", os.O_RDONLY)

    def fake_path(ruleset_fd: int, attr: _syscall.PathBeneathAttr, flags: int) -> None:
        calls.rules.append(("path", attr.allowed_access, flags))

    def fake_net(ruleset_fd: int, attr: _syscall.NetPortAttr, flags: int) -> None:
        calls.rules.append(("net", attr.allowed_access, attr.port, flags))

    def fake_restrict(ruleset_fd: int, flags: int) -> None:
        calls.restricted = flags
        calls.restricted_fd = ruleset_fd

    monkeypatch.setattr(_syscall, "create_ruleset", fake_create)
    monkeypatch.setattr(_syscall, "add_path_beneath", fake_path)
    monkeypatch.setattr(_syscall, "add_net_port", fake_net)
    monkeypatch.setattr(_syscall, "restrict_self", fake_restrict)
    monkeypatch.setattr(
        _syscall, "set_no_new_privs", lambda: setattr(calls, "nnp", calls.nnp + 1)
    )
    return calls


def set_abi(monkeypatch: pytest.MonkeyPatch, abi: int) -> None:
    monkeypatch.setattr(_syscall, "abi_version", lambda: abi)


def test_default_handles_all_known_rights(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset() as ruleset:
        assert ruleset.abi_version == 11
        assert ruleset.handled_fs == AccessFS((1 << 17) - 1)
        assert ruleset.handled_net == AccessNet((1 << 4) - 1)
        assert ruleset.scoped == Scope(0)
    assert fake_kernel.attr.handled_access_fs == (1 << 17) - 1
    assert fake_kernel.attr.handled_access_net == (1 << 4) - 1


def test_best_effort_masks_to_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 3)
    with Ruleset(
        handled_fs=AccessFS(0x1FFFF),
        handled_net=AccessNet(0xF),
        scoped=Scope.ABSTRACT_UNIX_SOCKET,
    ) as ruleset:
        assert ruleset.handled_fs == AccessFS(0x7FFF)  # bits 0-14, through TRUNCATE
        assert AccessFS.TRUNCATE in ruleset.handled_fs
        assert AccessFS.IOCTL_DEV not in ruleset.handled_fs
        assert ruleset.handled_net == AccessNet(0)
        assert ruleset.scoped == Scope(0)


def test_strict_mode_rejects_unsupported(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 4)
    with pytest.raises(UnsupportedError):
        Ruleset(handled_fs=AccessFS.IOCTL_DEV, best_effort=False)
    with pytest.raises(UnsupportedError):
        Ruleset(scoped=Scope.SIGNAL, best_effort=False)


def test_quiet_must_be_subset(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with pytest.raises(ValueError, match="subset"):
        Ruleset(handled_fs=AccessFS.READ_FILE, quiet_fs=AccessFS.WRITE_FILE)
    with pytest.raises(ValueError, match="subset"):
        Ruleset(quiet_scoped=Scope.SIGNAL)


def test_allow_path_masks_and_marshals(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 2)
    with Ruleset() as ruleset:
        granted = ruleset.allow_path(
            tmp_path, AccessFS.READ_FILE | AccessFS.TRUNCATE | AccessFS.RESOLVE_UNIX
        )
    assert granted == AccessFS.READ_FILE
    kind, access, flags = fake_kernel.rules[0]
    assert kind == "path"
    assert access == int(AccessFS.READ_FILE)
    assert flags == 0


def test_allow_path_skips_when_nothing_granted(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 4)
    with Ruleset() as ruleset:
        granted = ruleset.allow_path(tmp_path, AccessFS.RESOLVE_UNIX)
        assert granted == AccessFS(0)
    assert fake_kernel.rules == []


def test_allow_port_validates_range(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset() as ruleset:
        with pytest.raises(ValueError, match="port"):
            ruleset.allow_port(65536, AccessNet.BIND_TCP)
        with pytest.raises(ValueError, match="port"):
            ruleset.allow_port(-1, AccessNet.BIND_TCP)


def test_allow_port_marshals(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 10)
    with Ruleset() as ruleset:
        granted = ruleset.allow_port(53, AccessNet.CONNECT_TCP | AccessNet.BIND_UDP)
    assert granted == AccessNet.CONNECT_TCP | AccessNet.BIND_UDP
    kind, access, port, flags = fake_kernel.rules[0]
    assert (kind, access, port, flags) == (
        "net",
        int(AccessNet.CONNECT_TCP | AccessNet.BIND_UDP),
        53,
        0,
    )


def test_quiet_flag_passed_to_add_rule(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset(quiet_fs=AccessFS.READ_FILE) as ruleset:
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE, quiet=True)
        ruleset.allow_port(80, AccessNet.CONNECT_TCP, quiet=True)
    assert fake_kernel.attr.quiet_access_fs == int(AccessFS.READ_FILE)
    assert fake_kernel.rules[0][2] == _syscall.ADD_RULE_QUIET
    assert fake_kernel.rules[1][3] == _syscall.ADD_RULE_QUIET


def test_restrict_masks_flags_by_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 7)
    with Ruleset(handled_net=AccessNet.BIND_TCP) as ruleset:
        ruleset.restrict(RestrictFlag.TSYNC | RestrictFlag.LOG_NEW_EXEC_ON)
    assert fake_kernel.restricted == int(RestrictFlag.LOG_NEW_EXEC_ON)
    assert fake_kernel.nnp == 1


def test_restrict_uses_atomic_nnp_on_abi_11(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset() as ruleset:
        ruleset.restrict()
    assert fake_kernel.restricted == int(RestrictFlag.NO_NEW_PRIVS)
    assert fake_kernel.nnp == 0


def test_restrict_can_skip_nnp(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset() as ruleset:
        ruleset.restrict(no_new_privs=False)
    assert fake_kernel.restricted == 0
    assert fake_kernel.nnp == 0


def test_quiet_rule_flag_dropped_on_old_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 9)
    with Ruleset() as ruleset:
        granted = ruleset.allow_path(tmp_path, AccessFS.READ_FILE, quiet=True)
    assert granted == AccessFS.READ_FILE
    assert fake_kernel.rules[0][2] == 0


def test_quiet_rule_flag_raises_in_strict_mode(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 9)
    with (
        Ruleset(
            handled_fs=AccessFS.READ_FILE,
            handled_net=AccessNet.BIND_TCP,
            best_effort=False,
        ) as ruleset,
        pytest.raises(UnsupportedError, match="quiet"),
    ):
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE, quiet=True)


def test_allow_path_missing_path_propagates(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 11)
    with Ruleset() as ruleset, pytest.raises(FileNotFoundError):
        ruleset.allow_path(tmp_path / "missing", AccessFS.READ_FILE)


@requires_landlock
def test_fileno_raises_when_closed() -> None:
    ruleset = Ruleset()
    ruleset.close()
    with pytest.raises(ValueError, match="closed"):
        ruleset.fileno()


@requires_landlock
def test_enter_closed_ruleset_raises() -> None:
    ruleset = Ruleset()
    ruleset.close()
    with pytest.raises(RuntimeError, match="closed"), ruleset:
        pass


@requires_landlock
def test_ruleset_cannot_be_copied() -> None:
    with Ruleset() as ruleset:
        with pytest.raises(TypeError):
            copy.copy(ruleset)
        with pytest.raises(TypeError):
            copy.deepcopy(ruleset)


@requires_landlock
def test_repr() -> None:
    ruleset = Ruleset()
    assert repr(ruleset).startswith("Ruleset(fd=")
    assert f"abi={abi_version()}" in repr(ruleset)
    ruleset.close()
    assert "closed" in repr(ruleset)


@requires_landlock
def test_fd_is_close_on_exec() -> None:
    with Ruleset() as ruleset:
        flags = fcntl.fcntl(ruleset.fileno(), fcntl.F_GETFD)
        assert flags & fcntl.FD_CLOEXEC


def test_state_guards(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    set_abi(monkeypatch, 11)
    ruleset = Ruleset()
    ruleset.restrict()
    with pytest.raises(RuntimeError, match="enforced"):
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE)
    with pytest.raises(RuntimeError, match="enforced"):
        ruleset.restrict()
    ruleset.close()
    ruleset.close()
    with pytest.raises(RuntimeError, match="closed"):
        ruleset.allow_port(80, AccessNet.BIND_TCP)


@requires_landlock
def test_real_kernel_roundtrip(tmp_path: Path) -> None:
    with Ruleset() as ruleset:
        assert ruleset.abi_version == abi_version() >= 1
        granted = ruleset.allow_path(tmp_path, AccessFS.READ_FILE)
        assert granted == AccessFS.READ_FILE
        try:
            granted_net = ruleset.allow_port(443, AccessNet.CONNECT_TCP)
        except LandlockError as exc:
            # Kernels built without CONFIG_INET answer EAFNOSUPPORT.
            assert exc.errno == errno.EAFNOSUPPORT
        else:
            if ruleset.abi_version >= 4:
                assert granted_net == AccessNet.CONNECT_TCP
            else:
                assert granted_net == AccessNet.NONE
        assert ruleset.fileno() >= 0
    assert ruleset.closed


def test_strict_mode_rejects_unsupported_restrict_flags(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 7)
    with Ruleset(
        handled_fs=AccessFS.READ_FILE,
        handled_net=AccessNet.BIND_TCP,
        best_effort=False,
    ) as ruleset:
        with pytest.raises(UnsupportedError):
            ruleset.restrict(RestrictFlag.TSYNC)
        ruleset.restrict(RestrictFlag.LOG_NEW_EXEC_ON)
    assert fake_kernel.restricted == int(RestrictFlag.LOG_NEW_EXEC_ON)
    assert fake_kernel.nnp == 1


def test_quiet_rejected_in_strict_mode_on_old_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 9)
    with pytest.raises(UnsupportedError, match="quiet"):
        Ruleset(
            handled_fs=AccessFS.READ_FILE,
            handled_net=AccessNet.NONE,
            quiet_fs=AccessFS.READ_FILE,
            best_effort=False,
        )


def test_quiet_net_must_be_subset(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    with pytest.raises(ValueError, match="subset"):
        Ruleset(handled_net=AccessNet.BIND_TCP, quiet_net=AccessNet.CONNECT_TCP)


def test_allow_port_skips_when_nothing_granted(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 3)
    with Ruleset() as ruleset:
        granted = ruleset.allow_port(80, AccessNet.BIND_TCP)
    assert granted == AccessNet.NONE
    assert fake_kernel.rules == []


def test_allow_port_rejects_non_int(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    not_an_int: Any = 443.5
    with Ruleset() as ruleset, pytest.raises(TypeError):
        ruleset.allow_port(not_an_int, AccessNet.CONNECT_TCP)


def test_fd_closed_if_setup_fails(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    fds: list[int] = []
    closed: list[int] = []

    def boom(fd: int, inheritable: bool) -> None:
        fds.append(fd)
        raise OSError("set_inheritable failed")

    real_close = os.close

    def spy_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "set_inheritable", boom)
    monkeypatch.setattr(os, "close", spy_close)
    with pytest.raises(OSError, match="set_inheritable"):
        Ruleset()
    assert closed == fds


@requires_landlock
def test_ruleset_cannot_be_pickled() -> None:
    with Ruleset() as ruleset, pytest.raises(TypeError, match="pickled"):
        pickle.dumps(ruleset)


def test_mute_subdomain_logs(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 7)
    mute_subdomain_logs()
    assert fake_kernel.restricted_fd == -1
    assert fake_kernel.restricted == int(RestrictFlag.LOG_SUBDOMAINS_OFF)
    assert fake_kernel.nnp == 1


def test_mute_subdomain_logs_all_threads(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 8)
    mute_subdomain_logs(all_threads=True)
    assert fake_kernel.restricted_fd == -1
    assert fake_kernel.restricted == int(
        RestrictFlag.LOG_SUBDOMAINS_OFF | RestrictFlag.TSYNC
    )


def test_mute_subdomain_logs_old_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 6)
    with pytest.raises(UnsupportedError, match="ABI 7"):
        mute_subdomain_logs()
    assert fake_kernel.restricted is None

    set_abi(monkeypatch, 7)
    with pytest.raises(UnsupportedError, match="ABI 8"):
        mute_subdomain_logs(all_threads=True)
    assert fake_kernel.restricted is None


def test_quiet_dropped_in_best_effort_on_old_abi(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 9)
    with Ruleset(handled_fs=AccessFS.READ_FILE, quiet_fs=AccessFS.READ_FILE):
        pass
    assert fake_kernel.attr.quiet_access_fs == 0


def test_restrict_on_closed_ruleset(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_abi(monkeypatch, 11)
    ruleset = Ruleset()
    ruleset.close()
    with pytest.raises(RuntimeError, match="closed"):
        ruleset.restrict()
    assert fake_kernel.restricted is None
