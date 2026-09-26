# SPDX-License-Identifier: 0BSD

import ctypes
import errno
import sys

import pytest

from landlockpy import (
    LandlockError,
    Ruleset,
    UnsupportedError,
    _syscall,
    abi_version,
    errata,
    supported,
)

from .conftest import requires_landlock


@requires_landlock
def test_abi_version_matches_kernel() -> None:
    assert abi_version() >= 1
    assert supported()


@requires_landlock
def test_errata_returns_bitmask() -> None:
    assert errata() >= 0


def test_abi_version_zero_when_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_enosys() -> int:
        raise UnsupportedError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(_syscall, "abi_version", raise_enosys)
    assert abi_version() == 0
    assert not supported()


def test_errata_zero_on_old_kernels(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval() -> int:
        raise LandlockError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "errata", raise_einval)
    assert errata() == 0


def test_ruleset_raises_when_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_eopnotsupp() -> int:
        raise UnsupportedError(errno.EOPNOTSUPP, "Operation not supported")

    monkeypatch.setattr(_syscall, "abi_version", raise_eopnotsupp)
    with pytest.raises(UnsupportedError):
        Ruleset()


def test_unexpected_errors_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_efault() -> int:
        raise LandlockError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "abi_version", raise_efault)
    with pytest.raises(LandlockError):
        abi_version()


def test_errors_carry_errno() -> None:
    err = LandlockError(errno.EACCES, "denied")
    assert err.errno == errno.EACCES
    assert isinstance(err, OSError)
    assert isinstance(UnsupportedError(errno.ENOSYS, "x"), LandlockError)


class _FakeLibc:
    """Answers like a failing libc for _call and set_no_new_privs."""

    def __init__(self, err: int) -> None:
        self.err = err

    def syscall(self, *args: object) -> int:
        ctypes.set_errno(self.err)
        return -1

    def prctl(self, *args: object) -> int:
        ctypes.set_errno(self.err)
        return -1


def test_landlock_unavailable_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_libc", None)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert abi_version() == 0
    assert not supported()
    assert errata() == 0
    with pytest.raises(UnsupportedError):
        Ruleset()


def test_call_maps_errno_to_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_get_libc", lambda: _FakeLibc(errno.EACCES))
    with pytest.raises(LandlockError) as excinfo:
        _syscall.restrict_self(0, 0)
    assert excinfo.value.errno == errno.EACCES
    assert not isinstance(excinfo.value, UnsupportedError)

    monkeypatch.setattr(_syscall, "_get_libc", lambda: _FakeLibc(errno.EOPNOTSUPP))
    with pytest.raises(UnsupportedError):
        _syscall.restrict_self(0, 0)


def test_prctl_failure_maps_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "_get_libc", lambda: _FakeLibc(errno.EPERM))
    with pytest.raises(LandlockError) as excinfo:
        _syscall.set_no_new_privs()
    assert excinfo.value.errno == errno.EPERM


def test_errata_unexpected_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_efault() -> int:
        raise LandlockError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "errata", raise_efault)
    with pytest.raises(LandlockError):
        errata()
