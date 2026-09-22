# SPDX-License-Identifier: 0BSD

import errno

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
