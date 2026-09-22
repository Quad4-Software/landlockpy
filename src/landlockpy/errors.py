# SPDX-License-Identifier: 0BSD
"""Exception types raised by landlockpy."""


class LandlockError(OSError):
    """A Landlock syscall failed."""


class UnsupportedError(LandlockError):
    """The running kernel does not support Landlock or the requested feature."""
