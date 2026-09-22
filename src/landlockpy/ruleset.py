# SPDX-License-Identifier: 0BSD
"""Ruleset construction and enforcement for Landlock."""

from __future__ import annotations

import contextlib
import os
import types

from . import _syscall
from .errors import UnsupportedError
from .flags import (
    LATEST_ABI,
    AccessFS,
    AccessNet,
    RestrictFlag,
    Scope,
    fs_for_abi,
    net_for_abi,
    restrict_for_abi,
    scope_for_abi,
)

__all__ = ["Ruleset"]


class Ruleset:
    """A Landlock ruleset under construction.

    A ruleset declares which access rights it handles. Handled rights are
    denied by default once the ruleset is enforced. The allow_path()
    and allow_port() methods grant back specific rights for specific objects:

        with Ruleset() as ruleset:
            ruleset.allow_path("/usr", AccessFS.READ_FILE | AccessFS.READ_DIR)
            ruleset.allow_port(443, AccessNet.CONNECT_TCP)
            ruleset.restrict()

    Rights the running kernel does not support are dropped in best-effort
    mode (the default), or rejected with UnsupportedError when best_effort
    is False.

    The ruleset owns a kernel file descriptor. Use it as a context manager
    or call close() to release it.

    Kernel reference: https://docs.kernel.org/userspace-api/landlock.html
    """

    __slots__ = (
        "_abi",
        "_best_effort",
        "_closed",
        "_enforced",
        "_fd",
        "_handled_fs",
        "_handled_net",
        "_scoped",
    )

    def __init__(
        self,
        *,
        handled_fs: AccessFS | None = None,
        handled_net: AccessNet | None = None,
        scoped: Scope = Scope.NONE,
        quiet_fs: AccessFS = AccessFS.NONE,
        quiet_net: AccessNet = AccessNet.NONE,
        quiet_scoped: Scope = Scope.NONE,
        best_effort: bool = True,
    ) -> None:
        self._fd = -1
        self._closed = True
        self._enforced = False
        self._best_effort = best_effort
        self._abi = _syscall.abi_version()

        req_fs = fs_for_abi(LATEST_ABI) if handled_fs is None else AccessFS(handled_fs)
        req_net = (
            net_for_abi(LATEST_ABI) if handled_net is None else AccessNet(handled_net)
        )
        req_scoped = Scope(scoped)

        if best_effort:
            self._handled_fs = req_fs & fs_for_abi(self._abi)
            self._handled_net = req_net & net_for_abi(self._abi)
            self._scoped = req_scoped & scope_for_abi(self._abi)
        else:
            self._reject_unsupported(req_fs, fs_for_abi(self._abi), "filesystem")
            self._reject_unsupported(req_net, net_for_abi(self._abi), "network")
            self._reject_unsupported(req_scoped, scope_for_abi(self._abi), "scope")
            self._handled_fs = req_fs
            self._handled_net = req_net
            self._scoped = req_scoped

        quiet_fs, quiet_net, quiet_scoped = (
            AccessFS(quiet_fs),
            AccessNet(quiet_net),
            Scope(quiet_scoped),
        )
        if self._abi < 10 and (quiet_fs or quiet_net or quiet_scoped):
            if not best_effort:
                raise UnsupportedError("quiet rules require ABI 10")
            quiet_fs, quiet_net, quiet_scoped = (
                AccessFS.NONE,
                AccessNet.NONE,
                Scope.NONE,
            )
        if quiet_fs & ~self._handled_fs:
            raise ValueError("quiet_fs must be a subset of handled_fs")
        if quiet_net & ~self._handled_net:
            raise ValueError("quiet_net must be a subset of handled_net")
        if quiet_scoped & ~self._scoped:
            raise ValueError("quiet_scoped must be a subset of scoped")

        attr = _syscall.RulesetAttr(
            handled_access_fs=int(self._handled_fs),
            handled_access_net=int(self._handled_net),
            scoped=int(self._scoped),
            quiet_access_fs=int(quiet_fs),
            quiet_access_net=int(quiet_net),
            quiet_scoped=int(quiet_scoped),
        )
        self._fd = _syscall.create_ruleset(attr)
        os.set_inheritable(self._fd, False)
        self._closed = False

    @staticmethod
    def _reject_unsupported(requested: int, supported: int, kind: str) -> None:
        missing = requested & ~supported
        if missing:
            raise UnsupportedError(
                f"kernel does not support requested {kind} rights: {missing:#x}"
            )

    def _gate_quiet(self, quiet: bool) -> bool:
        if quiet and self._abi < 10:
            if not self._best_effort:
                raise UnsupportedError("quiet rules require ABI 10")
            return False
        return quiet

    @property
    def abi_version(self) -> int:
        """Landlock ABI version of the running kernel."""
        return self._abi

    @property
    def handled_fs(self) -> AccessFS:
        """Filesystem rights this ruleset denies by default."""
        return self._handled_fs

    @property
    def handled_net(self) -> AccessNet:
        """Network rights this ruleset denies by default."""
        return self._handled_net

    @property
    def scoped(self) -> Scope:
        """Scope isolation flags applied to the domain."""
        return self._scoped

    @property
    def enforced(self) -> bool:
        """Whether restrict() has been called successfully."""
        return self._enforced

    @property
    def closed(self) -> bool:
        """Whether the ruleset file descriptor has been closed."""
        return self._closed

    def fileno(self) -> int:
        """Return the underlying ruleset file descriptor."""
        if self._closed:
            raise ValueError("ruleset is closed")
        return self._fd

    def _check_mutable(self) -> None:
        if self._closed:
            raise RuntimeError("ruleset is closed")
        if self._enforced:
            raise RuntimeError("ruleset is already enforced")

    def allow_path(
        self, path: str | os.PathLike[str], access: AccessFS, *, quiet: bool = False
    ) -> AccessFS:
        """Grant filesystem access rights on a file hierarchy.

        The path can point to a file or a directory. A directory rule covers
        its whole hierarchy. Access is masked against the handled filesystem
        rights. Returns the rights actually granted, which is empty if none
        of the requested rights are handled and no rule was added.

        quiet marks the rule with LANDLOCK_ADD_RULE_QUIET, suppressing audit
        logs for accesses the ruleset declared quiet. Quiet requires ABI 10.
        On older kernels it is dropped in best-effort mode or rejected with
        UnsupportedError in strict mode. See "Extending a ruleset" in the
        kernel documentation.
        """
        self._check_mutable()
        quiet = self._gate_quiet(quiet)
        granted = AccessFS(access) & self._handled_fs
        if not granted:
            return AccessFS.NONE
        parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            attr = _syscall.PathBeneathAttr(
                allowed_access=int(granted), parent_fd=parent_fd
            )
            flags = _syscall.ADD_RULE_QUIET if quiet else 0
            _syscall.add_path_beneath(self._fd, attr, flags)
        finally:
            os.close(parent_fd)
        return granted

    def allow_port(
        self, port: int, access: AccessNet, *, quiet: bool = False
    ) -> AccessNet:
        """Grant network access rights on a TCP or UDP port.

        Port 0 covers the ephemeral port range used by auto-bound sockets.
        Access is masked against the handled network rights. Returns the
        rights actually granted, which is empty if none of the requested
        rights are handled and no rule was added.

        A LandlockError with errno EAFNOSUPPORT means the kernel lacks
        TCP/IP support. The operation is impossible anyway and the error
        can safely be ignored. See "Extending a ruleset" in the kernel
        documentation.
        """
        self._check_mutable()
        if not 0 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        quiet = self._gate_quiet(quiet)
        granted = AccessNet(access) & self._handled_net
        if not granted:
            return AccessNet.NONE
        attr = _syscall.NetPortAttr(allowed_access=int(granted), port=port)
        flags = _syscall.ADD_RULE_QUIET if quiet else 0
        _syscall.add_net_port(self._fd, attr, flags)
        return granted

    def restrict(
        self, flags: RestrictFlag = RestrictFlag.NONE, *, no_new_privs: bool = True
    ) -> None:
        """Enforce the ruleset on the calling thread and its future children.

        Flags unsupported by the running kernel are dropped. With
        no_new_privs, the thread is also prevented from gaining privileges
        through suid or file-capability binaries. On ABI 11 and newer this
        is set atomically with enforcement. On older kernels a
        prctl(PR_SET_NO_NEW_PRIVS) call is made first.

        Enforcement is irreversible and per-thread. Without the TSYNC flag
        (ABI 8), only the calling thread and its future children are
        restricted. Sibling threads keep their own policy. See "Enforcing
        a ruleset" in the kernel documentation.
        """
        if self._closed:
            raise RuntimeError("ruleset is closed")
        if self._enforced:
            raise RuntimeError("ruleset is already enforced")
        effective = RestrictFlag(flags) & restrict_for_abi(self._abi)
        if no_new_privs:
            if self._abi >= 11:
                effective |= RestrictFlag.NO_NEW_PRIVS
            else:
                _syscall.set_no_new_privs()
        _syscall.restrict_self(self._fd, int(effective))
        self._enforced = True

    def close(self) -> None:
        """Close the ruleset file descriptor. Safe to call twice."""
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __copy__(self) -> Ruleset:
        raise TypeError("Ruleset cannot be copied: it owns a kernel file descriptor")

    def __deepcopy__(self, memo: dict[int, object]) -> Ruleset:
        raise TypeError("Ruleset cannot be copied: it owns a kernel file descriptor")

    def __repr__(self) -> str:
        state = "closed" if self._closed else "enforced" if self._enforced else "open"
        abi = getattr(self, "_abi", "?")
        return f"{type(self).__name__}(fd={self._fd}, abi={abi}, {state})"

    def __enter__(self) -> Ruleset:
        if self._closed:
            raise RuntimeError("ruleset is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        # __del__ must never raise
        with contextlib.suppress(Exception):
            self.close()
