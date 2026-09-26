# SPDX-License-Identifier: 0BSD

import errno
import os
from pathlib import Path

import pytest

from landlockpy import AccessFS, Ruleset, _syscall
from landlockpy.testing import _probe_child, probe, probe_path

from .conftest import requires_landlock

pytestmark = requires_landlock


def test_probe_allowed(tmp_path: Path) -> None:
    (tmp_path / "ok.txt").write_text("ok")
    with Ruleset() as ruleset:
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE | AccessFS.READ_DIR)
        result = probe_path(ruleset, tmp_path / "ok.txt")
    assert result.ok, result


def test_probe_denied(tmp_path: Path) -> None:
    (tmp_path / "secret.txt").write_text("secret")
    with Ruleset() as ruleset:
        result = probe_path(ruleset, tmp_path / "secret.txt")
    assert not result.ok
    assert result.errno == errno.EACCES
    assert "PermissionError" in result.exception


def test_probe_custom_callable(tmp_path: Path) -> None:
    denied = tmp_path / "denied"
    denied.mkdir()
    with Ruleset() as ruleset:
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE | AccessFS.READ_DIR)
        result = probe(ruleset, lambda: (denied / "x.txt").write_text("x"))
    assert not result.ok
    assert result.errno == errno.EACCES


def test_probe_reports_non_oserror() -> None:
    with Ruleset() as ruleset:
        result = probe(ruleset, lambda: int("nope"))
    assert not result.ok
    assert result.errno == 0
    assert "ValueError" in result.exception


def test_probe_leaves_ruleset_unenforced(tmp_path: Path) -> None:
    with Ruleset() as ruleset:
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE)
        probe_path(ruleset, tmp_path)
        assert not ruleset.enforced
        assert not ruleset.closed
        ruleset.allow_path(tmp_path, AccessFS.READ_DIR)


def test_probe_rejects_used_ruleset(tmp_path: Path) -> None:
    ruleset = Ruleset()
    ruleset.close()
    with pytest.raises(RuntimeError, match="closed"):
        probe_path(ruleset, tmp_path)


@pytest.fixture
def fake_ruleset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let Ruleset() and restrict() run without a Landlock kernel."""
    monkeypatch.setattr(_syscall, "abi_version", lambda: 11)
    monkeypatch.setattr(
        _syscall,
        "create_ruleset",
        lambda attr: os.open("/dev/null", os.O_RDONLY),
    )
    monkeypatch.setattr(_syscall, "restrict_self", lambda fd, flags: None)


def test_probe_child_maps_results(fake_ruleset: None) -> None:
    read_fd, write_fd = os.pipe()
    with Ruleset() as ruleset:
        assert _probe_child(ruleset, lambda: None, write_fd) == 0
        assert ruleset.enforced

    def denied() -> None:
        raise PermissionError(errno.EACCES, "denied")

    with Ruleset() as ruleset:
        assert _probe_child(ruleset, denied, write_fd) == errno.EACCES

    with Ruleset() as ruleset:
        assert _probe_child(ruleset, lambda: int("x"), write_fd) == 255

    os.close(write_fd)
    data = os.read(read_fd, 4096)
    os.close(read_fd)
    assert b"PermissionError" in data
    assert b"ValueError" in data


def test_probe_rejects_enforced_ruleset(fake_ruleset: None, tmp_path: Path) -> None:
    with Ruleset() as ruleset:
        ruleset.restrict()
        with pytest.raises(RuntimeError, match="enforced"):
            probe(ruleset, lambda: None)


def test_probe_fork_failure_closes_pipe(
    fake_ruleset: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> int:
        raise OSError(errno.EAGAIN, "no more processes")

    monkeypatch.setattr(os, "fork", boom)
    with Ruleset() as ruleset, pytest.raises(OSError, match="no more"):
        probe(ruleset, lambda: None)
