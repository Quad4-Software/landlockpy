# SPDX-License-Identifier: 0BSD

import errno
from pathlib import Path

import pytest

from landlockpy import AccessFS, Ruleset
from landlockpy.testing import probe, probe_path

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


def test_probe_custom_callable(tmp_path: Path) -> None:
    denied = tmp_path / "denied"
    denied.mkdir()
    with Ruleset() as ruleset:
        ruleset.allow_path(tmp_path, AccessFS.READ_FILE | AccessFS.READ_DIR)
        result = probe(ruleset, lambda: (denied / "x.txt").write_text("x"))
    assert not result.ok
    assert result.errno == errno.EACCES


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
