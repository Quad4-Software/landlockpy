# SPDX-License-Identifier: 0BSD
"""Tests that apply real Landlock policies in a child process."""

import socket
from pathlib import Path

import pytest

import landlockpy

from .conftest import Sandbox, requires_landlock

pytestmark = [pytest.mark.enforced, requires_landlock]


def test_fs_enforcement(sandbox: Sandbox, tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    (allowed / "ok.txt").write_text("ok")
    (denied / "secret.txt").write_text("secret")

    result = sandbox("fs", allowed, denied)
    assert result.returncode == 0, result.stdout + result.stderr


def test_no_new_privs_set_on_restrict(sandbox: Sandbox) -> None:
    result = sandbox("nnp")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(landlockpy.abi_version() < 4, reason="network rules need ABI 4")
def test_net_enforcement(sandbox: Sandbox) -> None:
    result = sandbox("net", 45678)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(landlockpy.abi_version() < 6, reason="scoped domains need ABI 6")
def test_abstract_socket_scope(sandbox: Sandbox) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind("\0landlockpy-test")
    listener.listen(1)
    try:
        result = sandbox("abstract")
    finally:
        listener.close()
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(landlockpy.abi_version() < 10, reason="UDP rules need ABI 10")
def test_udp_enforcement(sandbox: Sandbox) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    allowed_port = sock.getsockname()[1]
    try:
        result = sandbox("udp", allowed_port, 45679)
    finally:
        sock.close()
    assert result.returncode == 0, result.stdout + result.stderr
