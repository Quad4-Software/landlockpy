# SPDX-License-Identifier: 0BSD
"""Helper run as a subprocess by the enforced tests.

Enforcing a ruleset is irreversible, so it must happen in a child process.
Each scenario applies a policy, checks the expected allow and deny outcomes,
prints FAIL lines for mismatches and exits nonzero on failure.
"""

import errno
import os
import socket
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from landlockpy import (
    AccessFS,
    AccessNet,
    Ruleset,
    Scope,
    mute_subdomain_logs,
)

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        failures.append(f"{name}: {detail}")


def scenario_fs(allowed_dir: str, denied_dir: str) -> None:
    """Read-only policy on allowed_dir, nothing on denied_dir."""
    with Ruleset() as ruleset:
        ruleset.allow_path(
            allowed_dir, AccessFS.READ_FILE | AccessFS.READ_DIR | AccessFS.EXECUTE
        )
        ruleset.restrict()

    data = Path(allowed_dir, "ok.txt").read_text()
    check("read allowed file", data == "ok")

    try:
        Path(denied_dir, "secret.txt").read_text()
        check("read denied file", False, "no error raised")
    except PermissionError as exc:
        check("read denied file", exc.errno == errno.EACCES, str(exc))

    try:
        Path(allowed_dir, "new.txt").write_text("nope")
        check("write under allowed dir", False, "no error raised")
    except PermissionError as exc:
        check("write under allowed dir", exc.errno == errno.EACCES, str(exc))


def scenario_guards(denied_dir: str) -> None:
    """After a real restrict(), the ruleset refuses further mutation."""
    denied = Path(denied_dir, "secret.txt")
    with Ruleset() as ruleset:
        ruleset.restrict()
        try:
            ruleset.allow_path(denied_dir, AccessFS.READ_FILE)
            check("allow_path after restrict", False, "no error raised")
        except RuntimeError:
            pass
        try:
            ruleset.restrict()
            check("second restrict", False, "no error raised")
        except RuntimeError:
            pass

    try:
        denied.read_text()
        check("read under enforcement", False, "no error raised")
    except PermissionError as exc:
        check("read under enforcement", exc.errno == errno.EACCES, str(exc))


def scenario_nnp() -> None:
    """no_new_privs is set as part of restrict()."""
    fd = os.open("/proc/self/status", os.O_RDONLY)
    try:
        with Ruleset() as ruleset:
            ruleset.restrict()
        status = os.read(fd, 65536).decode()
    finally:
        os.close(fd)
    check(
        "no_new_privs",
        "NoNewPrivs:\t1" in status,
        "NoNewPrivs not set in /proc/self/status",
    )


def scenario_net(denied_port: int) -> None:
    """Only ephemeral TCP binds are granted. Fixed-port connect is denied."""
    with Ruleset() as ruleset:
        ruleset.allow_port(0, AccessNet.BIND_TCP)
        ruleset.restrict()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
    except OSError as exc:
        check("bind ephemeral port", False, str(exc))
    finally:
        sock.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex(("127.0.0.1", denied_port))
        check(
            "connect denied port",
            result == errno.EACCES,
            f"expected EACCES, got {result}",
        )
    finally:
        sock.close()


def scenario_udp(allowed_port: int, denied_port: int) -> None:
    """UDP sends are limited to the granted remote port."""
    with Ruleset() as ruleset:
        ruleset.allow_port(0, AccessNet.BIND_UDP)
        ruleset.allow_port(allowed_port, AccessNet.CONNECT_SEND_UDP)
        ruleset.restrict()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent = sock.sendto(b"x", ("127.0.0.1", allowed_port))
        check("udp send allowed port", sent == 1)
        try:
            sock.sendto(b"x", ("127.0.0.1", denied_port))
            check("udp send denied port", False, "no error raised")
        except OSError as exc:
            check("udp send denied port", exc.errno == errno.EACCES, str(exc))
    finally:
        sock.close()


def scenario_mute() -> None:
    """Subdomain log muting without a domain is accepted by the kernel."""
    mute_subdomain_logs()
    mute_subdomain_logs(all_threads=True)


def scenario_abstract() -> None:
    """Abstract UNIX sockets outside the domain refuse the connection."""
    with Ruleset(scoped=Scope.ABSTRACT_UNIX_SOCKET) as ruleset:
        ruleset.restrict()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect("\0landlockpy-test")
        check("abstract unix connect", False, "no error raised")
    except OSError as exc:
        check(
            "abstract unix connect",
            exc.errno in (errno.EPERM, errno.ECONNREFUSED),
            str(exc),
        )
    finally:
        sock.close()


def scenario_threads(denied_dir: str) -> None:
    """Without TSYNC, only the calling thread and its children are restricted.

    A sibling thread started before restrict() keeps its own policy. A
    thread started after restrict() inherits the domain and is denied.
    """
    denied = Path(denied_dir, "secret.txt")
    sibling_outcome: list[str] = []
    go = threading.Event()
    done = threading.Event()

    def sibling() -> None:
        go.wait(10)
        try:
            denied.read_text()
            sibling_outcome.append("allowed")
        except OSError as exc:
            sibling_outcome.append(str(exc.errno))
        finally:
            done.set()

    sibling_thread = threading.Thread(target=sibling)
    sibling_thread.start()

    with Ruleset() as ruleset:
        ruleset.restrict()

    child_outcome: list[str] = []

    def child() -> None:
        try:
            denied.read_text()
            child_outcome.append("allowed")
        except OSError as exc:
            child_outcome.append(str(exc.errno))

    go.set()
    done.wait(10)
    child_thread = threading.Thread(target=child)
    child_thread.start()
    child_thread.join(10)

    check(
        "sibling thread keeps its policy",
        sibling_outcome == ["allowed"],
        str(sibling_outcome),
    )
    check(
        "child thread inherits the domain",
        child_outcome == [str(errno.EACCES)],
        str(child_outcome),
    )


SCENARIOS: dict[str, Callable[[list[str]], None]] = {
    "fs": lambda a: scenario_fs(a[0], a[1]),
    "guards": lambda a: scenario_guards(a[0]),
    "nnp": lambda a: scenario_nnp(),
    "mute": lambda a: scenario_mute(),
    "net": lambda a: scenario_net(int(a[0])),
    "udp": lambda a: scenario_udp(int(a[0]), int(a[1])),
    "abstract": lambda a: scenario_abstract(),
    "threads": lambda a: scenario_threads(a[0]),
}


def main() -> int:
    name = sys.argv[1]
    run = SCENARIOS.get(name)
    if run is None:
        print(f"unknown scenario {name}", file=sys.stderr)
        return 2
    run(sys.argv[2:])

    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
