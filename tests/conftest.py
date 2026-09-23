# SPDX-License-Identifier: 0BSD

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

import landlockpy

ROOT = Path(__file__).resolve().parent.parent
HELPER = Path(__file__).resolve().parent / "_sandbox.py"

Sandbox = Callable[..., "subprocess.CompletedProcess[str]"]

requires_landlock = pytest.mark.skipif(
    landlockpy.abi_version() < 1 and os.environ.get("Q4_REQUIRE_LIVE") != "1",
    reason="kernel does not support Landlock",
)


@pytest.fixture
def sandbox() -> Sandbox:
    """Run a scenario in _sandbox.py under a fresh Python process."""

    def run(scenario: str, *args: object) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        return subprocess.run(
            [sys.executable, str(HELPER), scenario, *(str(a) for a in args)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    return run
