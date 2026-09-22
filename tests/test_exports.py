# SPDX-License-Identifier: 0BSD

import landlockpy


def test_all_exports_resolve() -> None:
    for name in landlockpy.__all__:
        assert getattr(landlockpy, name) is not None, name


def test_version_is_exposed() -> None:
    parts = landlockpy.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
    assert "testing" in landlockpy.__all__
