# Contributing

Report bugs through GitHub issues. Security reports go to
security@quad4.io (see SECURITY.md).

## Setup

    uv sync
    make check

`make check` runs the full local gate: ruff lint and format, bandit,
mypy strict, ty, and pytest with coverage.

## Conventions

- No runtime dependencies. The library is stdlib-only.
- Source files start with the SPDX license identifier.
- Public API changes need tests. Enforcement changes need a scenario in
  tests/_sandbox.py that runs against the real kernel.
- Commit messages: short, imperative, formal.
