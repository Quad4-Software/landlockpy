# landlockpy

[![CI](https://github.com/Quad4-Software/landlockpy/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/landlockpy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/landlockpy/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/landlockpy/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/landlockpy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/landlockpy)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Dependency-free Python bindings for the Landlock Linux security module.
Landlock lets unprivileged processes sandbox themselves with filesystem,
network and IPC restrictions enforced by the kernel. Supports ABI versions
1 through 11 with best-effort degradation on older kernels.

Requires Python 3.10+ and Linux 5.13+ with Landlock enabled in the LSM list.

## Install

    pip install landlockpy

## Usage

```python
from landlockpy import AccessFS, AccessNet, Ruleset

with Ruleset() as ruleset:
    ruleset.allow_path(
        "/usr", AccessFS.READ_FILE | AccessFS.READ_DIR | AccessFS.EXECUTE
    )
    ruleset.allow_port(443, AccessNet.CONNECT_TCP)
    ruleset.restrict()

# everything not granted above is now denied for this thread and its children
```

`landlockpy.supported()` reports whether the running kernel has Landlock,
and `landlockpy.abi_version()` returns its ABI version.

## Documentation

- API: docstrings in `src/landlockpy/`, mostly `ruleset.py`
- Landlock API reference: https://docs.kernel.org/userspace-api/landlock.html
- Project site: https://landlock.io/

License: 0BSD.
