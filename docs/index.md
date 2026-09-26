# landlockpy

Dependency-free Python bindings for the Landlock Linux security module.
Landlock lets unprivileged processes sandbox themselves with filesystem,
network and IPC restrictions enforced by the kernel. landlockpy supports
ABI versions 1 through 11 with best-effort degradation on older kernels.

Requires Python 3.10+ and Linux 5.13+ with Landlock enabled in the LSM
list.

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

# everything not granted above is now denied for this thread and its
# children
```

`landlockpy.supported()` reports whether the running kernel has Landlock,
and `landlockpy.abi_version()` returns its ABI version. Enforcement is
irreversible and per-thread, so use `landlockpy.testing.probe()` to check
a policy in a forked child before applying it for real.

See the [API reference](api.md) for the full surface and the
[changelog](changelog.md) for release notes.

Kernel reference: https://docs.kernel.org/userspace-api/landlock.html
