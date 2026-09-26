# Changelog

## Unreleased

- Docs now build with Zensical instead of mkdocs-material. The site
  gains a light/dark/system palette toggle and the modern theme
  variant.

## 0.2.0 - 2026-09-26

- Add landlockpy.mute_subdomain_logs() wrapping the
  landlock_restrict_self(-1) call that suppresses audit logging for
  nested domains without creating a new one.
- probe() now reports non-OSError child exceptions through
  ProbeResult.exception instead of a synthetic errno 255.
- restrict() rejects flags the kernel does not support with
  UnsupportedError in strict mode (best_effort=False) instead of
  silently dropping them.
- Ruleset now rejects pickling. The ruleset fd is closed if
  initialization fails partway, and close() marks the ruleset closed
  before releasing the descriptor.
- allow_port() rejects non-integer ports with TypeError via
  operator.index.
- abi_version(), errata() and supported() now report 0/False on
  non-Linux platforms instead of raising UnsupportedError.
- Document the ctypes layout of all three kernel structs explicitly.
- Build API documentation with mkdocs-material and mkdocstrings
  (make docs, enforced in CI). Pushes to master publish it to GitHub
  Pages at https://quad4-software.github.io/landlockpy/

## 0.1.1 - 2026-09-22

- Add landlockpy.testing with probe() and probe_path() for running a
  callable under a ruleset in a forked child without enforcing it in
  the caller.
- Ruleset: add __repr__, reject copy/deepcopy, raise ValueError from
  fileno() when closed, raise RuntimeError when entering a closed
  ruleset.
- Fix quiet rule flag on allow_path() and allow_port(): dropped in
  best-effort mode and rejected in strict mode on kernels below ABI 10.
- Declare explicit ctypes layout on the packed path_beneath struct.
  The implicit default is deprecated since Python 3.14.

## 0.1.0 - 2026-09-22

Initial release.

- Ruleset construction with handled filesystem, network and scope rights.
- Path-hierarchy rules and TCP/UDP port rules, including quiet rules (ABI 10).
- Scoped domains for abstract UNIX sockets and signals (ABI 6).
- Restrict flags covering audit logging, TSYNC and atomic no_new_privs
  (ABI 11, prctl fallback on older kernels).
- Best-effort masking to the running kernel, strict mode via
  best_effort=False.
- Kernel probes: abi_version(), errata(), supported(), and the for_abi
  helpers for computing which rights a given ABI supports.
