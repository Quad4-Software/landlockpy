# Changelog

## 0.1.1 - 2026-09-22

- Add landlockpy.testing with probe() and probe_path() for running a
  callable under a ruleset in a forked child without enforcing it in
  the caller.
- Ruleset: add __repr__, reject copy/deepcopy, raise ValueError from
  fileno() when closed, raise RuntimeError when entering a closed
  ruleset.
- Fix quiet rule flag on allow_path() and allow_port(): dropped in
  best-effort mode and rejected in strict mode on kernels below ABI 10.
- Declare explicit ctypes layout on the packed path_beneath struct;
  the implicit default is deprecated since Python 3.14.

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
