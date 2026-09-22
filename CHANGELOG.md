# Changelog

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
