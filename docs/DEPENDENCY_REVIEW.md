# Third-Party Dependency Review Log

This file records security-relevant reviews of transitive Rust dependencies in the
SessionScope workspace. Each entry includes the date the review was performed, the
crate version and checksum that was actually inspected, who/what publishes the crate,
and the conclusion that led us to either keep the dependency or pin it.

The intent is to make supply-chain decisions auditable: if a future advisory
references one of these crates, reviewers can compare the previously-recorded
state against the new evidence.

---

## `zmij` 1.0.21 (pulled in by `serde_json` 1.0.149)

| Field | Value |
| --- | --- |
| Reviewed | 2026-05-20 |
| Reviewer | SessionScope v0.1.0 pre-release remediation (Phase 2, finding F-08) |
| Crate | `zmij` |
| Version | `1.0.21` |
| crates.io checksum (SHA-256) | `b8848ee67ecc8aedbaf3e4122217aff892639231befc6a1b58d29fff4c2cabaa` |
| Source repository | https://github.com/dtolnay/zmij |
| Publisher | David Tolnay (`dtolnay@gmail.com`) — also publishes `serde`, `serde_json`, `syn`, `quote`, `anyhow`, `thiserror` |
| License | MIT |
| Pulled in by | `serde_json` 1.0.149 (also published by David Tolnay) |
| Pulled in via | `Cargo.toml` line `zmij = "1.0"` in `serde_json` 1.0.149's manifest |

### Why we looked at this

`serde_json` historically had no `zmij` dependency. Adding a transitive crate
with an unfamiliar name to the JSON path of a security tool warrants a manual
review before a public release.

### What `zmij` does

`zmij` is a pure-Rust port of Schubfach / Victor Zverovich's "Żmij" double-to-
decimal-string conversion algorithm (https://github.com/vitaut/zmij). It
replaces or supplements the prior `ryu`-style code path inside `serde_json`'s
floating-point formatter. The crate is `no_std`-friendly, declared in
categories `value-formatting`, `no-std`, `no-std::no-alloc`.

### Inspection notes

The cached source under
`~/.cargo/registry/src/index.crates.io-*/zmij-1.0.21/` was inspected directly:

- `Cargo.toml`: declares one optional dependency (`no-panic`) and a few
  dev-dependencies (`criterion`, `num-bigint`, `num_cpus`, `num-integer`,
  `rand`, `ryu`). No runtime network or filesystem deps.
- `build.rs`: only runs `rustc --version` to set conditional `cfg` flags for
  older toolchains (the same pattern dtolnay uses across `serde`, `syn`, etc.).
  No downloads, no codegen of opaque blobs, no environment exfiltration.
- `src/lib.rs`, `src/stdarch_x86.rs`, `src/hint.rs`, `src/traits.rs`: contain
  the float-formatting algorithm with `unsafe` blocks limited to indexing
  pre-computed lookup tables and SIMD intrinsics (`_mm_load_si128`, etc.).
  No `std::net`, `std::process::Command`, `std::fs::File`, `spawn`, `fork`, or
  network/HTTP client usage anywhere in `src/`.
- `tests/`: numeric regression tests only.

### `serde_json` 1.0.149 manifest confirms the dependency

The cached `serde_json-1.0.149/Cargo.toml.orig` lists `zmij = "1.0"` as a
required dependency in the `[dependencies]` section, alongside `itoa`,
`memchr`, `indexmap` (optional), and `serde_core`. This matches what
`Cargo.lock` resolves and matches what `cargo tree --invert -p zmij` shows:
the only path to `zmij` in this workspace is via `serde_json` (plus a
transitive path through `tree-sitter`'s build-dependencies, which itself uses
`serde_json`).

### Conclusion

`zmij` 1.0.21 is a legitimate float-formatting helper crate maintained by the
same author as `serde_json` itself. The dependency is intentional and
traceable to a published upstream repository. No pinning is required for
v0.1.0.

If a future advisory targets `zmij` directly, revisit this decision and
consider pinning `serde_json` to a pre-`zmij` release.
