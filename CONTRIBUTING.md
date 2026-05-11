# Contributing

This repository is early-stage and design-first. Contributions should preserve the core product-security boundary: defensive, authorized analysis of software you own or are permitted to assess.

## Useful contribution types

- Framework adapters
- Detection heuristics
- Documentation improvements
- False-positive reduction ideas
- Test fixtures for real-world application patterns
- Output/reporting improvements

## Ground rules

- Do not add exploit automation, payload generation, credential theft, bypass instructions, or live attack workflows.
- Prefer evidence-bound findings over unsupported vulnerability claims.
- Keep outputs actionable for application developers and product-security reviewers.
- Add fixtures for new detection behavior where practical.

## Development status

The current repository contains initial product documentation, architecture
notes, and a Rust Cargo workspace scaffold.

## Development setup

Install the stable Rust toolchain from <https://rustup.rs/>. The workspace uses
the Rust 2024 edition and builds the `sessionscope` CLI binary from
`crates/sessionscope-cli`.

Run the same checks locally that CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
cargo test --workspace --all-targets
```

Run the scaffolded CLI during development:

```bash
cargo run -p sessionscope-cli -- --help
cargo run -p sessionscope-cli -- version
cargo run -p sessionscope-cli -- scan --path . --format markdown
```

CLI commands may be placeholders while the project is early, but they should
remain deterministic, offline-only, and safe to run on source trees. Do not
print raw tokens, private keys, bearer strings, cookie values, or other secrets.
