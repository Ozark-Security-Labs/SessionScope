# SessionScope

SessionScope is a defensive product-security tool for auditing session, cookie, JWT, and token lifecycle behavior in application code.

It answers:

> How are authentication tokens issued, stored, validated, refreshed, revoked, and scoped?

SessionScope is intended for product-security teams and developers who need evidence-backed review of session management risks without attacking a live system.

## Problem

Session and token bugs are high-impact and common. Teams often rely on framework defaults, scattered middleware, or third-party libraries, but still accidentally introduce issues such as:

- cookies missing `HttpOnly`, `Secure`, or `SameSite`
- JWTs accepted without issuer or audience validation
- refresh tokens that are never rotated
- logout paths that do not revoke server-side state
- long-lived tokens without expiry enforcement
- tokens reused across trust boundaries
- API keys or bearer tokens stored in unsafe places
- password reset or email verification tokens without single-use semantics

Many checks can be reviewed statically by mapping token lifecycle paths and configuration evidence.

## Product thesis

Authentication security is not just "does login work?" It is a lifecycle problem.

SessionScope builds a map of token issuance, storage, validation, refresh, revocation, and expiry so reviewers can see lifecycle gaps clearly.

## Initial scope

SessionScope will start as a CLI and CI-friendly analyzer for common web application patterns.

Initial targets:

- Express session/cookie/JWT middleware
- Next.js auth/session patterns
- FastAPI auth dependencies
- Django sessions and signing utilities
- JWT libraries in TypeScript and Python
- Cookie-setting APIs

Initial outputs:

- Markdown lifecycle report
- JSON token-flow inventory
- SARIF findings for high-confidence issues
- GitHub Actions summary

## Example report shape

```text
Token: access_jwt
Issued at: src/auth/login.ts:44
Validation evidence:
  - jwt.verify(token, publicKey)
  - issuer check: present
  - audience check: missing
  - expiry check: library default
Storage evidence:
  - Authorization bearer token expected
Risk: review_required
Reviewer question:
  - Should this service enforce an audience claim?
```

```text
Cookie: session
Set at: app/auth/session.py:71
Attributes:
  - HttpOnly: present
  - Secure: missing
  - SameSite: lax
  - Max-Age: 30 days
Risk: high_confidence_misconfiguration
Suggested fix:
  - Set Secure in production cookie configuration.
```

## Core concepts

The versioned inventory and finding schema is documented in
[`docs/SCHEMA.md`](docs/SCHEMA.md).

### Lifecycle stages

SessionScope models auth artifacts through stages:

- issue
- store
- transmit
- validate
- refresh
- revoke
- expire
- introspect

### Token types

SessionScope should classify:

- session cookies
- signed cookies
- access JWTs
- refresh JWTs
- opaque bearer tokens
- API keys
- password-reset tokens
- email-verification tokens
- device/session records

### Evidence-bound findings

SessionScope should prefer precise statements:

- "No audience validation evidence detected near JWT verification."
- "This cookie-setting call does not set Secure."
- "Refresh token rotation evidence was not found."

It should avoid unsupported claims like "authentication bypass" unless proven by deterministic evidence.

## CLI sketch

```bash
sessionscope init
sessionscope scan --format markdown --output sessions.md
sessionscope scan --format json --output sessions.json
sessionscope explain FINDING_ID
sessionscope diff main...HEAD
sessionscope baseline create
```

## GitHub Action sketch

```yaml
name: SessionScope
on: [pull_request]

jobs:
  sessionscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bjcorder/SessionScope@v0
        with:
          mode: advisory
          output: markdown,sarif
```

## Potential checks

- Cookie missing `HttpOnly`
- Cookie missing `Secure`
- Unsafe `SameSite=None` without `Secure`
- JWT verification without issuer validation
- JWT verification without audience validation
- Tokens issued without explicit expiry
- Refresh tokens without rotation evidence
- Logout without revocation evidence
- Password reset tokens without expiry or single-use evidence
- Session fixation risk signals
- Token accepted from query parameters

## Non-goals

SessionScope is not intended to:

- exploit authentication systems
- brute-force tokens
- attack live applications
- steal or decode secrets
- replace manual security review

## Development

SessionScope is scaffolded as a Rust Cargo workspace using the Rust 2024
edition. Install the stable Rust toolchain from <https://rustup.rs/> before
running local checks.

The workspace is split into focused crates for the CLI, core scanner pipeline,
shared model, detectors, classifiers, reporters, and test helpers. The CLI
binary is named `sessionscope`.

Canonical local checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
cargo test --workspace --all-targets
```

Useful CLI commands while developing:

```bash
cargo run -p sessionscope-cli -- --help
cargo run -p sessionscope-cli -- version
cargo run -p sessionscope-cli -- scan --path . --format markdown
```

The scanner is defensive and offline-only. Do not add analyzer behavior that
prints token values, private keys, bearer strings, cookie values, or other
runtime secrets.

## Status

This repository contains the initial product documentation and Rust workspace
scaffold. The CLI, pipeline, detector, classifier, reporter, and test-helper
crates are present, with detector and classifier behavior to be implemented in
the next milestones.
