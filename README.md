# SessionScope

SessionScope is a defensive product-security tool for auditing session, cookie, JWT, and token lifecycle behavior in application code.

It answers:

> How are authentication tokens issued, stored, validated, refreshed, revoked, and scoped?

SessionScope is intended for product-security teams and developers who need evidence-backed review of session management risks without attacking a live system.

## Problem

Session and token bugs are high-impact and common. Teams often rely on framework defaults, scattered middleware, or third-party libraries, but still accidentally introduce issues such as:

- cookies missing `HttpOnly`, `Secure`, scoped lifetime, or `SameSite`
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

SessionScope is a CLI and CI-friendly analyzer for common web application patterns.

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

SessionScope classifies:

- session cookies
- signed cookies
- access JWTs
- refresh JWTs
- opaque bearer tokens
- API keys
- service tokens
- unknown token flows
- password-reset tokens
- email-verification tokens
- device/session records
- token scope and trust-boundary evidence

### Evidence-bound findings

SessionScope prefers precise statements:

- "No audience validation evidence detected near JWT verification."
- "This cookie-setting call does not set Secure."
- "Refresh token rotation evidence was not found."

It should avoid unsupported claims like "authentication bypass" unless proven by deterministic evidence.

## CLI sketch

```bash
sessionscope init
sessionscope scan --path . --format markdown --output sessions.md
sessionscope scan --path . --include "src/**/*.ts" --exclude "**/*.test.ts" --format json --output sessions.json
sessionscope scan --path . --max-file-size 1000000
sessionscope cookies --path . --format markdown
sessionscope claims --path . --format json
sessionscope logout --path . --format markdown
sessionscope refresh --path . --format json
sessionscope explain FINDING_ID --report sessions.json
sessionscope baseline create --from sessions.json --output sessionscope-baseline.json
sessionscope diff --baseline sessionscope-baseline.json --current sessions.json --format markdown
```

JSON reports are machine-readable inventories using the documented schema
version. A compact cookie audit excerpt looks like:

```json
{
  "schema_version": "0.5.0",
  "summary": {
    "files_discovered": 1,
    "files_scanned": 1,
    "files_skipped": 0,
    "diagnostics": []
  },
  "artifacts": [
    {
      "id": "artifact_...",
      "artifact_type": "session_cookie",
      "display_name": "session",
      "locations": [{ "path": "src/app.ts", "line": 12, "column": 3 }],
      "lifecycle_evidence": {
        "issue": [],
        "store": ["evidence_cookie_store"],
        "transmit": ["evidence_cookie_secure"],
        "validate": [],
        "refresh": [],
        "revoke": [],
        "expire": [],
        "introspect": []
      },
      "confidence": "high",
      "framework_hints": ["express"],
      "cookie_attributes": {
        "http_only": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_http_only"],
          "confidence": "high"
        },
        "secure": {
          "state": "present",
          "value": "true",
          "evidence_ids": ["evidence_cookie_secure"],
          "confidence": "high"
        },
        "same_site": {
          "state": "present",
          "value": "lax",
          "evidence_ids": ["evidence_cookie_same_site"],
          "confidence": "high"
        },
        "max_age": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_max_age"],
          "confidence": "high"
        },
        "expires": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_expires"],
          "confidence": "high"
        },
        "path": {
          "state": "framework_default",
          "value": "/",
          "evidence_ids": ["evidence_cookie_path"],
          "confidence": "low"
        },
        "domain": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_domain"],
          "confidence": "high"
        }
      }
    }
  ],
  "evidence": [
    {
      "id": "evidence_cookie_store",
      "lifecycle_stage": "store",
      "location": { "path": "src/app.ts", "line": 12, "column": 3 },
      "detector_id": "cookie.set",
      "confidence": "high",
      "excerpt": "response.cookie(\"session\", [REDACTED], ...)",
      "dynamic": false,
      "framework_default": false
    }
  ],
  "lifecycle_paths": [
    {
      "id": "lifecycle_path_...",
      "artifact_ids": ["artifact_..."],
      "stages": [
        {
          "stage": "store",
          "evidence_ids": ["evidence_cookie_store"]
        }
      ],
      "confidence": "high",
      "dynamic": false,
      "reviewer_question": null
    }
  ],
  "findings": [
    {
      "id": "finding_...",
      "category": "high_confidence_misconfiguration",
      "severity": "high",
      "artifact_ids": ["artifact_..."],
      "evidence_ids": ["evidence_cookie_http_only"],
      "title": "Session-like cookie `session` does not set HttpOnly",
      "description": "No HttpOnly attribute evidence was detected for this cookie-setting call.",
      "suggested_fix": "Set HttpOnly on session cookies so client-side scripts cannot read them.",
      "reviewer_question": "Is this cookie intended to be inaccessible to browser JavaScript?"
    }
  ],
  "files": []
}
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

## Configuration

Run `sessionscope init` to create a checked-in `sessionscope.toml` file. The
command is non-interactive, does not require network access, and refuses to
overwrite an existing config unless `--force` is passed.

Example initialized config:

```toml
# SessionScope configuration
# Generated by `sessionscope init`. Safe to check in.
# Do not put token values, private keys, bearer strings, cookie values, or
# environment-specific secrets in this file.

scan_paths = ["."]
include = ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.py", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.toml"]
exclude = ["**/*.test.ts", "**/*.spec.ts", "**/__tests__/**"]
formats = ["markdown"]
mode = "advisory"
max_file_size_bytes = 1000000
framework_hints = ["express", "nextjs", "fastapi", "django"]
provider_hints = []
```

Config precedence is:

1. CLI flags such as `--path`, `--include`, `--exclude`, `--format`, and
   `--max-file-size`
2. `sessionscope.toml`
3. Built-in defaults

`--include` replaces configured include patterns, while `--exclude` appends to
configured excludes. SessionScope also respects `.gitignore` where practical,
applies built-in dependency/vendor/build excludes, and skips sensitive paths
such as env files and private-key material before source loading.

## Potential checks

- Cookie missing `HttpOnly`
- Cookie missing `Secure`
- Unsafe or review-required cookie posture, including excessive lifetime, broad Domain/Path scope, and `SameSite=None` handling
- JWT verification without issuer validation
- JWT verification without audience validation
- Tokens issued without explicit expiry
- Refresh tokens without rotation evidence
- Logout without revocation evidence
- Password reset tokens without expiry or single-use evidence
- Session fixation risk signals
- Token accepted from query parameters
- Review-required token reuse across services, environments, or trust boundaries

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
cargo run -p sessionscope-cli -- scan --path . --include "src/**/*.ts" --exclude "**/*.test.ts" --max-file-size 1000000 --format json
```

The scanner is defensive and offline-only. Do not add analyzer behavior that
prints token values, private keys, bearer strings, cookie values, or other
runtime secrets.

## Redaction Trust Boundary

SessionScope treats source text and detector output as untrusted until it has
passed through `sessionscope-core::redaction`. Evidence excerpts and rendered
reports should keep source locations, finding IDs, lifecycle stages, claim
names, and attribute names, but token values, cookie values, bearer strings,
private keys, and high-entropy secret-like literals must be replaced with
`[REDACTED]`.

Redaction is a best-effort static safeguard, not a guarantee that arbitrary
source is secret-free. Stable IDs and source locations are preserved for
reviewability and must never be generated from runtime token values, private
keys, bearer strings, cookie values, or other secrets.

## Status

This repository contains the initial product documentation and Rust workspace
scaffold. The CLI, pipeline, detector, classifier, reporter, and test-helper
crates are present, with detector and classifier behavior to be implemented in
the next milestones.
