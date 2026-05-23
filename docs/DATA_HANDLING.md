# Data handling

SessionScope analyzes source you point it at and produces reviewable reports. This document describes the trust boundary between raw source and rendered output, and the guidance for handling reports once they exist.

## Redaction trust boundary

SessionScope treats source text and detector output as untrusted until it has passed through `sessionscope-core::redaction`. Evidence excerpts and rendered reports keep source locations, finding IDs, lifecycle stages, claim names, and attribute names — but **token values, cookie values, bearer strings, private keys, OAuth `state`, `nonce`, `code_verifier`, `code_challenge` values, and high-entropy secret-like literals are replaced with `[REDACTED]`** before they reach any reporter.

Stable IDs and source locations are preserved for reviewability. They must never be generated from runtime token values, private keys, bearer strings, cookie values, or other secrets.

Redaction is a best-effort static safeguard, not a guarantee that arbitrary source is secret-free. Treat scan output as you would treat the source it was derived from.

## What is preserved

Reports retain the information a reviewer needs:

- File path, line, and column.
- Stable artifact, evidence, lifecycle-path, and finding IDs.
- Lifecycle stage labels (`issue`, `store`, `transmit`, `validate`, `refresh`, `revoke`, `expire`, `introspect`).
- Detector IDs and confidence levels.
- Claim names, attribute names, and configuration keys.
- Framework hints and reviewer questions.

## What is removed

Before rendering:

- Token, cookie, and bearer **values**.
- OAuth/OIDC correlation and PKCE values named `state`, `nonce`, `code_verifier`, `code_challenge`, `codeVerifier`, or `codeChallenge`, including URL parameter values.
- Private-key material.
- High-entropy string literals that match secret-like patterns.
- Source excerpts have these spans replaced with `[REDACTED]`.

## Report sensitivity

Scan reports describe the structure of authentication code in your repository. Even fully redacted, they identify which files contain auth logic, where, and what controls are missing. Handle reports with the same care you would handle the source itself:

- Treat reports as **internal artifacts** unless your repository is public.
- Do not paste full reports into third-party tools without reviewing them first.
- When attaching a report to a bug or PR, prefer linking to a private artifact over inlining.
- SARIF uploads to GitHub code scanning are subject to your repository's visibility — scoped to repository contributors for private repos, public for public repos.

## Offline by design

SessionScope is offline-only. The CLI does not make network requests. There is no telemetry. Analysis runs entirely against local source.

If you find a code path that violates these properties, please report it via [SECURITY.md](../SECURITY.md).
