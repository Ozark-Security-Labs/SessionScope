# Roadmap

SessionScope uses one milestone structure for its umbrella capability model:
cookie posture, claims and validation, logout and revocation, and refresh-token
lifecycle evidence. These capabilities share the same scanner, inventory,
redaction boundary, classifiers, and reporters; they are not separate public
products or duplicate version tracks.

## Phase 0: Repository foundation

- Product documentation
- Initial architecture notes
- Security policy
- Contribution guidelines

Capability impact: establishes the shared workspace, safety rules, and docs
surface used by all capability areas.

## Phase 1: Cookie audit MVP

- Detect common cookie-setting APIs
- Extract security attributes
- Report missing HttpOnly/Secure/SameSite evidence
- Markdown and JSON output

Capability impact: delivers the first cookie posture inventory and findings.

## Phase 2: JWT validation MVP

- Detect JWT issue and verify calls
- Classify issuer/audience/expiry evidence
- Report missing validation evidence

Capability impact: delivers the first claims and validation inventory, including
issuer, audience, expiry, signature verification, and the SessionScope-owned
identity-claim evidence subset.

## Phase 3: Lifecycle mapping

- Link issue/validate/refresh/revoke paths
- Detect logout/revocation gaps
- Detect reset-token lifecycle gaps

Capability impact: connects logout and refresh evidence into deterministic
lifecycle paths and review-required findings.

## Phase 4: CI integration

- GitHub Action wrapper
- SARIF output
- PR summary
- Advisory vs enforce mode

Capability impact: renders the shared inventory and findings for CI review
without changing the offline analysis boundary.

## Phase 5: Framework expansion

- Next.js framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Express framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- FastAPI framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Django framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Common auth libraries and providers are documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md), with incremental fixture-backed coverage for Auth.js/NextAuth, Passport strategies, OAuth/OIDC client configuration, and common cloud identity SDKs.

Capability impact: broadens source-visible framework and provider evidence for
cookies, claims, logout, and refresh while keeping findings evidence-bound.

## Current capability issue map

- Cookie posture: cookie detector/classifier work, expanded cookie posture fixtures, and framework cookie APIs.
- Claims and validation: #35 and JWT validation work, plus future AuthMap/rulepath interoperability where explicitly designed.
- Logout and revocation: #37 and lifecycle linking/classification in #17.
- Refresh lifecycle: #38 and lifecycle linking/classification in #17.
- Framework and provider coverage: #18 and #27 feed all four capability areas.
- Focused command aliases: #39 should expose capability-oriented entry points while preserving the shared scan/config/reporting pipeline.
