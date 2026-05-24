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

- Cookie posture: cookie detector/classifier work, expanded cookie posture fixtures, framework cookie APIs, and closed expanded posture work in #36.
- Claims and validation: closed JWT schema and identity-claim inventory work in #35, plus future AuthMap/rulepath interoperability where explicitly designed.
- Logout and revocation: closed logout/revocation detector work in #37 and lifecycle linking/classification in #17.
- Refresh lifecycle: closed refresh-token lifecycle detector work in #38 and lifecycle linking/classification in #17.
- Framework and provider coverage: #18 and #27 feed all four capability areas, with umbrella capability documentation completed in #40.
- Focused command aliases: #39 exposes capability-oriented entry points while preserving the shared scan/config/reporting pipeline.
- Stable CLI release: #28 tracks release packaging, versioning, installation workflow, and final readiness; #41 tracks this folded capability model without creating duplicate v1.1-v1.4 milestone tracks.

## v0.2 edge-case hardening status

The v0.2 depth-first edge-case hardening round is complete across all four
phases:

- **P1 cookie prefix/attribute rules:** `__Host-` / `__Secure-`,
  `SameSite=None` + Secure, Partitioned cookie review, broad non-session
  Domain review, and conflicting same-handler cookie writes.
- **P2 JWT crypto-trust:** `alg:none`, algorithm-confusion signals,
  `jku`/`x5u`/embedded-JWK header-trust review, missing `nbf`, broad
  clock-skew review, and unvalidated `kid` review.
- **P3 OAuth/OIDC and client storage:** PKCE, `state`, OIDC `nonce`, wildcard
  redirect URI review, browser storage token findings, URL path/fragment token
  findings, browser-path client secret review, and OAuth redaction expansion.
- **P4 lifecycle and test hygiene:** JWT denylist-on-logout review,
  refresh-family revocation-on-logout review, sliding-expiry-without-rotation
  review, password-change global revocation review, clean-baseline
  false-positive fixtures, JSON report snapshots, CLI exit-code matrix tests,
  and the consolidated category audit.

The consolidated category decision keeps the existing five finding categories
and does not require a schema or SARIF rule bump.

## Deferred to v0.3+

New language and framework breadth is intentionally deferred. The next breadth
round may consider Flask, Tornado, Sanic, Starlette, NestJS, Koa, Fastify, Hapi,
Remix, Hono, SvelteKit, Go, Ruby/Rails, Java/Spring, .NET, PHP, python-jose,
authlib JWT validation paths, and deeper runtime/provider policy integration.
