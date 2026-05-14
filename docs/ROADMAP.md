# Roadmap

## Phase 0: Repository foundation

- Product documentation
- Initial architecture notes
- Security policy
- Contribution guidelines

## Phase 1: Cookie audit MVP

- Detect common cookie-setting APIs
- Extract security attributes
- Report missing HttpOnly/Secure/SameSite evidence
- Markdown and JSON output

## Phase 2: JWT validation MVP

- Detect JWT issue and verify calls
- Classify issuer/audience/expiry evidence
- Report missing validation evidence

## Phase 3: Lifecycle mapping

- Link issue/validate/refresh/revoke paths
- Detect logout/revocation gaps
- Detect reset-token lifecycle gaps

## Phase 4: CI integration

- GitHub Action wrapper
- SARIF output
- PR summary
- Advisory vs enforce mode

## Phase 5: Framework expansion

- Next.js framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Express framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- FastAPI framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Django framework coverage matrix and fixtures are documented in [`FRAMEWORK_COVERAGE.md`](FRAMEWORK_COVERAGE.md).
- Common auth libraries and providers are documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md), with incremental fixture-backed coverage for Auth.js/NextAuth, Passport strategies, OAuth/OIDC client configuration, and common cloud identity SDKs.
