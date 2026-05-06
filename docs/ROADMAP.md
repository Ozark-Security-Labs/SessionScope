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

- Next.js
- Express
- FastAPI
- Django
- Common auth libraries and providers
