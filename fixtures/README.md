# Fixtures

Synthetic fixtures for detector and classifier tests live here. Fixtures use
obvious placeholders only and must not contain real credentials, tokens,
customer code, or production configuration.

Each fixture case contains an `expected.json` file. These expectation files are
test metadata for future detectors; they are not public report output and do
not replace `docs/SCHEMA.md`.

Placeholder values intentionally look fake:

- `PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE`
- `PLACEHOLDER_SECRET_DO_NOT_USE`
- `PLACEHOLDER_RESET_TOKEN`

## Fixture Families

| Family | Case | Purpose |
| --- | --- | --- |
| `express/` | `cookie-session-lifecycle` | Express cookie attributes, refresh rotation signals, and logout/revocation evidence. |
| `express/` | `refresh-rotation` | Refresh-token handler with lookup, old-token invalidation, new-token storage, and expiry evidence. |
| `express/` | `refresh-without-rotation` | Refresh-token handler/use evidence without linked rotation or revocation evidence. |
| `nextjs/` | `route-handler-auth` | Next.js-style route handlers for cookies, JWT validation, refresh, and logout. |
| `fastapi/` | `dependency-auth-lifecycle` | FastAPI dependency patterns for cookies, JWT claims, logout, and reset-token expiry. |
| `django/` | `session-and-reset-flow` | Django settings/views for secure cookies, session logout, signing, and reset-token expiry. |
| `django/` | `password-change-refresh-revoke` | Password-change-triggered refresh-token revocation evidence. |
| `generic-ts/` | `jwt-validation` | Generic TypeScript JWT issue/verify cases for issuer, audience, expiry, and missing validation evidence. |
| `generic-ts/` | `refresh-reuse-detection` | Refresh-token reuse detection with token-family revocation evidence. |
| `generic-ts/` | `provider-refresh` | Provider-managed refresh behavior represented as dynamic review context. |
| `generic-python/` | `jwt-and-reset` | Generic Python/PyJWT-style issue/verify cases and reset-token lifecycle examples. |

The `generic-ts` family covers the generic JavaScript/TypeScript JWT fixture
space for now. Add narrower `generic-js` fixtures only if future detectors need
plain JavaScript-specific syntax coverage.
