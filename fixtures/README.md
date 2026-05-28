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
- `PLACEHOLDER_API_KEY_DO_NOT_USE`
- `PLACEHOLDER_SERVICE_TOKEN_DO_NOT_USE`

## Capability Mapping

| Capability area | Representative fixture families/cases |
| --- | --- |
| Cookie posture | `express/cookie-session-lifecycle`, `express/cookie-posture-expanded`, `fastapi/cookie-posture-expanded`, `django/settings-session-auth`, `nextjs/nextresponse-session` |
| Claims and validation | `generic-ts/jwt-validation`, `generic-python/jwt-and-reset`, `fastapi/security-dependencies`, `django/settings-session-auth`, provider/OIDC fixtures with issuer/audience/scope evidence |
| Logout and revocation | `express/clear-cookie-only-logout`, `express/session-middleware`, `django/session-and-reset-flow`, `generic-ts/provider-revoke`, provider/library fixtures with revoke/sign-out calls |
| Refresh lifecycle | `express/refresh-rotation`, `express/refresh-without-rotation`, `generic-ts/refresh-reuse-detection`, `generic-ts/provider-refresh`, `django/password-change-refresh-revoke`, provider/library fixtures with refresh calls |

## Fixture Families

| Family | Case | Purpose |
| --- | --- | --- |
| `express/` | `cookie-session-lifecycle` | Express cookie attributes, refresh rotation signals, and logout/revocation evidence. |
| `express/` | `session-middleware` | Express `express-session` and `cookie-session` middleware configuration, login regeneration, refresh revocation, and logout/session destroy evidence. |
| `express/` | `cookie-posture-expanded` | Expanded cookie posture checks, Set-Cookie headers, dynamic options, and browser storage session signals. |
| `express/` | `clear-cookie-only-logout` | Logout path that only clears a client cookie and should produce a lifecycle review finding. |
| `express/` | `passport-oauth-strategy` | Passport OAuth strategy configuration, callback/session handling, provider refresh, and provider revocation evidence. |
| `express/` | `refresh-rotation` | Refresh-token handler with lookup, old-token invalidation, new-token storage, and expiry evidence. |
| `express/` | `refresh-without-rotation` | Refresh-token handler/use evidence without linked rotation or revocation evidence. |
| `express/` | `jwt-validation` | Express route handlers issuing/verifying `jsonwebtoken` JWTs, with a legacy verify that disables expiry enforcement and pins neither issuer nor audience, plus a decode-without-verify inspect route. |
| `nextjs/` | `route-handler-auth` | Next.js-style route handlers for cookies, JWT validation, refresh, and logout. |
| `nextjs/` | `authjs-nextauth-provider` | Auth.js/NextAuth provider configuration, JWT/session callbacks, provider-managed refresh, and logout revocation evidence. |
| `nextjs/` | `nextresponse-session` | Next.js `NextResponse` cookie storage/deletion, route-local JWT validation, refresh rotation, and logout revocation evidence. |
| `nextjs/` | `session-fixation-signals` | Next.js App Router login and privilege-transition session-fixation signals, clear-and-reissue suppression, and logout-only suppression. |
| `fastapi/` | `dependency-auth-lifecycle` | FastAPI dependency patterns for cookies, JWT claims, logout, and reset-token expiry. |
| `fastapi/` | `cookie-posture-expanded` | Expanded FastAPI cookie posture checks and Set-Cookie header parsing. |
| `fastapi/` | `security-dependencies` | FastAPI `Depends`, `Security`, `OAuth2PasswordBearer`, `APIKeyCookie`, response cookies, JWT validation, refresh revocation, and logout deletion. |
| `fastapi/` | `oauth-flow` | FastAPI router handlers running an Authlib `OAuth2Session` authorization-code flow with static state and a callback that reads state without visible verification. |
| `fastapi/` | `trust-boundary` | FastAPI-framed token reuse across inbound/outbound, frontend/backend, and cross-environment boundaries plus provider-managed token review. |
| `django/` | `session-and-reset-flow` | Django settings/views for secure cookies, session logout, signing, and reset-token expiry. |
| `django/` | `trust-boundary` | Django-framed token reuse across inbound/outbound, frontend/backend, and cross-environment boundaries plus provider-managed token review. |
| `django/` | `password-change-refresh-revoke` | Password-change-triggered refresh-token revocation evidence. |
| `django/` | `settings-session-auth` | Django session cookie settings, login/session cycling, signing utilities, JWT helpers, refresh revocation, and logout/session flush evidence. |
| `generic-ts/` | `jwt-validation` | Generic TypeScript JWT issue/verify cases for issuer, audience, expiry, and missing validation evidence. |
| `generic-ts/` | `refresh-reuse-detection` | Refresh-token reuse detection with token-family revocation evidence. |
| `generic-ts/` | `provider-refresh` | Provider-managed refresh behavior represented as dynamic review context. |
| `generic-ts/` | `provider-revoke` | Provider abstraction revocation evidence without live provider calls. |
| `generic-ts/` | `oidc-client-config` | OAuth/OIDC issuer, audience, scope, callback, refresh, and revocation configuration evidence. |
| `generic-ts/` | `cloud-identity-sdk` | Common cloud identity SDK token, refresh, scope, provider, and revoke/sign-out evidence (all seven SDKs together). |
| `generic-ts/` | `sdk-auth0` | Auth0 SDK client-credentials issue, refresh, and logout evidence (per-SDK breakdown of the combined cloud-identity fixture). |
| `generic-ts/` | `sdk-supabase` | Supabase Auth SDK session read, refresh, and sign-out evidence (per-SDK breakdown of the combined cloud-identity fixture). |
| `generic-ts/` | `bearer-api-key-lifecycle` | Generic TypeScript opaque bearer token, service token, and API-key lifecycle evidence. |
| `generic-ts/` | `trust-boundary-token-reuse` | TypeScript token scope, environment, frontend/backend, and trust-boundary reuse evidence. |
| `generic-python/` | `jwt-and-reset` | Generic Python/PyJWT-style issue/verify cases and reset-token lifecycle examples. |
| `generic-python/` | `bearer-api-key-lifecycle` | Generic Python opaque bearer token, service token, and API-key lifecycle evidence. |
| `generic-python/` | `trust-boundary-token-reuse` | Python token scope, environment, frontend/backend, and trust-boundary reuse evidence. |

The `generic-ts` family covers the generic JavaScript/TypeScript JWT fixture
space for now. Add narrower `generic-js` fixtures only if future detectors need
plain JavaScript-specific syntax coverage.
