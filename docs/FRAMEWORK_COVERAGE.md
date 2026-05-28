# Framework Coverage

SessionScope framework coverage for `#18` is evidence-bound and pattern-based. Detectors emit source-bound artifacts and evidence for the shared cookie posture, claims and validation, logout and revocation, and refresh lifecycle capability areas; classifiers decide whether the evidence is a finding. Unsupported or provider-managed behavior should be documented as a limitation rather than reported as a high-confidence issue.

For per-check truth across languages, frameworks, libraries, lifecycle stages, categories, and SARIF rule IDs, see [COVERAGE_MATRIX.md](COVERAGE_MATRIX.md).

## Common rules

- Source analysis is offline only and does not call running applications or providers.
- Evidence excerpts must be sanitized before reporting.
- Framework defaults are represented with `framework_default = true` and low confidence unless local source proves the effective value.
- Runtime configuration, provider-managed behavior, wrappers without visible implementation, and unresolved control flow are represented as dynamic review context.
- Missing local evidence is not proof of absence unless the detector has deterministic source context for that claim.

## Next.js

Supported patterns:

- App Router route handlers named `GET`, `POST`, `PATCH`, and `DELETE` when local source exposes auth, refresh, or logout behavior.
- `cookies().set(...)` and object-form `cookies().set({ name, value, ... })` cookie storage, including `__Host-` / `__Secure-` prefix evidence, `Partitioned` evidence, and same-handler conflicting-write review.
- `cookies().delete(...)` logout cookie deletion evidence.
- Clear-and-reissue session rotation at authentication or privilege transitions: a `cookies().set(...)` session write inside an authenticating route handler feeds the session-fixation checks (`session_fixation_login_regeneration_review` / `session_fixation_privilege_regeneration_review`), and a co-located `cookies().delete(...)` + `cookies().set(...)` reissue in the same handler suppresses the review.
- `NextResponse.cookies.set(...)` and `NextResponse.cookies.delete(...)` cookie storage and logout evidence, including prefix-rule and conflicting-write cookie hardening where source-visible.
- `Request` header bearer reads and route-local JWT verification through supported JWT libraries such as `jose`.
- Refresh route handlers that read, validate, rotate, store, expire, or revoke refresh-token evidence in local source.
- Auth.js/NextAuth OAuth/OIDC provider blocks for source-visible PKCE/state/nonce evidence and browser-client storage hygiene in `app/`, `pages/`, `src/components/`, and `public/` paths.
- `NEXT_PUBLIC_*` environment variable references and `publicRuntimeConfig` / `runtimeConfig` object keys that carry token-shaped values produce `bearer_public_runtime_config_exposure` evidence. `.tsx` files and paths under `/client/`, `/frontend/`, `/public/`, `/static/`, and `/browser/` also produce `bearer_frontend_bundle_exposure` evidence when token-shaped assignments are visible.

Unsupported or dynamic patterns:

- Auth.js/NextAuth provider-managed session, JWT, refresh, callback, and logout behavior beyond the source-visible patterns documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md).
- Edge middleware control flow that delegates to opaque helpers without visible cookie, JWT, bearer, session, or refresh operations.
- Framework version-specific defaults not visible in local source.

## Express

Supported patterns:

- `res.cookie(...)` cookie storage and security attributes, including `__Host-` / `__Secure-` prefix-rule checks, `Partitioned` evidence, broad non-session Domain review, and same-handler conflicting-write review.
- `res.clearCookie(...)` logout cookie deletion evidence.
- Static `Set-Cookie` header writes through representative response header APIs, including prefix and `Partitioned` attribute evidence.
- `express-session` middleware cookie configuration and default assumptions for omitted options.
- `cookie-session` middleware configuration and clear-and-reissue patterns.
- `req.session.regenerate(...)` session fixation rotation evidence.
- `req.session.destroy(...)` server-side logout/session revocation evidence.
- Session mutation near login, sign-in, auth callback, impersonation, or privilege elevation route handlers.
- Refresh routes that expose validate, rotate, store, expire, or revoke operations in local source.
- Passport OAuth2 strategy construction and callback-local state evidence for source-visible P3 OAuth flow checks.
- `jsonwebtoken` JWT issue/verify/decode posture in route handlers — missing issuer/audience evidence, disabled or default expiry enforcement, and decode-without-verify (see the `express/jwt-validation` fixture).
- Browser/client storage hygiene in source paths that match client-side heuristics.

Unsupported or dynamic patterns:

- Custom session stores whose invalidate/rotate semantics are not visible in local source.
- Passport or provider strategy behavior beyond the source-visible patterns documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md).
- Middleware ordering guarantees that cannot be inferred from the scanned files.

## FastAPI

Supported patterns:

- `Response.set_cookie(...)` and `Response.delete_cookie(...)` storage and logout evidence, including `__Host-` / `__Secure-` prefix-rule checks, broad non-session Domain review, and same-handler conflicting-write review. `Partitioned` is recognized when the runtime API exposes it as a source-visible option.
- `Cookie(...)` parameters used in auth dependencies.
- `Depends(...)` and `Security(...)` dependency functions where local source exposes cookie, bearer, JWT, session, refresh, or revocation behavior.
- `OAuth2PasswordBearer(...)` and `APIKeyCookie(...)` security utility declarations as transmit/validate context when linked to local dependency code.
- JWT encode/decode calls in dependencies and route handlers through supported Python JWT libraries.
- Logout handlers with cookie deletion and visible session/token revocation helpers.
- Refresh handlers with visible lookup, validation, rotation, storage, expiry, or revocation helpers.
- Authlib/generic OAuth2Session authorization URL construction for source-visible PKCE/state/nonce evidence, including static-state and callback-state-without-verification review (see the `fastapi/oauth-flow` fixture).
- Token trust-boundary review across inbound/outbound, frontend/backend, and cross-environment contexts plus provider-managed token review (see the `fastapi/trust-boundary` fixture).

Unsupported or dynamic patterns:

- External dependency injection containers and auth backends with no visible implementation.

- Provider-managed OAuth/OIDC behavior not represented in local source; supported source-visible patterns are documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md).
- Runtime-only OpenAPI/security configuration without source-visible cookie, bearer, JWT, or session handling.

## Django

Supported patterns:

- `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE`, and related static settings-derived cookie evidence.
- `login(...)` / `auth_login(...)` auth transition evidence and Django framework-default session key rotation context.
- `logout(...)`, `request.session.flush()`, and visible session/token revoke helpers.
- `request.session.cycle_key()` explicit session rotation evidence.
- `response.set_cookie(...)` runtime cookie evidence for prefix-rule checks, broad non-session Domain review, and same-handler conflicting-write review where source-visible. Runtime coverage is narrower than settings-derived `sessionid` coverage.
- `response.delete_cookie(...)` logout cookie deletion evidence.
- `django.core.signing.dumps(...)` and `signing.loads(...)` issue/validate context for signed token flows.
- `PASSWORD_RESET_TIMEOUT` and local reset-token issue/expiry helpers.
- JWT encode/decode wrappers in views or local auth helpers through supported Python JWT libraries.
- Token trust-boundary review across inbound/outbound, frontend/backend, and cross-environment contexts plus provider-managed token review (see the `django/trust-boundary` fixture).

Unsupported or dynamic patterns:

- Authentication backend internals that are not present in scanned source.
- Database/session engine behavior unless local source exposes concrete revocation or expiry operations.
- Provider-managed social-auth or OAuth behavior beyond source-visible lifecycle calls; provider/library coverage is documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md).
- Rolling TTL via `SESSION_COOKIE_AGE` in `settings.py` does **not** produce `sliding_expiry_without_rotation_review` evidence. The classifier requires source-visible session-config or helper code whose evidence excerpt contains rolling/sliding/idle terminology together with maxage/ttl/expires terms; `SESSION_COOKIE_AGE` alone does not satisfy this condition.
- python-jose and Authlib JWT validation are deferred and not covered by the JWT detector. Authlib OAuth **flow** construction (authorization URL, `OAuth2Session`, PKCE/state) IS covered via the generic-python path.
- Django OAuth/OIDC integrations such as django-allauth and python-social-auth are deferred and not covered in this release round.

## Generic JS/TS

Generic JS/TS coverage applies to any JavaScript or TypeScript source that is not matched by a more-specific framework hint. Most patterns are also active inside Express and Next.js handlers.

Supported patterns:

- **JWT libraries:** `jsonwebtoken` (`jwt.sign`, `jwt.verify`, `jwt.decode`) and `jose` (`jwtVerify`, `SignJWT`, `decodeJwt`) calls are recognized by import tracking. Algorithm, issuer, audience, expiry, clock tolerance, key reference, and `ignoreExpiration` options are extracted from source-visible arguments. `jose.jwtVerify` and `jsonwebtoken.verify` are modeled separately because their option shapes differ (e.g. `maxTokenAge` vs `maxAge`, `clockTolerance` vs `clockTimestamp`).
- **Bearer and API-key handling:** `Authorization: Bearer ...` header reads and writes, `api_key`/`x-api-key` parameter handling, token-context variable assignments, and URL query-string token acceptance produce issue, store, transmit, validate, expire, rotate, and revoke evidence when the call shapes match.
- **OAuth/OIDC client flow patterns:** `openid-client` authorization URL construction, generic `state`, `nonce`, `code_verifier`, and `code_challenge` identifiers near auth-code construction produce OAuth/OIDC flow evidence for PKCE/state/nonce checks. Provider-managed issuer, audience, tenant, scope, and callback context produces token-boundary observations.
- **Trust-boundary evidence:** Token context near `frontend`, `client`, `backend`, `server`, `public`, or `internal` identifiers, or in provider-named config objects (Auth0, Okta, Cognito, Azure AD, Firebase, Supabase, Clerk), produces trust-boundary and provider-boundary observations.
- **Refresh lifecycle:** Refresh-token issue, store, validate, rotate, revoke, and reuse-detection call shapes produce lifecycle evidence when source-visible.
- **Client-storage hygiene:** `localStorage.setItem`, `sessionStorage.setItem`, and `document.cookie = ...` writes with token-shaped keys produce `token_in_local_storage`, `token_in_session_storage`, and client-storage evidence. URL path or fragment token embedding produces `token_in_url_path_or_fragment` evidence.
- **Browser-client path heuristics:** The `client_secret_in_browser_code` check is limited to files whose path matches browser-client heuristics. A file path is considered browser-client when its normalized (lowercased, backslash-to-slash) form satisfies any of the following conditions: contains `/pages/`, `/app/`, `/src/components/`, `/components/`, or `/public/`; or starts with `pages/`, `app/`, `src/components/`, or `public/`. Note that `components/` (without a leading slash) is only matched as a mid-path substring (`/components/`), not as a leading segment. Path matching is case-insensitive.
- **Frontend-bundle exposure:** Paths containing `/client/`, `/frontend/`, `/public/`, `/static/`, or `/browser/`, as well as `.tsx` files, are treated as frontend-bundle context for `bearer_frontend_bundle_exposure` evidence.

Unsupported or dynamic patterns:

- JWT libraries not in the recognized set (`jsonwebtoken`, `jose`): python-jose, Authlib JWT, and other JS/TS JWT wrappers are not handled by the JS/TS JWT detector.
- Provider-managed OAuth/OIDC discovery, JWKS state, and runtime token rotation/revocation not visible in source.
- Opaque helper functions where the implementation is not present in the scanned files.

## Generic Python

Generic Python coverage applies to any Python source that is not matched by a more-specific framework hint. Most patterns are also active inside FastAPI and Django handlers.

Supported patterns:

- **JWT library:** `PyJWT` (`jwt.encode`, `jwt.decode`) calls are recognized by import tracking. Algorithm, issuer, audience, expiry, `options` dict (including `verify_exp`, `verify_signature`), and key reference are extracted from source-visible arguments.
- **Bearer and API-key handling:** `Authorization` header reads, `api_key` parameter handling, token-context variable assignments, and URL query-string token acceptance produce lifecycle evidence when the call shapes match.
- **OAuth/OIDC client flow patterns:** Authlib `OAuth2Client`, `OAuth2Session`, and authorization URL construction emit PKCE/state/nonce flow evidence. Generic `state`, `nonce`, `code_verifier`, and `code_challenge` identifiers near auth-code construction also produce flow evidence.
- **Trust-boundary evidence:** Token context near provider names (Auth0, Okta, Cognito, Azure AD, Firebase, Supabase, Clerk), environment identifiers, or service/internal/backend labels produces boundary observations.
- **Refresh lifecycle:** Refresh-token issue, store, validate, rotate, revoke, and reuse-detection call shapes produce lifecycle evidence when source-visible.
- **No client-storage detection:** `localStorage` and `sessionStorage` are browser-only JavaScript APIs. Python server code has no equivalent browser storage mechanism, so there is no Python client-storage detector and none is planned.

Unsupported or dynamic patterns:

- python-jose JWT validation and Authlib JWT validation are deferred and not handled by the Python JWT detector. Only PyJWT is recognized.
- Provider-managed OAuth/OIDC discovery, JWKS state, and runtime token rotation/revocation not visible in source.
- Django OAuth/OIDC integrations (django-allauth, python-social-auth) are deferred.
- Flask, Starlette, Sanic, and other Python web frameworks are deferred; only FastAPI and Django have framework-specific hints. Generic Python patterns still apply to those frameworks' source files.

## Verification expectations

Every supported framework family should have representative fixtures and tests that assert artifacts, lifecycle evidence, framework hints, conservative findings, and sanitized reports. Provider/library behavior is covered separately in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md), and limitation fixtures or assertions should ensure provider-managed or opaque behavior does not produce overconfident findings.
