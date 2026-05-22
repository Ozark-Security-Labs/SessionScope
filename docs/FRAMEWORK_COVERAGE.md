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
- `NextResponse.cookies.set(...)` and `NextResponse.cookies.delete(...)` cookie storage and logout evidence, including prefix-rule and conflicting-write cookie hardening where source-visible.
- `Request` header bearer reads and route-local JWT verification through supported JWT libraries such as `jose`.
- Refresh route handlers that read, validate, rotate, store, expire, or revoke refresh-token evidence in local source.

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

Unsupported or dynamic patterns:

- Authentication backend internals that are not present in scanned source.
- Database/session engine behavior unless local source exposes concrete revocation or expiry operations.
- Provider-managed social-auth or OAuth behavior beyond source-visible lifecycle calls; provider/library coverage is documented in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md).

## Verification expectations

Every supported framework family should have representative fixtures and tests that assert artifacts, lifecycle evidence, framework hints, conservative findings, and sanitized reports. Provider/library behavior is covered separately in [`PROVIDER_LIBRARY_COVERAGE.md`](PROVIDER_LIBRARY_COVERAGE.md), and limitation fixtures or assertions should ensure provider-managed or opaque behavior does not produce overconfident findings.
