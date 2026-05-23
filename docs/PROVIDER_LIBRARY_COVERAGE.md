# Provider And Library Coverage

SessionScope provider/library coverage for `#27` is evidence-bound and offline.
Detectors emit source-bound artifacts and lifecycle evidence for the shared
cookie posture, claims and validation, logout and revocation, and refresh
lifecycle capability areas. Classifiers decide whether evidence is a finding.
Provider-managed behavior is dynamic review context unless local source exposes
deterministic lifecycle actions.

For per-check truth across languages, frameworks, libraries, lifecycle stages,
categories, and SARIF rule IDs, see [COVERAGE_MATRIX.md](COVERAGE_MATRIX.md).

## Common rules

- Source analysis does not call identity providers, SDKs, discovery endpoints, or running applications.
- Evidence excerpts must be sanitized before reporting.
- Runtime tenant, issuer, audience, scope, callback, refresh, logout, and revocation behavior is dynamic unless the scanned source shows the effective value or call.
- Provider SDK calls may satisfy local lifecycle evidence for refresh or revoke stages, but they do not prove provider-side rotation, reuse detection, or policy configuration.
- Missing local evidence is not proof of absence unless the detector has deterministic source context for that claim.

## Auth.js / NextAuth

Supported patterns:

- `NextAuth(...)` and Auth.js/NextAuth option objects that expose provider configuration, session strategy, callback, refresh, or sign-out context.
- `jwt` and `session` callbacks that reference provider-managed token fields as dynamic lifecycle context.
- Source-visible provider issuer, audience, tenant, callback, and scope configuration as token-boundary evidence.
- Source-visible provider refresh and revoke/logout calls as lifecycle evidence.

Unsupported or dynamic patterns:

- Provider dashboard settings, hosted logout behavior, rotation policy, refresh-token reuse detection, and tenant policy not present in scanned source.
- Adapter/database session behavior delegated to packages with no local implementation.
- Framework or library defaults that vary by package version unless visible in local source/config.

## Passport Strategies

Supported patterns:

- Passport OAuth/OIDC strategy configuration with source-visible issuer, authorization/token URLs, callback URL, audience, and scope fields.
- Passport authenticate callbacks and route-local session/token handling as dynamic provider context.
- Source-visible refresh and provider revocation/logout calls.

Unsupported or dynamic patterns:

- Strategy internals, middleware ordering guarantees, and session-store semantics that are not visible in scanned files.
- Provider-side token rotation, revocation, and reuse policy.

## OAuth/OIDC Client Configuration

Supported patterns:

- OIDC client construction, issuer discovery references, callback handling, audience, scope, tenant, and redirect/callback configuration.
- Source-visible refresh and revoke calls on provider clients.
- Boundary evidence for issuer, audience, provider, tenant, scope, and callback context.

Unsupported or dynamic patterns:

- Live OIDC discovery metadata, JWKS state, provider dashboard configuration, and runtime-only client registration.
- Assertions that a provider validates issuer, audience, expiry, or signature unless local source exposes that validation call/configuration.

## OAuth/OIDC flow integrity

Supported P3 OAuth/OIDC checks are source-only and review-conservative:

- `passport-oauth2` / Express: strategy construction and callback-adjacent code can emit auth-code flow, state, PKCE, and redirect URI evidence. Provider-side redirect matching and PKCE enforcement remain review-required unless visible in source.
- `openid-client`: `authorizationUrl` / authorization URL construction can emit PKCE, state, nonce, scope, and redirect URI evidence. Live discovery and JWKS/provider metadata are not fetched.
- NextAuth/Auth.js: provider blocks and `checks` arrays can satisfy source-visible PKCE/state evidence; provider defaults are surfaced as review-required context rather than high-confidence failures.
- Authlib: `OAuth2Client`, `OAuth2Session`, and authorization URL construction can emit PKCE/state/nonce evidence for Python projects. Authlib JWT validation paths remain out of scope for the P2 JWT detector surface.
- Generic OAuth/OIDC code: crypto-near identifiers such as `state`, `nonce`, `code_verifier`, and `code_challenge` can provide flow evidence when they appear near auth-code construction.

SessionScope never contacts authorization servers, discovery endpoints, JWKS URLs, or provider dashboards, and it does not prove runtime client registration settings. OAuth `state`, OIDC `nonce`, and PKCE values are redacted from evidence and reports.

## Common Cloud Identity SDKs

Supported patterns:

- Source-visible Auth0, Okta, Cognito, Azure AD, Firebase, Supabase, and Clerk SDK calls that issue, refresh, revoke, sign out, or request scoped provider tokens.
- SDK configuration fields that expose safe issuer, audience, tenant, provider, service, environment, or scope boundaries.

Unsupported or dynamic patterns:

- Hosted provider policy, tenant settings, dashboard-only scopes, refresh-token rotation defaults, and revocation propagation semantics.
- Any live provider probing, token introspection, or credential collection.

## Verification expectations

Each supported provider/library pattern should have representative fixtures and
tests that assert artifacts, lifecycle evidence, provider hints, conservative
findings, and sanitized reports. Fixtures should use obvious placeholders only
and must not contain real credentials, tokens, private keys, bearer values,
cookie values, or customer code.
