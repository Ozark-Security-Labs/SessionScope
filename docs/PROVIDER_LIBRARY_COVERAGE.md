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

## Auth0

**How SessionScope recognizes Auth0:** The normalized source text must contain the substring `auth0` (case-insensitive after symbol normalization). This is a shared-substring heuristic in `provider_hint_for_context()` (`sessions/mod.rs`) and the equivalent function in `bearer/mod.rs`; there is no Auth0-SDK-specific import tracking.

Supported patterns:

- Any call, assignment, or config object whose normalized text contains `auth0` together with a token/session/OAuth/OIDC context term (e.g. `callback`, `session`, `token`, `jwt`, `revoke`, `logout`, `scope`, `issuer`, `audience`, `clientid`) produces provider-hinted lifecycle evidence with `framework_hint = "auth0"`.
- Source-visible Auth0 config fields (`issuer`, `audience`, `clientId`, `tenant`, `scope`, `callbackUrl`) produce token-boundary observations.
- Auth0 logout/sign-out calls (`auth0.logout`, provider revoke context) produce `logout.provider_revoke` evidence.
- Auth0 refresh/token calls produce `refresh.provider` evidence (dynamic review context).

Unsupported or dynamic patterns:

- Auth0 dashboard settings, tenant policy, rotation configuration, RBAC/scopes policy, and any live provider behavior.
- Auth0 Management API calls, machine-to-machine token flows, and Actions/Rules are not specifically tracked.
- Auth0-SDK-specific import detection is not implemented; detection relies on the `auth0` substring appearing in the normalized source context.

## Okta

**How SessionScope recognizes Okta:** The normalized source text must contain the substring `okta`. Same shared-substring heuristic as Auth0.

Supported patterns:

- Calls and config objects whose normalized text contains `okta` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "okta"`.
- Source-visible Okta config fields (`issuer`, `audience`, `clientId`, `scope`, `callbackUrl`) produce token-boundary observations.
- Okta logout/sign-out calls produce `logout.provider_revoke` evidence.
- Okta refresh/token calls produce `refresh.provider` evidence (dynamic review context).

Unsupported or dynamic patterns:

- Okta Admin API, Okta Workflows, inline hooks, and device-flow patterns are not specifically tracked.
- Okta-SDK-specific import detection is not implemented; detection relies on the `okta` substring.

## Cognito

**How SessionScope recognizes Cognito:** The normalized source text must contain the substring `cognito`. Same shared-substring heuristic.

Supported patterns:

- Calls and config objects whose normalized text contains `cognito` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "cognito"`.
- Source-visible Cognito config fields (`userPool`, `clientId`, `region`, `scope`, `callbackUrl`) that appear with provider context produce token-boundary observations.
- Cognito logout/sign-out calls produce `logout.provider_revoke` evidence.
- Cognito refresh/token calls produce `refresh.provider` evidence (dynamic review context).

Unsupported or dynamic patterns:

- Cognito User Pool policy, hosted UI, Lambda triggers, and SAML federation are not specifically tracked.
- Cognito-SDK-specific import detection is not implemented; detection relies on the `cognito` substring.

## Azure AD

**How SessionScope recognizes Azure AD:** The normalized source text must contain either `azuread` or `azure_ad` (after symbol normalization, which removes hyphens and spaces). Same shared-substring heuristic.

Supported patterns:

- Calls and config objects whose normalized text contains `azuread` or `azure_ad` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "azure-ad"`.
- Source-visible Azure AD config fields (`tenantId`, `clientId`, `audience`, `issuer`, `scope`) that appear with provider context produce token-boundary observations.
- Azure AD logout/sign-out calls produce `logout.provider_revoke` evidence.
- Azure AD refresh/token calls produce `refresh.provider` evidence (dynamic review context).

Unsupported or dynamic patterns:

- Azure AD Conditional Access, app roles, claims-mapping policy, and managed identities are not specifically tracked.
- Note that `azure` alone (without `ad`) is NOT sufficient to trigger the Azure AD hint; the text must contain `azuread` or `azure_ad`. The token `azure` alone may appear in `bearer.boundary.issuer` terms but does not produce an `azure-ad` provider hint.
- Azure-MSAL-specific import detection is not implemented; detection relies on the `azuread`/`azure_ad` substrings.

## Firebase

**How SessionScope recognizes Firebase:** The normalized source text must contain the substring `firebase`. Same shared-substring heuristic.

Supported patterns:

- Calls and config objects whose normalized text contains `firebase` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "firebase"`.
- Source-visible Firebase config fields (`projectId`, `apiKey`, `authDomain`, `audience`) that appear with provider context produce token-boundary observations.
- Firebase logout/sign-out calls produce `logout.provider_revoke` evidence.
- Firebase refresh/token calls produce `refresh.provider` evidence (dynamic review context).

Unsupported or dynamic patterns:

- Firebase Security Rules, Realtime Database, Firestore, and Cloud Functions auth integrations are not specifically tracked.
- Firebase Admin SDK vs. Firebase Client SDK distinction is not detected; both rely on the `firebase` substring.

## Supabase

**How SessionScope recognizes Supabase:** The normalized source text must contain the substring `supabase`. Same shared-substring heuristic; additionally, `supabase.auth.signout` is recognized as a literal provider-revoke pattern.

Supported patterns:

- Calls and config objects whose normalized text contains `supabase` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "supabase"`.
- `supabase.auth.signout` is a recognized literal pattern that directly produces `logout.provider_revoke` evidence with the `supabase` hint.
- Source-visible Supabase config fields (`url`, `anonKey`, `serviceRoleKey` — key value redacted, `jwtSecret` reference) that appear with provider context produce token-boundary observations.
- Supabase refresh/token calls produce `refresh.provider` evidence (dynamic review context).
- Boundary provider evidence is produced when `supabase` appears in `bearer.boundary.provider` context terms.

Unsupported or dynamic patterns:

- Supabase Row Level Security, Edge Functions, and Realtime auth integrations are not specifically tracked.
- Supabase-specific import detection is not implemented beyond the `supabase` substring and the `supabase.auth.signout` literal pattern.

## Clerk

**How SessionScope recognizes Clerk:** The normalized source text must contain the substring `clerk`. Same shared-substring heuristic; additionally, `clerk.sessions.revoke` is recognized as a literal provider-revoke pattern.

Supported patterns:

- Calls and config objects whose normalized text contains `clerk` together with a token/session/OAuth/OIDC context term produce provider-hinted lifecycle evidence with `framework_hint = "clerk"`.
- `clerk.sessions.revoke` is a recognized literal pattern that directly produces `logout.provider_revoke` evidence with the `clerk` hint.
- Source-visible Clerk config fields (`publishableKey`, `secretKey` reference, `domain`, `audience`) that appear with provider context produce token-boundary observations.
- Clerk refresh/token calls produce `refresh.provider` evidence (dynamic review context).
- Boundary provider evidence is produced when `clerk` appears in `bearer.boundary.provider` context terms.

Unsupported or dynamic patterns:

- Clerk Organizations, multi-tenancy policy, session token rotation defaults, and webhook integrations are not specifically tracked.
- Clerk-SDK-specific import detection is not implemented beyond the `clerk` substring and the `clerk.sessions.revoke` literal pattern.

## Verification expectations

Each supported provider/library pattern should have representative fixtures and
tests that assert artifacts, lifecycle evidence, provider hints, conservative
findings, and sanitized reports. Fixtures should use obvious placeholders only
and must not contain real credentials, tokens, private keys, bearer values,
cookie values, or customer code.
