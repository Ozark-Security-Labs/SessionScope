# Design Decisions

This document records early design decisions that classifier and detector
issues can reference. Decisions are intentionally conservative: SessionScope
should present evidence clearly without overstating what static analysis can
prove.

## SS-DEC-001: Environment-Specific Cookie And JWT Settings

Environment-specific settings are represented as dynamic evidence unless the
production behavior is statically clear.

Rules:

- Literal, unconditional insecure settings may produce
  `high_confidence_misconfiguration`.
- Environment-conditioned or computed settings set `dynamic = true`, use lower
  confidence, and usually produce `dynamic_review_required`.
- If a production branch is statically clear, classifiers may evaluate that
  branch directly.
- If production behavior is not statically clear, reports should show the
  sanitized expression and ask a reviewer question.

Example dynamic cookie evidence:

```json
{
  "lifecycle_stage": "store",
  "detector_id": "cookie.attribute",
  "confidence": "medium",
  "excerpt": "secure: process.env.NODE_ENV === \"production\"",
  "dynamic": true,
  "framework_default": false
}
```

Example finding shape:

```json
{
  "category": "dynamic_review_required",
  "severity": "medium",
  "title": "Cookie Secure attribute depends on environment",
  "description": "The cookie appears to set Secure only when NODE_ENV is production.",
  "reviewer_question": "Can this deployment guarantee NODE_ENV is production for externally reachable environments?"
}
```

Example dynamic JWT validation evidence:

```json
{
  "lifecycle_stage": "validate",
  "detector_id": "jwt.verify.options",
  "confidence": "medium",
  "excerpt": "audience: config.auth.expectedAudience",
  "dynamic": true,
  "framework_default": false
}
```

## SS-DEC-002: Framework Defaults And Inferred Behavior

Framework defaults are evidence, not proof of application behavior, unless the
framework version and active configuration are deterministically known.

Rules:

- Default-derived evidence sets `framework_default = true`.
- Findings based primarily on defaults should use `framework_default_assumed`
  or `dynamic_review_required`.
- Default-derived evidence should not produce high-confidence findings unless
  local source/config proves the effective behavior.
- Reports should identify the framework and the assumption behind the default.

Example Express-style default assumption:

```json
{
  "lifecycle_stage": "store",
  "detector_id": "express.cookie.default",
  "confidence": "low",
  "excerpt": "cookie options omit sameSite; Express default assumed",
  "dynamic": false,
  "framework_default": true
}
```

Example Django/FastAPI-style default assumption:

```json
{
  "category": "framework_default_assumed",
  "severity": "low",
  "title": "Cookie setting depends on framework default",
  "description": "The local code does not set the attribute directly; behavior appears to depend on the framework default.",
  "reviewer_question": "Which framework version and deployment settings are active in production?"
}
```

## SS-DEC-003: Confidence Levels And Finding Categories

Confidence describes the strength of evidence, not impact.

Rules:

- `high`: direct local evidence with literal or structurally deterministic
  behavior.
- `medium`: strong pattern evidence with some config, environment, or framework
  indirection.
- `low`: heuristic, partial, or framework-default-dependent evidence.
- High-confidence findings require direct evidence of misconfiguration.
- Missing evidence generally becomes `dynamic_review_required` or another
  review-required finding unless detector coverage is complete enough to state
  the absence precisely.

Finding category guidance:

- Use `high_confidence_misconfiguration` for direct, deterministic unsafe
  settings.
- Use `missing_validation_evidence` when validation code is present but a
  specific check, such as issuer or audience, is not observed nearby.
- Use `lifecycle_gap` when evidence shows part of the lifecycle but no linked
  counterpart, such as refresh without rotation evidence.
- Use `dynamic_review_required` when behavior depends on runtime config,
  environment, or unresolved control flow.
- Use `framework_default_assumed` when the finding depends primarily on a
  framework default.

## SS-DEC-004: AuthMap-Style Authorization Evidence Alignment

SessionScope will not share an intermediate representation with AuthMap in
`v0.1.0`.

Rules:

- SessionScope owns its token lifecycle inventory schema for this milestone.
- The claims capability records JWT validation, identity-claim, and boundary evidence as source-bound inventory and reviewer questions; it is not a full authorization graph engine.
- The model should align conceptually with AuthMap-style evidence records:
  stable IDs, source locations, sanitized excerpts, confidence, and reviewer
  questions.
- Future AuthMap/rulepath interoperability should be designed as an explicit integration boundary rather than implied by claim inventory fields.
- Shared IR work should be revisited only when a concrete integration
  requirement exists.
- Detectors should keep token lifecycle evidence separate from authorization
  policy evidence until such an integration is designed.

## SS-DEC-005: Logout Cookie Clearing And Server-Side Revocation

Client-side cookie clearing is lifecycle evidence, but it is not proof that the
server-side session, refresh token, or provider token was revoked.

Rules:

- Detectors may emit `revoke` evidence for cookie deletion APIs such as
  Express `clearCookie`, Next.js `cookies().delete`, FastAPI
  `delete_cookie`, and Django `delete_cookie`.
- Cookie clear evidence uses `logout.cookie_clear` and should be treated as a
  browser-side action only.
- Server-side invalidation evidence should use more specific detector IDs such
  as `logout.session_destroy`, `logout.token_revoke`, or
  `logout.provider_revoke`.
- `logout.handler` identifies logout control flow, but it does not satisfy
  server-side revocation checks by itself.
- Lifecycle classifiers may ask a reviewer question when logout only clears a
  cookie and no linked server-side revocation evidence is present.
- Cookie deletion should use the same static `path` and `domain` attributes
  used when the cookie was set; mismatches or omitted set attributes are
  review-required lifecycle context.
- Provider and wrapper revocation calls are static-analysis context only; they
  should stay medium or low confidence unless local source proves the exact
  backend behavior.

## SS-DEC-006: Refresh-Token Rotation And Provider-Managed Behavior

Refresh-token rotation and reuse handling require server-side lifecycle
evidence. Seeing a refresh handler or provider SDK call is useful context, but
it is not proof that previous refresh tokens are invalidated.

Rules:

- Refresh handlers, token generation, storage, validation, expiry, rotation,
  reuse detection, and revocation should be emitted as lifecycle evidence when
  statically visible.
- Old-token invalidation, mark-used updates, denylist writes, token-family
  revocation, and provider revoke calls may satisfy server-side revocation
  checks when linked to the same refresh-token path.
- Refresh-token evidence is linked by bounded source context or explicit safe
  local keys, not by the common `refresh_token` display name alone.
- Provider-managed refresh behavior should be represented as dynamic review
  context unless local source proves the provider rotates or revokes previous
  refresh tokens.
- Clearing a refresh cookie remains client-side evidence only; it does not
  satisfy refresh-token rotation or revocation checks.

## SS-DEC-007: Session Fixation Signals Are Review-Required

Session fixation review depends on framework behavior, middleware ordering, and
the exact point where an authenticated or elevated identity is bound to a
session. Static evidence should identify likely transition points and visible
rotation, but it should not claim exploitability from missing local evidence
alone.

Rules:

- Login, sign-in, auth callback, impersonation, role elevation, admin
  promotion, and permission-change handlers may emit session transition
  evidence.
- Explicit session regeneration, session-key cycling, and clear-and-reissue
  cookie-session patterns may satisfy nearby transition review when linked by
  local source context.
- Recognized Django `login(request, user)`, `auth_login(request, user)`, and
  `request.session.cycle_key()` calls are acceptable framework/default
  regeneration evidence when visible in source.
- Missing regeneration near a login or privilege transition should produce a
  medium-severity `dynamic_review_required` finding with a reviewer question,
  not a high-confidence misconfiguration.
- Logout-only handlers and cookie deletion evidence should not create session
  fixation findings.

## SS-DEC-008: Trust-Boundary Reuse Is Review-Required

Token reuse across services, audiences, environments, or frontend/backend
boundaries depends on deployment configuration and provider policy. Static
source evidence should preserve boundary hints and ask targeted reviewer
questions when reuse is plausible, but it should not turn ambiguous reuse into a
definitive exploit finding.

Rules:

- Boundary evidence may include issuer, audience, service, environment, tenant,
  provider, scope, and frontend/backend trust-boundary hints when visible.
- JWT missing issuer or audience validation remains a JWT validation finding;
  trust-boundary reuse findings ask whether a token is reused outside its
  intended boundary.
- Inbound bearer/API-key evidence forwarded outbound without visible
  audience/service/scope evidence should be `dynamic_review_required`.
- Same token names spanning frontend/backend paths or multiple environment
  hints should be review-required unless source-bound evidence proves
  separation.
- Provider and wrapper-managed token handling should remain review-required
  unless local source or config shows the effective audience, service, tenant,
  and scope policy.

## SS-DEC-009: Expanded Cookie Posture Classification

Cookie posture findings should distinguish deterministic unsafe settings from
runtime policy questions.

Rules:

- Explicit cookie lifetime greater than 30 days is a high-confidence posture
  finding when Max-Age or a relative Expires duration is statically derivable.
- Absolute far-future Expires values are review-required unless the local source
  also exposes a derivable relative duration.
- Explicit broad Domain scope and explicit `Path=/` on session-like or signed
  cookies are high-confidence findings when the values are directly visible.
- `SameSite=None` without Secure remains high-confidence. `SameSite=None` with
  Secure is review-required because cross-site cookie delivery may be
  intentional.
- Dynamic cookie options and framework-default behavior should remain
  `dynamic_review_required` or `framework_default_assumed`.
- Browser storage of session-like tokens should reuse token storage evidence and
  must not introduce raw token or cookie values into reports.

## SS-DEC-010: CI Enforcement Is Explicit And Conservative

SessionScope reports should be useful before they become merge blockers.
Advisory mode remains the default for CLI and GitHub Action usage. Enforce mode
is opt-in and evaluates already-rendered findings after reports have been
written.

Rules:

- `mode = "advisory"` exits successfully when scanning and report writing
  succeed, even if findings are present.
- `mode = "enforce"` exits nonzero only for findings that match the configured
  policy.
- The default enforcement threshold is `high` severity across all categories.
  Teams can tighten to `medium`, `low`, or `info` after reviewing advisory
  output.
- Category filters use model JSON names, such as
  `high_confidence_misconfiguration` and `dynamic_review_required`.
- Exact finding IDs in `include_finding_ids` block even when they are present in
  a baseline. Exact IDs in `exclude_finding_ids` never block.
- Baseline support is read-only suppression of finding IDs from an existing
  JSON report with a top-level `findings` array. Full baseline creation and
  lifecycle management remain separate.
- Missing or malformed baseline files are configuration errors whenever a
  baseline is explicitly supplied.

## SS-DEC-011: v0.2 P1-P4 Check Category Consolidation

The v0.2 edge-case hardening checks fit the existing five finding categories.
No new finding category or SARIF rule ID is added in this round, and the scan
report schema remains `0.5.0`.

Explicit audit decisions:

- **P2.3 `jwt_alg_confusion_signal`:** no new
  `cryptographic_trust_violation` category. Literal mixed algorithm families
  remain `high_confidence_misconfiguration`; key-family ambiguity remains
  `dynamic_review_required`.
- **P2.4 JWT header-trust checks:** no new `cryptographic_trust_violation`
  category. Header-driven `jku`, `x5u`, and embedded-JWK trust remains
  `dynamic_review_required` because source evidence cannot prove live URL,
  certificate, JWKS, or provider allow-list behavior.
- **P3.1 OAuth artifact type:** keep the dedicated `oauth_auth_code_flow`
  artifact type. Reusing a token artifact would blur flow-construction evidence
  with issued-token lifecycle evidence.

Category mapping for new v0.2 checks:

| Check ID | Category mapping |
| --- | --- |
| `cookie_host_prefix_path_violation` | `high_confidence_misconfiguration` for literal violations; `dynamic_review_required` for dynamic Path evidence |
| `cookie_host_prefix_domain_violation` | `high_confidence_misconfiguration` for literal Domain evidence; `dynamic_review_required` for dynamic Domain evidence |
| `cookie_host_prefix_secure_violation` | `high_confidence_misconfiguration` for missing/false literal Secure; `dynamic_review_required` for dynamic/default Secure evidence |
| `cookie_secure_prefix_secure_violation` | `high_confidence_misconfiguration` for missing/false literal Secure; `dynamic_review_required` for dynamic/default Secure evidence |
| `cookie_samesite_none_without_secure` | `high_confidence_misconfiguration` |
| `cookie_samesite_none_dynamic_secure` | `dynamic_review_required` |
| `cookie_samesite_none_default_secure` | `framework_default_assumed` |
| `cookie_samesite_none_cross_site_review` | `dynamic_review_required` |
| `cookie_partitioned_review` | `dynamic_review_required` |
| `cookie_domain_leak_review` | `dynamic_review_required` |
| `cookie_conflicting_writes_review` | `dynamic_review_required` |
| `jwt_alg_none_accepted` | `high_confidence_misconfiguration` for literal `none`; `framework_default_assumed` for default-sensitive library behavior |
| `jwt_alg_confusion_signal` | `high_confidence_misconfiguration` for deterministic mixed algorithm families; `dynamic_review_required` for key-family ambiguity |
| `jwt_jku_header_trust` | `dynamic_review_required` |
| `jwt_x5u_header_trust` | `dynamic_review_required` |
| `jwt_embedded_jwk_trust` | `dynamic_review_required` |
| `jwt_nbf_missing` | `missing_validation_evidence` |
| `jwt_clock_skew_review` | `dynamic_review_required` |
| `jwt_kid_unvalidated_review` | `missing_validation_evidence` |
| `oauth_pkce_missing_review` | `dynamic_review_required` |
| `oauth_state_missing` | `missing_validation_evidence` |
| `oauth_state_static_review` | `dynamic_review_required` |
| `oauth_state_unverified_review` | `missing_validation_evidence` |
| `oidc_nonce_missing` | `missing_validation_evidence` |
| `oidc_nonce_unverified_review` | `missing_validation_evidence` |
| `oauth_redirect_uri_wildcard_review` | `dynamic_review_required` |
| `token_in_local_storage` | `high_confidence_misconfiguration` |
| `token_in_session_storage` | `high_confidence_misconfiguration` |
| `token_in_url_path_or_fragment` | `high_confidence_misconfiguration` |
| `client_secret_in_browser_code` | `dynamic_review_required` |
| `jwt_denylist_absent_on_logout_review` | `lifecycle_gap` |
| `refresh_family_revocation_absent_on_logout_review` | `lifecycle_gap` |
| `sliding_expiry_without_rotation_review` | `lifecycle_gap` |
| `password_change_global_revocation_absent_review` | `lifecycle_gap` |

Rules:

- Prefer existing category semantics over adding near-duplicate category names.
- Keep cryptographic trust evidence in the category that describes the static
  certainty: deterministic unsafe configuration, missing validation evidence, or
  dynamic review.
- Keep SARIF stable by mapping findings through the existing category rule IDs.
- Revisit a dedicated cryptographic-trust category only if future checks cannot
  be accurately expressed as deterministic misconfiguration, missing validation,
  lifecycle gap, dynamic review, or framework default evidence.
