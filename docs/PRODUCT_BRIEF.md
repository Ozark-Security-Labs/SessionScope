# Product Brief: SessionScope

## One-liner

Session, cookie, JWT, and token lifecycle auditing for product-security review.

SessionScope is the umbrella product model for four capability areas: cookie posture, claim and validation evidence, logout and revocation evidence, and refresh-token lifecycle evidence. Earlier working names such as CookieJarvis, the SessionScope-owned ClaimTrace subset, LogoutLab, and RefreshRaptor are folded into SessionScope rather than tracked as separate public products.

## Target users

- Product-security engineers
- AppSec reviewers
- Authentication platform teams
- Developers maintaining login/session/token code

## Primary job to be done

When reviewing an application or pull request, show how auth artifacts move through their lifecycle and identify missing or weak lifecycle controls across cookies, claims, logout, and refresh behavior.

## Why now

Applications increasingly mix framework sessions, JWTs, refresh tokens, third-party auth providers, service tokens, and API keys. The lifecycle is distributed across code and config, making security review difficult.

## Differentiator

SessionScope focuses on lifecycle evidence rather than isolated lint rules or separate point products. It maps where tokens are created, stored, validated, refreshed, revoked, and expired, then reports evidence-bound review questions for the relevant capability area.

## MVP success criteria

- Detect cookie-setting calls in a representative app.
- Flag missing cookie security attributes with high confidence.
- Detect JWT verification calls and classify issuer/audience/expiry evidence.
- Produce Markdown and JSON reports.
- Run in GitHub Actions in advisory mode.

## Capability boundaries

SessionScope is offline source analysis. It does not perform live exploitation, brute forcing, token theft, secret collection, provider probing, full authorization graph analysis, or general SAST sprawl. Claims and authorization reasoning should remain evidence inventory and review questions, with future AuthMap/rulepath interoperability considered only for clearly designed integrations.

## Open design questions

These questions are resolved for `v0.1.0` in
[`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md):

- How should environment-specific cookie settings be represented? See
  `SS-DEC-001`.
- How should framework defaults be modeled without overstating findings? See
  `SS-DEC-002`.
- How should confidence levels and review-required findings be assigned? See
  `SS-DEC-003`.
- Should token lifecycle maps share an IR with AuthMap authorization evidence?
  See `SS-DEC-004`.
