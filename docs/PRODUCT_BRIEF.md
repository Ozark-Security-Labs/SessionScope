# Product Brief: SessionScope

## One-liner

Session, cookie, JWT, and token lifecycle auditing for product-security review.

## Target users

- Product-security engineers
- AppSec reviewers
- Authentication platform teams
- Developers maintaining login/session/token code

## Primary job to be done

When reviewing an application or pull request, show how auth artifacts move through their lifecycle and identify missing or weak lifecycle controls.

## Why now

Applications increasingly mix framework sessions, JWTs, refresh tokens, third-party auth providers, service tokens, and API keys. The lifecycle is distributed across code and config, making security review difficult.

## Differentiator

SessionScope focuses on lifecycle evidence rather than isolated lint rules. It maps where tokens are created, stored, validated, refreshed, revoked, and expired.

## MVP success criteria

- Detect cookie-setting calls in a representative app.
- Flag missing cookie security attributes with high confidence.
- Detect JWT verification calls and classify issuer/audience/expiry evidence.
- Produce Markdown and JSON reports.
- Run in GitHub Actions in advisory mode.

## Open design questions

- How should environment-specific cookie settings be represented?
- How should framework defaults be modeled without overstating findings?
- Should token lifecycle maps share an IR with AuthMap authorization evidence?
