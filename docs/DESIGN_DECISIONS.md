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
- The model should align conceptually with AuthMap-style evidence records:
  stable IDs, source locations, sanitized excerpts, confidence, and reviewer
  questions.
- Shared IR work should be revisited only when a concrete integration
  requirement exists.
- Detectors should keep token lifecycle evidence separate from authorization
  policy evidence until such an integration is designed.
