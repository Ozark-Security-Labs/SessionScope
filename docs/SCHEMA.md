# SessionScope Schema

SessionScope uses the `sessionscope-model` crate as its internal inventory
model and JSON wire schema. The current schema version is `0.4.0`.

Design decisions for dynamic evidence, framework defaults, confidence, and
AuthMap-style alignment are recorded in
[`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md).

The schema is designed for defensive, offline source-code analysis. It must not
store token values, private keys, bearer strings, cookie values, or other
sensitive runtime data. Evidence excerpts must be sanitized before they enter
the model.

## Versioning

Serialized reports include:

```json
{
  "schema_version": "0.4.0"
}
```

Schema changes should be intentional because JSON output, Markdown rendering,
SARIF, baselines, diffs, and explain flows depend on stable field meanings.

## Stable IDs

Artifacts, evidence, and findings use transparent string IDs:

- `artifact_<hex>`
- `evidence_<hex>`
- `finding_<hex>`

IDs are deterministic for unchanged normalized non-secret inputs. Suitable ID
inputs include detector IDs, artifact types, finding categories, normalized
paths, source line/column numbers, lifecycle stages, and already-sanitized local
keys. Do not include secrets or runtime token values in ID inputs.

## Artifacts

An artifact is the normalized auth object under review. Supported artifact
types are:

- `session_cookie`
- `signed_cookie`
- `access_jwt`
- `refresh_jwt`
- `opaque_bearer_token`
- `api_key`
- `password_reset_token`
- `email_verification_token`
- `session_record`
- `unknown`

Artifacts include a stable ID, type, optional safe display name, source
locations, confidence, framework hints, lifecycle evidence references, optional
cookie attributes for cookie artifacts, and optional JWT attributes for JWT
artifacts.

Lifecycle evidence is grouped by stage:

- `issue`
- `store`
- `transmit`
- `validate`
- `refresh`
- `revoke`
- `expire`
- `introspect`

## Lifecycle Paths

Lifecycle paths are classifier-linked views over artifact evidence. They do not
replace artifact-local lifecycle evidence; they make deterministic linked paths
explicit for reports and downstream tooling.

Each lifecycle path includes:

- stable lifecycle path ID: `lifecycle_path_<hex>`
- related artifact IDs
- ordered stage steps, each with a lifecycle stage and evidence IDs
- confidence: `low`, `medium`, or `high`
- dynamic flag
- optional reviewer question for dynamic or framework-default-dependent paths

Path IDs are derived only from non-secret facts such as artifact IDs, lifecycle
stages, evidence IDs, and normalized source locations. Paths link same-artifact
lifecycle evidence and may merge revoke-only evidence into an existing path
when static display names and compatible artifact types line up. Future
detectors may add refresh, reset-token, bearer/API-key, and provider evidence
without changing this shape.

Logout cookie deletion is represented as `revoke` lifecycle evidence, but
`logout.cookie_clear` only proves that browser-side state is cleared. It does
not satisfy server-side revocation checks for sessions, refresh tokens, or
provider tokens unless linked evidence such as `logout.session_destroy`,
`logout.token_revoke`, or `logout.provider_revoke` is also present.

Refresh-token detector evidence uses the existing lifecycle stages. Static
rotation or revocation evidence, such as marking the previous refresh token
used, deleting it, denylisting it, or revoking a token family, may satisfy the
server-side revoke stage when linked into the same refresh-token path.
Provider-managed refresh evidence is dynamic review context unless local source
also shows deterministic rotation or revocation behavior.

Cookie artifacts may include a `cookie_attributes` object with structured
observations for:

- `http_only`
- `secure`
- `same_site`
- `max_age`
- `expires`
- `path`
- `domain`

Each attribute observation includes:

- `state`: `present`, `missing`, `dynamic`, `framework_default`, or `unknown`
- optional sanitized `value`
- related `evidence_ids`
- `confidence`

Cookie attribute observations are evidence inventory, not findings. Dynamic or
framework-default values must not be treated as proof of insecurity until a
classifier evaluates them.

JWT artifacts may include a `jwt_attributes` object with structured
observations for:

- `operation`
- `algorithm`
- `key_reference`
- `issuer`
- `audience`
- `expiration`
- `signature_verification`
- `expiry_enforcement`
- optional `identity_claims`

Each JWT observation includes:

- `state`: `present`, `missing`, `dynamic`, `framework_default`, or
  `unknown`
- optional sanitized `value`
- related `evidence_ids`
- `confidence`

JWT attribute values must be safe static identifiers or redacted placeholders,
not token values, private keys, signing secrets, or runtime JWT contents.
`expiration` describes issued-token expiry evidence; `expiry_enforcement`
describes verification-time expiry behavior.

`identity_claims` is a nested object for the SessionScope-owned ClaimTrace
subset when statically visible in JWT issue payloads. It uses the same
observation shape as the top-level JWT attributes and may contain:

- `subject`
- `user_id`
- `tenant_id`
- `org_id`
- `workspace_id`
- `roles`
- `scopes`
- `groups`
- `email`
- `email_verified`
- `auth_method`
- `auth_class`

Identity-claim observations are trust-boundary inventory only. They indicate
that a JWT may carry a claim useful for downstream authorization review; they do
not mean the claim is trustworthy unless validation evidence also exists.
Literal identity claim values, including subjects, user IDs, tenant IDs, org
IDs, workspace IDs, roles, scopes, groups, email addresses, and auth method
strings, must be redacted or summarized as placeholders. Boolean
`email_verified` literals may be retained because they do not identify a
principal.

Example JWT attributes:

```json
{
  "issuer": {
    "state": "present",
    "value": "ISSUER",
    "evidence_ids": ["evidence_jwt_attribute_issuer"],
    "confidence": "high"
  },
  "audience": {
    "state": "present",
    "value": "AUDIENCE",
    "evidence_ids": ["evidence_jwt_attribute_audience"],
    "confidence": "high"
  },
  "expiration": {
    "state": "present",
    "value": "[literal]",
    "evidence_ids": ["evidence_jwt_attribute_expiration"],
    "confidence": "high"
  },
  "identity_claims": {
    "subject": {
      "state": "present",
      "value": "userId",
      "evidence_ids": ["evidence_jwt_attribute_subject"],
      "confidence": "high"
    },
    "tenant_id": {
      "state": "present",
      "value": "tenantId",
      "evidence_ids": ["evidence_jwt_attribute_tenant_id"],
      "confidence": "high"
    },
    "roles": {
      "state": "present",
      "value": "[literal]",
      "evidence_ids": ["evidence_jwt_attribute_roles"],
      "confidence": "high"
    }
  }
}
```

## Evidence

Evidence is a source-bound fact emitted by a detector. Evidence includes:

- stable evidence ID
- lifecycle stage
- source path, line, and column when available
- detector ID
- confidence: `low`, `medium`, or `high`
- optional sanitized excerpt
- dynamic and framework-default flags

Evidence excerpts are represented as sanitized strings only. They should provide
review context without preserving secret-bearing source values.

`sessionscope-core::redaction` is the canonical sanitizer for evidence excerpts.
It keeps useful structure such as claim names, cookie attribute names, source
locations, lifecycle stages, and IDs, while replacing secret-bearing values with
`[REDACTED]`. The sanitizer is best-effort and should be applied before evidence
enters inventory and again before report rendering as a defensive boundary.

## Findings

Findings are classifier-produced review items linked back to artifacts and
evidence. Finding categories are:

- `high_confidence_misconfiguration`
- `missing_validation_evidence`
- `lifecycle_gap`
- `dynamic_review_required`
- `framework_default_assumed`

Findings include stable finding IDs, severity, related artifact IDs, related
evidence IDs, evidence-bound title and description text, optional suggested
fixes, and optional reviewer questions.

Supported severities are `info`, `low`, `medium`, and `high`.

## Reports

A scan report contains:

- schema version
- scan summary
- per-file scan results
- merged artifacts
- merged evidence
- lifecycle paths
- findings

Skipped file reasons are serialized as non-sensitive categories: `binary`,
`too_large`, `unsupported`, `excluded`, `ignored`, `sensitive_path`, or
`read_error`.

JSON report output serializes the full `ScanReport` model. Reporters should not
receive raw secret-bearing source snippets, and output formats should continue
escaping or formatting defensively.

Reports must not rely on redaction to fix unsafe identifiers. Stable artifact,
evidence, and finding IDs should always be derived from non-secret facts rather
than token values, private keys, bearer strings, cookie values, or runtime
secrets.
