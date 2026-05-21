# SessionScope Schema

SessionScope uses the `sessionscope-model` crate as its internal inventory
model and JSON wire schema. The current schema version is `0.5.0`.

Design decisions for dynamic evidence, framework defaults, confidence, and
AuthMap-style alignment are recorded in
[`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md).

The schema is designed for defensive, offline source-code analysis. It must not
store token values, private keys, bearer strings, cookie values, or other
sensitive runtime data. Evidence excerpts must be sanitized before they enter
the model. The same schema represents SessionScope's cookie posture, claims and
validation, logout and revocation, and refresh lifecycle capability areas; these
areas are report views over shared evidence, not separate wire formats.

## Versioning

Serialized reports include:

```json
{
  "schema_version": "0.5.0"
}
```

Schema changes should be intentional because JSON output, Markdown rendering,
SARIF, baselines, diffs, and explain flows depend on stable field meanings.

## Version policy

SessionScope publishes three independent SemVer contracts. Consumers should
pin whichever they actually depend on; they evolve on different cadences and
break independently. The canonical constants live in
[`crates/sessionscope-model/src/schema.rs`](../crates/sessionscope-model/src/schema.rs)
and [`crates/sessionscope-model/src/baseline.rs`](../crates/sessionscope-model/src/baseline.rs).

| Surface | Constant | Current | Governs |
| ------- | -------- | ------- | ------- |
| CLI release | `sessionscope` crate version (`Cargo.toml`) | `0.1.0` | CLI flags, command grammar, output paths, exit codes, `sessionscope.toml` keys, GitHub Action inputs |
| Scan report | `SCHEMA_VERSION` (`schema.rs`) | `0.5.0` | `ScanReport` JSON inventory and findings shape; SARIF and Markdown render this same model |
| Baseline | `BASELINE_SCHEMA_VERSION` (`baseline.rs`) | `0.1.0` | Baseline JSON wire format (`sessionscope baseline create` output) |
| Diff | `DIFF_SCHEMA_VERSION` (`baseline.rs`) | `0.1.0` | Diff JSON wire format (`sessionscope diff` output) |

Each contract evolves under its own SemVer rules:

- A breaking change to the CLI grammar bumps the CLI version regardless of
  whether the JSON schema changed.
- A breaking change to the JSON inventory bumps `SCHEMA_VERSION` regardless
  of whether the CLI grammar changed.
- Baseline and diff schemas bump independently from the report schema even
  though they reference fields from it; `baseline.report_schema_version`
  records the report schema a baseline was captured against.

For the full release-time compatibility policy (changelog discipline,
release-note requirements, GitHub Action stability), see
[`RELEASES.md`](RELEASES.md).

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
- `service_token`
- `unknown_token`
- `password_reset_token`
- `email_verification_token`
- `session_record`
- `unknown`

Artifacts include a stable ID, type, optional safe display name, source
locations, confidence, framework hints, lifecycle evidence references, optional
cookie attributes for cookie artifacts, optional JWT attributes for JWT
artifacts, and optional token boundary attributes for JWT, bearer, API-key, and
service-token artifacts.

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
lifecycle evidence and may merge revoke evidence into an existing path when
static display names or known session-cookie aliases, compatible artifact types,
and bounded source context line up. Refresh-token paths are linked only when
evidence is source-local to the same route/function-sized region; unrelated
`refresh_token` flows remain separate even when their display names match.

Logout cookie deletion is represented as `revoke` lifecycle evidence, but
`logout.cookie_clear` only proves that browser-side state is cleared. It does
not satisfy server-side revocation checks for sessions, refresh tokens, or
provider tokens unless linked evidence such as `logout.session_destroy`,
`logout.token_revoke`, or `logout.provider_revoke` is also present.
When a cookie is set with static `path` or `domain` attributes, linked
clear-cookie evidence is reviewed for matching deletion options. Broader
cross-route control-flow analysis for inconsistent logout paths is deferred
unless a deterministic same-cookie signal exists in the local source evidence.

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

Cookie evidence may come from framework cookie APIs or representative static
`Set-Cookie` header writes. Header-derived cookie values must be redacted before
entering evidence excerpts, IDs, or rendered reports. Expanded posture findings
use the same attribute inventory and do not add schema fields.

Bearer/API-key token artifacts are evidence inventory for opaque token flows.
`opaque_bearer_token`, `api_key`, `service_token`, and `unknown_token` use
artifact-local lifecycle evidence to represent static issue, store, transmit,
validate, expire, and revoke signals when visible. Dynamic provider-managed or
wrapper-heavy evidence must be represented as review-required context rather
than definitive unsafe behavior.

Token artifacts may include a `token_boundary_attributes` object when static
source evidence exposes issuer, audience, service, environment, tenant,
provider, scope, or trust-boundary context. Each observation includes:

- `state`: `present`, `missing`, `dynamic`, `framework_default`, or
  `unknown`
- optional sanitized `value`
- related `evidence_ids`
- `confidence`

Supported boundary observations are:

- `issuer`
- `audience`
- `service`
- `environment`
- `tenant`
- `provider`
- `scope`
- `trust_boundary`

Unknown boundary observations are omitted from JSON output, and an artifact
whose boundary inventory is entirely unknown omits `token_boundary_attributes`.
Missing fields deserialize as unknown observations so older compact reports
round-trip without changing schema version.

Boundary observations are conservative static hints for reuse analysis and
future provider adapters. They may be populated from JWT issuer/audience/claim
evidence, bearer/API-key config names, provider wrapper calls, service-token
names, environment-specific config references, or frontend/backend source
context. They must never contain runtime token values, bearer strings, private
keys, signing secrets, or raw JWT contents.

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
not mean the claim is trustworthy unless validation evidence also exists. They
also do not make SessionScope a full authorization graph engine; future
AuthMap/rulepath interoperability should consume sanitized evidence through an
explicit integration boundary. Literal identity claim values, including
subjects, user IDs, tenant IDs, org IDs, workspace IDs, roles, scopes, groups,
email addresses, and auth method strings, must be redacted or summarized as
placeholders. Boolean `email_verified` literals may be retained because they do
not identify a principal.

JWT issuer, audience, tenant, workspace, and scope observations may also be
mirrored into `token_boundary_attributes` so trust-boundary reuse findings can
reference the same evidence without changing JWT-specific validation findings.

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

Individual findings can be explained from a JSON report:

```bash
sessionscope explain FINDING_ID --report sessions.json
```

Explain output is a presentation view over existing report data. It should use
the finding text, linked evidence records, confidence, suggested fix, and
reviewer question without adding unsupported runtime impact claims.

## Reports

A scan report contains:

- schema version
- scan summary
- per-file scan results
- merged artifacts
- merged evidence
- lifecycle paths
- findings

Focused capability commands such as `sessionscope cookies`, `sessionscope
claims`, `sessionscope logout`, and `sessionscope refresh` serialize the same
report shape after filtering artifacts, evidence, lifecycle paths, and findings
to the requested capability area. They do not change the schema version.

Skipped file reasons are serialized as non-sensitive categories: `binary`,
`too_large`, `unsupported`, `excluded`, `ignored`, `sensitive_path`,
`read_error`, or `timeout`. `timeout` indicates that detectors collectively
exceeded the per-file CPU budget on that file; SessionScope records the
skip and continues with the rest of the scan.

The scan summary also includes `skipped_by_reason`, a map keyed by the
`SkippedReasonKind` variant tag (e.g. `{"too_large": 3, "timeout": 1}`). The
map is omitted from JSON when empty. `ScanReport::has_critical_failures()`
returns true when permission errors dominate the skipped files; CI
integrations can use it to surface a "scan was crippled" signal even when no
findings were produced.

JSON report output serializes the full `ScanReport` model. Reporters should not
receive raw secret-bearing source snippets, and output formats should continue
escaping or formatting defensively.

SARIF output is a rendered presentation format over the sanitized `ScanReport`.
It does not define additional model fields or change the persisted inventory
schema. SARIF `ruleId` values map one-to-one onto `FindingCategory`; the
canonical catalog and the `0.x` stability commitment for each ID live in
[`SARIF_RULES.md`](SARIF_RULES.md).

Reports must not rely on redaction to fix unsafe identifiers. Stable artifact,
evidence, and finding IDs should always be derived from non-secret facts rather
than token values, private keys, bearer strings, cookie values, or runtime
secrets.

## Baselines

Baseline files capture findings that a team has accepted for incremental
review. They are created from sanitized JSON scan reports:

```bash
sessionscope baseline create --from sessions.json --output sessionscope-baseline.json
```

The baseline schema is versioned independently from scan reports. Current
baseline files use `schema_version: "0.1.0"` and include the source
`report_schema_version`, deterministic finding entries, semantic fingerprints,
evidence fingerprints, related artifact/evidence IDs, and source locations.

Baselines are safe to store with project review artifacts when generated from
sanitized reports. They must not be edited to add token values, private keys,
bearer strings, cookie values, signing secrets, API keys, or raw JWT contents.

## Diffs

Diff reports compare a current JSON scan report against a baseline:

```bash
sessionscope diff --baseline sessionscope-baseline.json --current sessions.json --format json
sessionscope diff --baseline sessionscope-baseline.json --current sessions.json --format markdown
```

Diff output uses `schema_version: "0.1.0"` and groups findings into:

- `new`
- `unchanged`
- `changed`
- `moved`
- `resolved`

Comparison is deterministic and file-based. Findings match by stable finding ID
first, then by semantic and evidence fingerprints so source moves can be
reviewed without re-triaging unchanged finding content. Diff output is advisory
for CI workflows; it does not change process exit policy by itself.
