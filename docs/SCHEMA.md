# SessionScope Schema

SessionScope uses the `sessionscope-model` crate as its internal inventory
model and JSON wire schema. The current schema version is `0.1.0`.

The schema is designed for defensive, offline source-code analysis. It must not
store token values, private keys, bearer strings, cookie values, or other
sensitive runtime data. Evidence excerpts must be sanitized before they enter
the model.

## Versioning

Serialized reports include:

```json
{
  "schema_version": "0.1.0"
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
locations, confidence, framework hints, and lifecycle evidence references.

Lifecycle evidence is grouped by stage:

- `issue`
- `store`
- `transmit`
- `validate`
- `refresh`
- `revoke`
- `expire`
- `introspect`

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
- findings

JSON report output serializes the full `ScanReport` model. Reporters should not
receive raw secret-bearing source snippets, and output formats should continue
escaping or formatting defensively.
