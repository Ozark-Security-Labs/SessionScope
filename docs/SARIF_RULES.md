# SARIF rule IDs

SessionScope emits SARIF 2.1.0 output that GitHub Code Scanning, GitLab,
and other SARIF consumers can ingest. Each SessionScope finding carries
a `ruleId` that maps one-to-one to a `FindingCategory` defined in
[`crates/sessionscope-model/src/finding.rs`](../crates/sessionscope-model/src/finding.rs).
The SARIF reporter that emits these IDs lives in
[`crates/sessionscope-reporters/src/sarif.rs`](../crates/sessionscope-reporters/src/sarif.rs).

This document enumerates each rule ID, its descriptions, and the
project's stability commitment for downstream consumers that pin to
SessionScope rule IDs (for example, code-scanning suppressions or alert
routing rules).

## Stability commitment

For the entire `0.x` release line, SessionScope will not:

- rename any rule ID listed below;
- change the meaning of an existing rule ID such that an existing
  consumer suppression would silently start matching a different
  finding kind; or
- remove an existing rule ID without first deprecating it in a release
  note.

New SessionScope finding categories may be added as new rule IDs in
minor releases (`0.MINOR.0`). New rule IDs are non-breaking for
existing consumers because suppressions and alert rules pinned to the
previous IDs continue to behave the same.

The `0.x` series is the pre-1.0 stabilization window for SessionScope.
The next breaking opportunity for rule IDs is `1.0.0`, and any such
change will be called out in `CHANGELOG.md` and `docs/RELEASES.md`.

Rule IDs are also persisted in finding `partialFingerprints` via the
`sessionscopeFindingId` field, so deduplication and triage state in
SARIF consumers remain stable across rule-ID-preserving releases.

## Rule catalog

Each rule ID below matches the SARIF `runs[].tool.driver.rules[].id`
emitted by the SARIF reporter, the `runs[].results[].ruleId` on each
finding, and the `category` field in the JSON report (see
[`SCHEMA.md`](SCHEMA.md)). The `security-severity` column maps to the
GitHub Code Scanning severity band that SessionScope applies; absent
values render as `note` severity without a security-severity claim.

### `high_confidence_misconfiguration`

- **Name:** High-confidence session or token misconfiguration
- **Short description:** Deterministic session or token misconfiguration evidence.
- **Full description:** SessionScope found direct source evidence of an
  unsafe session, cookie, JWT, or token lifecycle setting.
- **SARIF level:** `error` for `severity: high`, `warning` for `medium`, `note` otherwise.
- **Security severity:** `8.0` (high band).
- **Stability:** This rule ID will not change within the `0.x` release line.

### `missing_validation_evidence`

- **Name:** Missing validation evidence
- **Short description:** Expected token validation evidence was not found near token use.
- **Full description:** SessionScope found token validation code without
  nearby evidence for required validation attributes such as issuer,
  audience, signature, or expiry enforcement.
- **SARIF level:** `error` for `severity: high`, `warning` for `medium`, `note` otherwise.
- **Security severity:** `6.5` (medium band).
- **Stability:** This rule ID will not change within the `0.x` release line.

### `lifecycle_gap`

- **Name:** Token lifecycle gap
- **Short description:** Token lifecycle evidence is missing a related lifecycle control.
- **Full description:** SessionScope found evidence for one part of a
  token lifecycle without linked evidence for a complementary control
  such as rotation, revocation, or expiry.
- **SARIF level:** `error` for `severity: high`, `warning` for `medium`, `note` otherwise.
- **Security severity:** `5.5` (medium band).
- **Stability:** This rule ID will not change within the `0.x` release line.

### `dynamic_review_required`

- **Name:** Dynamic review required
- **Short description:** Session or token behavior depends on dynamic runtime context.
- **Full description:** SessionScope found evidence that requires human
  review because static source alone cannot determine the effective
  session or token behavior.
- **SARIF level:** rendered as `note`.
- **Security severity:** not set (intentionally omitted; the band is
  reserved for findings SessionScope can mechanically classify).
- **Stability:** This rule ID will not change within the `0.x` release line.

### `framework_default_assumed`

- **Name:** Framework default assumed
- **Short description:** SessionScope inferred behavior from framework defaults.
- **Full description:** SessionScope found behavior that appears to
  rely on framework defaults rather than explicit local configuration.
- **SARIF level:** rendered as `note`.
- **Security severity:** not set.
- **Stability:** This rule ID will not change within the `0.x` release line.

## See also

- [`docs/SCHEMA.md`](SCHEMA.md) — JSON inventory and finding schema,
  including `FindingCategory` and severity semantics.
- [`docs/RELEASES.md`](RELEASES.md) — versioning and compatibility
  policy, including SARIF compatibility expectations.
- [`docs/DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) — rationale for
  category, severity, and security-severity tiers.
- [`crates/sessionscope-model/src/finding.rs`](../crates/sessionscope-model/src/finding.rs)
  — canonical `FindingCategory` enum.
- [`crates/sessionscope-reporters/src/sarif.rs`](../crates/sessionscope-reporters/src/sarif.rs)
  — SARIF reporter that emits the rule IDs and metadata above.
