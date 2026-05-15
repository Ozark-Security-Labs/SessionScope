# Architecture

SessionScope is a Rust CLI for defensive source-code analysis of session,
cookie, JWT, and token lifecycle behavior. It analyzes files and configuration
in a repository, reconstructs auth artifact lifecycle evidence, classifies
reviewable risks, and emits reports for humans and CI systems.

Design decisions for dynamic settings, framework defaults, confidence, and
AuthMap-style alignment are recorded in
[`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md).

The implementation should favor:

- deterministic output for unchanged inputs
- evidence-bound findings
- no collection or printing of token or secret values
- safe parallel scanning with explicit ownership boundaries
- small detector modules that can be tested with fixtures

## Pipeline

```text
CLI/config
  -> repository discovery
  -> file classification
  -> per-file parsing and detector execution
  -> per-file evidence records
  -> deterministic inventory merge
  -> lifecycle linking
  -> risk classification
  -> report rendering
```

The important architectural rule is that scanning work may run in parallel, but
shared state mutation should not. Parallel workers should produce immutable
records, and the main pipeline should merge, sort, link, classify, and render
those records deterministically.

## Rust Workspace Scaffold

SessionScope should use a Cargo workspace so core analysis logic stays separate
from the CLI and release packaging.

```text
SessionScope/
  Cargo.toml
  Cargo.lock
  README.md
  SECURITY.md
  CONTRIBUTING.md
  docs/
    ARCHITECTURE.md
    PRODUCT_BRIEF.md
    ROADMAP.md
  crates/
    sessionscope-cli/
      Cargo.toml
      src/
        main.rs
        commands/
          init.rs
          scan.rs
          explain.rs
          baseline.rs
          diff.rs
    sessionscope-core/
      Cargo.toml
      src/
        lib.rs
        config.rs
        discovery.rs
        pipeline.rs
        source.rs
        diagnostics.rs
        redaction.rs
    sessionscope-model/
      Cargo.toml
      src/
        lib.rs
        artifact.rs
        evidence.rs
        finding.rs
        lifecycle.rs
        report.rs
        schema.rs
    sessionscope-detectors/
      Cargo.toml
      src/
        lib.rs
        registry.rs
        traits.rs
        cookies/
        jwt/
        sessions/
        bearer/
        reset_tokens/
        frameworks/
    sessionscope-classifier/
      Cargo.toml
      src/
        lib.rs
        cookies.rs
        jwt.rs
        lifecycle.rs
        bearer.rs
        trust_boundary.rs
    sessionscope-reporters/
      Cargo.toml
      src/
        lib.rs
        json.rs
        markdown.rs
        sarif.rs
        github_summary.rs
    sessionscope-testing/
      Cargo.toml
      src/
        lib.rs
        fixtures.rs
        snapshots.rs
  fixtures/
    README.md
    express/
    nextjs/
    fastapi/
    django/
    generic-js/
    generic-python/
  tests/
    cli/
    integration/
  .github/
    workflows/
      docs.yml
      ci.yml
```

### `sessionscope-cli`

Owns user interaction, argument parsing, exit codes, and command orchestration.
It should be thin: commands call into `sessionscope-core` and reporters rather
than implementing analysis logic directly.

Initial commands:

- `sessionscope init`
- `sessionscope scan`
- `sessionscope explain FINDING_ID`
- `sessionscope baseline create --from REPORT.json --output BASELINE.json`
- `sessionscope diff --baseline BASELINE.json --current REPORT.json`
- `sessionscope version`

### `sessionscope-core`

Owns the scanner pipeline and operational concerns:

- config loading and CLI/config precedence
- repository walking and include/exclude handling
- file classification and size/binary checks
- concurrency orchestration
- diagnostics and skipped-file summaries
- central redaction/safe excerpt utilities
- deterministic merge of scan records

This crate should not contain framework-specific detection rules.

Repository discovery should respect `.gitignore` where practical, apply
built-in dependency/vendor/build excludes, and apply user-provided include and
exclude globs as repository-relative patterns. Sensitive paths such as env files
and private-key material should be skipped before source loading even if a user
include pattern matches them.

### `sessionscope-model`

Owns stable data structures shared across the application:

- auth artifacts
- lifecycle stages
- source locations
- evidence records
- findings
- report documents
- schema version metadata

Model types should derive serialization/deserialization where needed. Schema
changes should be intentional because JSON, SARIF, baseline, diff, and explain
flows all depend on stable identifiers and stable field meaning.

### `sessionscope-detectors`

Owns source-specific and framework-specific detection. Detectors convert parsed
source into evidence records, not final findings.

Initial detector families:

- cookie-setting APIs
- JWT issue/verify/decode APIs
- session middleware and session regeneration calls
- password-reset and email-verification token patterns
- refresh-token stores and rotation signals
- logout and revocation handlers
- opaque bearer token and API key storage/transmission
- query-parameter token acceptance
- framework adapters for Express, Next.js, FastAPI, and Django

Detectors should be small modules with fixture-backed tests. A detector may emit
confidence and reviewer-question hints, but final risk classification belongs in
`sessionscope-classifier`.

### `sessionscope-classifier`

Owns conversion from lifecycle evidence to findings.

Example categories:

- `high_confidence_misconfiguration`
- `missing_validation_evidence`
- `lifecycle_gap`
- `dynamic_review_required`
- `framework_default_assumed`

Classifiers should use evidence-bound language. Missing evidence is not the
same thing as proof of absence unless the detector has enough deterministic
context to say so.

Classifier issues should follow `SS-DEC-001`, `SS-DEC-002`, and `SS-DEC-003`
from the design decision record when handling environment-specific behavior,
framework defaults, confidence, and review-required findings.

### `sessionscope-reporters`

Owns rendering of already-classified scan output:

- Markdown
- JSON
- SARIF
- GitHub Actions step summary

Reporters should not re-run classification. They should also not receive raw
secret-bearing source snippets. Redaction should happen before evidence enters
the inventory, with reporters applying final defensive escaping/formatting.

### `sessionscope-testing`

Owns shared testing helpers. This crate should be used by tests and fixtures,
not by production crates:

- fixture loading
- snapshot normalization
- path normalization across operating systems
- synthetic source builders
- report validation helpers

Keeping this separate prevents production crates from depending on test-only
utilities.

## Core Data Model

### Artifact

An artifact is the normalized object being reviewed: a session cookie, signed
cookie, access JWT, refresh JWT, opaque bearer token, API key, password-reset
token, email-verification token, or session record.

Artifacts should include:

- stable artifact ID
- artifact type
- display name when safely known
- source locations
- lifecycle evidence references
- confidence
- framework/library hints
- optional scope, audience, issuer, tenant, provider, and environment evidence

### Evidence

Evidence is a source-bound fact discovered by a detector.

Evidence should include:

- stable evidence ID
- lifecycle stage
- source file, line, and column when available
- detector ID
- confidence
- sanitized excerpt or structured metadata
- dynamic/framework-default state when relevant

Evidence must not contain token values, private keys, bearer strings, cookie
values, or other sensitive runtime data.

### Finding

A finding is a classifier-produced review item.

Findings should include:

- stable finding ID
- category
- severity or review priority
- related artifact IDs
- related evidence IDs
- evidence-bound title and description
- suggested fix where appropriate
- reviewer question where uncertainty remains

Stable IDs should be deterministic for unchanged source locations and rule
inputs. Baseline and diff workflows depend on this.

## Detector Strategy

SessionScope should prefer structured parsing over string matching where the
language ecosystem makes that practical.

Recommended approach:

- use path and extension classification to select candidate detectors
- use tree-sitter or language-specific parsers for JavaScript/TypeScript and
  Python when feasible
- use structured config parsers for JSON, YAML, TOML, and env-like files when
  needed
- reserve regex/string matching for narrow, well-tested fallback patterns

Detector output should be append-only per file. A detector should not mutate a
global inventory, perform report formatting, or decide CI failure behavior.

## Concurrency Model

Parallelism should be introduced at phase boundaries where ownership is clear.

### Good Parallelism

Repository scanning has natural concurrency opportunities:

- file metadata checks and content reads
- per-file parsing
- per-file detector execution
- independent fixture/integration test scans
- report rendering to multiple formats after classification

These phases can be parallel because each unit can operate on immutable config
and produce independent output records.

### Avoid Parallel Shared Mutation

The following should remain single-owner or deterministic reduction steps:

- assigning final artifact IDs
- merging evidence from multiple files
- linking lifecycle evidence across files
- classifying findings from the merged inventory
- applying baselines and diff comparisons
- deciding process exit status

These steps depend on global ordering and cross-file context. Keeping them as
deterministic reductions avoids race conditions, nondeterministic IDs, and
unstable report output.

### Worker Inputs

Each file worker should receive immutable inputs:

- effective scanner config
- detector registry
- file path and metadata
- source text or parsed source unit
- redaction policy

The worker should return a value such as:

```text
FileScanResult {
  file_id,
  path,
  language,
  artifacts,
  evidence,
  diagnostics,
  skipped_reason,
}
```

No worker should write to shared report files, update baselines, or mutate a
process-wide inventory.

### Deterministic Merge

After parallel file scanning, the pipeline should:

1. Sort file results by normalized repository-relative path.
2. Sort evidence by path, location, detector ID, and stable local key.
3. Create artifact IDs from stable semantic inputs.
4. Link lifecycle evidence using deterministic rules.
5. Classify findings.
6. Sort findings by severity, path, location, rule ID, and finding ID.
7. Render reports.

This makes output stable regardless of worker scheduling.

### Thread Safety Rules

- Prefer immutable shared state behind `Arc`.
- Prefer message passing or parallel iterators that return owned results.
- Avoid `Arc<Mutex<Inventory>>` for core scanning.
- Avoid global mutable detector registries.
- Avoid time-dependent IDs.
- Normalize paths before hashing or ID generation.
- Keep reporter file writes outside detector workers.

## Error and Diagnostic Model

SessionScope should distinguish:

- user-facing command errors
- scanner diagnostics
- skipped-file reasons
- detector parse failures
- report write failures

Parse failures in one file should not abort the full scan unless the user opts
into strict behavior. Reports should include non-sensitive skipped and failed
file counts so reviewers understand coverage.

Skipped-file reasons should describe only operational categories such as
`unsupported`, `excluded`, `sensitive_path`, `too_large`, `binary`, and
`read_error`. They should not include source contents or secret-bearing values.

## Trust Boundary

SessionScope should never collect or print real tokens. It analyzes source code
and configuration patterns, not production traffic or secret values.

The trust boundary should be enforced in `sessionscope-core::redaction` before
source excerpts or structured values enter the inventory. Downstream crates
should be designed as if inventory data is already sanitized, while still
escaping output formats defensively.

The central sanitizer redacts common bearer headers, cookie values, JWT-shaped
strings, private-key blocks, sensitive key/value assignments, sensitive query
parameters, sensitive claim values, and long high-entropy token-like literals.
It should preserve review anchors such as source paths, line and column
locations, artifact and finding IDs, lifecycle stages, claim names, and cookie
attribute names. Redaction is intentionally conservative and best-effort; it is
not a proof that arbitrary source text is secret-free.

Stable IDs and source locations are outside the sanitizer rewrite path because
they are needed to correlate reports. Callers must therefore construct IDs only
from normalized non-secret facts such as detector IDs, paths, line numbers,
artifact kinds, lifecycle stages, and sanitized local keys.

## Implementation Order

The recommended Rust implementation order is:

1. Create the Cargo workspace and thin CLI.
2. Define `sessionscope-model` schema types and stable ID strategy.
3. Implement repository discovery and safe file loading in `sessionscope-core`.
4. Implement central redaction and safe evidence excerpts.
5. Add fixture-backed cookie detectors and cookie classifiers.
6. Add JSON and Markdown reporters.
7. Add JWT detectors and classifiers.
8. Add SARIF and GitHub summary reporters.
9. Add baseline, diff, explain, and enforce-mode behavior.
10. Expand lifecycle mapping, frameworks, providers, and trust-boundary checks.
