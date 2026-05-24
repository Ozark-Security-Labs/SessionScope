# AGENTS.md

Guidance for agents and automation working in this repository.

## Project Purpose

SessionScope is a defensive product-security tool for auditing session, cookie,
JWT, and token lifecycle behavior in application source code. Keep all work
focused on authorized, offline source analysis and evidence-backed reporting.

Do not add exploit automation, payload generation, credential theft, bypass
instructions, live attack workflows, or behavior that attacks running systems.

## Repository Shape

- `crates/sessionscope-model`: shared inventory, evidence, finding, and schema
  types.
- `crates/sessionscope-detectors`: source and framework detectors that produce
  artifacts and evidence, not final risk judgments.
- `crates/sessionscope-classifier`: converts evidence into findings.
- `crates/sessionscope-reporters`: JSON, Markdown, SARIF, and GitHub summary
  rendering.
- `crates/sessionscope-core`: file discovery, source loading, scan pipeline,
  config, diagnostics, and redaction boundary.
- `crates/sessionscope-cli`: `sessionscope` command-line interface.
- `crates/sessionscope-testing`: fixture and snapshot helpers for tests only.
- `fixtures`: representative app patterns and expected fixture metadata.
- `docs`: architecture, schema, roadmap, and design decisions.

## Safety And Data Handling

- Never store or print raw tokens, private keys, bearer strings, cookie values,
  signing secrets, API keys, or runtime JWT contents.
- Stable IDs must be derived only from non-secret facts such as detector IDs,
  artifact types, normalized paths, source locations, lifecycle stages, and
  sanitized local keys.
- Evidence excerpts must be sanitized before they enter reports or persisted
  inventory.
- Preserve the distinction between evidence and findings:
  - Detectors emit source-bound facts with confidence and dynamic/default
    state.
  - Classifiers decide risk category, severity, suggested fix, and reviewer
    question.
- Prefer review-required findings for dynamic or ambiguous behavior. Use
  high-confidence misconfiguration only for deterministic unsafe evidence.

## Implementation Preferences

- Prefer structured parsing with tree-sitter over ad hoc string scanning for
  source-language detectors.
- Follow existing detector patterns for stable IDs, locations, sanitized
  excerpts, fixture-backed tests, and framework hints.
- Keep schema changes intentional and documented in `docs/SCHEMA.md`; JSON,
  Markdown, SARIF, baselines, diffs, and explain flows depend on stable field
  meanings.
- Add or update fixtures for new detector/classifier behavior where practical.
- Keep reporter code presentation-only. Reporters should not re-run detection
  or classification.

## Development Commands

Run focused checks while iterating, then the full suite before handoff:

```bash
cargo fmt --check
cargo check --workspace
cargo test -q
```

Regenerate committed JSON report snapshots after intentional report-output
changes:

```bash
SESSIONSCOPE_UPDATE_JSON_SNAPSHOTS=1 cargo test -p sessionscope-testing --test json_snapshots
```

For broader local validation:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Useful CLI smoke tests:

```bash
cargo run -p sessionscope-cli -- --help
cargo run -p sessionscope-cli -- version
cargo run -p sessionscope-cli -- scan --path fixtures/generic-ts/jwt-validation --format json
cargo run -p sessionscope-cli -- scan --path fixtures/express/cookie-session-lifecycle --format markdown
```

## Documentation Touchpoints

- Update `README.md` for user-facing behavior changes.
- Update `docs/SCHEMA.md` for inventory or finding schema changes.
- Update `docs/DESIGN_DECISIONS.md` when adding a lasting classification or
  confidence policy.
- Keep fixture `expected.json` files aligned with fixture intent.
