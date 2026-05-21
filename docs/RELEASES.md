# Release Policy

SessionScope releases package the defensive CLI, JSON schema contract, report
renderers, and composite GitHub Action behavior that users rely on in local
review and CI. Releases should be reproducible from a protected git tag and
should include enough compatibility notes for users to decide whether to
upgrade immediately. Official releases require an active GitHub repository tag
ruleset named `Protect release tags` protecting `refs/tags/v*`.

## Versioning model

SessionScope uses semantic versioning for the workspace package version and
release tags. Tags use the form `vMAJOR.MINOR.PATCH`, and the tag version must
match the Cargo workspace package version.

Compatibility expectations are:

- **Major** releases may include breaking CLI, schema, configuration, report, or
  GitHub Action changes.
- **Minor** releases may add commands, flags, schema fields, diagnostics, report
  sections, action inputs, or non-breaking behavior.
- **Patch** releases should contain bug fixes, dependency updates,
  documentation corrections, and release automation fixes.

## Version policy

SessionScope ships three independently versioned surfaces. Each one is its own
SemVer contract; downstream consumers should pin to whichever they depend on.
The canonical constants live in
[`crates/sessionscope-model/src/schema.rs`](../crates/sessionscope-model/src/schema.rs)
and [`crates/sessionscope-model/src/baseline.rs`](../crates/sessionscope-model/src/baseline.rs).
A parallel summary lives in [`SCHEMA.md` Version policy](SCHEMA.md#version-policy).

| Surface | Constant | Current | Governs |
| ------- | -------- | ------- | ------- |
| CLI release | `sessionscope` crate version (`Cargo.toml`) | `0.1.0` | CLI flags, command grammar, output paths, exit codes, `sessionscope.toml` keys, GitHub Action inputs |
| Scan report | `SCHEMA_VERSION` (`schema.rs`) | `0.5.0` | `ScanReport` JSON inventory and findings shape |
| Baseline | `BASELINE_SCHEMA_VERSION` (`baseline.rs`) | `0.1.0` | Baseline JSON wire format |
| Diff | `DIFF_SCHEMA_VERSION` (`baseline.rs`) | `0.1.0` | Diff JSON wire format |

Each version moves under its own SemVer rules:

- A CLI release tag (`vX.Y.Z`) tracks the workspace package version and does
  not imply any change to `SCHEMA_VERSION`, the baseline schema, or the diff
  schema.
- Bumping `SCHEMA_VERSION` is independent of the CLI version. Breaking changes
  to the scan-report JSON shape require a `SCHEMA_VERSION` bump and a release
  note even if no CLI grammar changed.
- The baseline and diff schemas evolve independently from the report schema.
  `baseline.report_schema_version` records the report-schema version a
  baseline was captured against, so producers and consumers can correlate the
  two without forcing them onto the same SemVer line.

Release notes must call out which contract changed whenever a release touches
the JSON inventory, baseline wire format, diff wire format, or SARIF rule IDs.
SARIF rule-ID stability is documented in
[`SARIF_RULES.md`](SARIF_RULES.md).

## Compatibility expectations

### CLI

Documented commands, flags, exit-code meanings, and output-format names are
user-facing behavior. Removing a command, renaming a flag, changing the meaning
of an exit code, or changing default behavior requires a compatibility note.
Additive flags and commands are non-breaking when existing invocations continue
to work.

### JSON schemas

The canonical scan report schema, baseline schema, and diff schema are versioned
independently from the CLI release version. Schema changes must update
`docs/SCHEMA.md`, examples or golden output when applicable, and the changelog.

Breaking schema changes include removing required fields, changing field types,
changing enum values, or changing the meaning of existing fields. Release notes
should call out schema compatibility whenever the JSON contract, IDs, report
ordering, baseline behavior, diff behavior, or deterministic output changes.

### Configuration

`sessionscope.toml` compatibility covers documented keys, default values,
validation behavior, and precedence semantics. Removing keys, changing default
enforcement behavior, or changing option interpretation requires a compatibility
note. New optional keys are non-breaking when existing configuration files
continue to load with the same meaning.

### Reports

Markdown and SARIF are user-facing review outputs. Markdown is optimized for
humans and may receive additive sections in minor releases. SARIF output should
remain suitable for advisory code-scanning integration. Changes to alert
severity, result locations, rule IDs, or report failure behavior require
release-note coverage.

### GitHub Action

The composite action follows the release tag. Existing documented inputs and
outputs should remain stable within a major release after `v1.0.0`. New optional
inputs are non-breaking. Removing inputs, changing defaults, changing artifact
behavior, or requiring new workflow permissions requires a compatibility note.

When the action is used from a release tag, it downloads the matching
`sessionscope` release archive for the runner OS and architecture, verifies the
`.sha256` sidecar, and runs that binary. `SESSIONSCOPE_BIN` remains an override
for tests and local workflows. Non-tag refs, unsupported platforms, or missing
release artifacts fall back to the source checkout path.

## Changelog discipline

Every user-visible change should update `CHANGELOG.md` under `Unreleased`
before merge. Release pull requests move entries from `Unreleased` into the new
version section and add schema compatibility notes when relevant.

Use these categories when they fit:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

Keep changelog entries evidence-bound. Do not describe SessionScope findings as
confirmed vulnerabilities unless the project can mechanically prove that claim.

## Release checklist

Before creating a release tag, maintainers should verify:

1. `CHANGELOG.md` has a dated section for the release and an empty
   `Unreleased` section.
2. The Cargo workspace version matches the intended tag.
3. Schema compatibility notes are present when schema-facing behavior changed.
4. The release commit has passed the normal Rust, docs, security, and
   dependency determinism workflows.
5. `cargo test --workspace --all-targets --locked` passes locally or in CI.
6. `cargo package --list --manifest-path crates/sessionscope-cli/Cargo.toml --locked`
   shows only intended package contents.
7. A clean `cargo install --path crates/sessionscope-cli --locked` can run
   `sessionscope --help` and `sessionscope version`.
8. Release binary archives do not include fixtures, generated reports, local
   baselines, credentials, private keys, or scanned target source code.
9. The repository has an active `Protect release tags` ruleset protecting
   `refs/tags/v*`.

## Automated release workflow

The release workflow runs on pushed `v*` tags. Maintainers use `cargo-release`
locally after `v0.1.0` to create the version-bump commit and tag, move the
release commit through a protected-branch PR, then push the tag after verifying
the tag commit is reachable from `main` and `refs/tags/v*` is protected by an
active repository ruleset. The step-by-step runbook is in
[../RELEASING.md](../RELEASING.md).

The workflow checks that the tag matches the workspace version, runs locked
tests, builds platform binaries, verifies release tag protection, generates
per-artifact SHA-256 sidecars, creates SLSA provenance, and publishes a GitHub
Release from the changelog section for that version.

The SLSA generic reusable workflow is intentionally referenced with a semantic
version tag because the upstream generator requires that form. The release
workflow keeps a narrow dependency-determinism allowlist for that single
reference; other external GitHub Actions stay pinned to full commit SHAs.

The workflow publishes GitHub Release artifacts only. It does not publish crates
to crates.io or any package registry. Cargo package artifacts are used to review
package contents while SessionScope's internal crates remain unpublished.
Registry publishing requires a separate reviewed policy and explicit maintainer
approval.

Release artifacts include:

- platform-specific `sessionscope` binaries packaged as archives;
- one `.sha256` sidecar per binary archive;
- `sessionscope-VERSION.cdx.json` CycloneDX SBOM plus its `.sha256` sidecar; and
- `sessionscope-VERSION.intoto.jsonl` SLSA provenance.

GitHub may expose automatic source snapshots for tags. Those snapshots are not
curated install artifacts and are not covered by the binary archive hygiene
promise.

Users can verify release artifacts with
[VERIFYING_RELEASES.md](VERIFYING_RELEASES.md).

`sessionscope version` prints one deterministic line containing the CLI package
version.

## Supported versions

Supported release lines are documented in `SECURITY.md` and updated when
support windows change.
