<p align="center">
  <img src="docs/assets/sessionscope-banner.svg" alt="SessionScope" width="640">
</p>

<p align="center"><strong>Session, cookie, JWT, and token lifecycle auditing for product-security review.</strong></p>

<p align="center">
  <a href="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/rust.yml"><img alt="CI" src="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/rust.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/security.yml"><img alt="Security" src="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/security.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Ozark-Security-Labs/SessionScope/actions/workflows/codeql.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://github.com/Ozark-Security-Labs/SessionScope/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/Ozark-Security-Labs/SessionScope?sort=semver&display_name=tag"></a>
</p>

---

SessionScope maps how authentication artifacts move through your application: how cookies, JWTs, refresh tokens, password-reset tokens, and provider-managed tokens are issued, stored, transmitted, validated, refreshed, revoked, expired, and introspected. It answers a foundational appsec question: **what controls each artifact actually has, and where they go missing?**

SessionScope is intended for product-security teams and developers who need authorized, evidence-backed review of session management risks without attacking a live system.

## Quickstart

Download a prebuilt binary archive from the
[GitHub Releases](https://github.com/Ozark-Security-Labs/SessionScope/releases)
page, unpack it, and move `sessionscope` into a directory on your `PATH`.
On Windows, use `sessionscope.exe` from the `.zip` archive.

You can also install from source:

```bash
cargo install --git https://github.com/Ozark-Security-Labs/SessionScope sessionscope-cli
```

Then bootstrap a config and scan:

```bash
sessionscope init
sessionscope scan --path . --format markdown,json,sarif --output-dir sessionscope-reports
```

## GitHub Action

SessionScope ships a composite GitHub Action:

```yaml
name: SessionScope
on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  sessionscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: sessionscope
        uses: Ozark-Security-Labs/SessionScope@v0.1.0
        with:
          mode: advisory
          path: .
          output: markdown,json,sarif
          fail-on-findings: "false"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sessionscope-reports
          path: ${{ steps.sessionscope.outputs.reports-dir }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.sessionscope.outputs.sarif-path != ''
        with:
          sarif_file: ${{ steps.sessionscope.outputs.sarif-path }}
          category: sessionscope
```

The action runs in advisory mode by default, downloads the matching release binary when used from a tag, writes a GitHub Actions step summary, and exposes report paths for artifact and SARIF upload steps. Requested report formats are produced from a single scan.

To enforce policy in CI, start with `mode: advisory` while uploading Markdown, JSON, and SARIF reports. After the team has reviewed the initial findings, switch to `mode: enforce` with the default `fail-severity: high`. The legacy `fail-on-findings: "true"` input is still accepted and is equivalent to `mode: enforce` with `fail-severity: info`.

## Sample output

A scan flags a session cookie missing `HttpOnly` with the evidence that supports the call:

```text
Cookie: session
Set at: app/auth/session.py:71
Attributes:
  - HttpOnly: missing
  - Secure: present
  - SameSite: lax
  - Max-Age: 30 days
Risk: high_confidence_misconfiguration
Suggested fix:
  - Set HttpOnly on session cookies so client-side scripts cannot read them.
```

The same scan emits JSON for automation, including artifact context, linked evidence, and a reviewer question:

```json
{
  "id": "finding_0001",
  "category": "high_confidence_misconfiguration",
  "severity": "high",
  "artifact_ids": ["artifact_0001"],
  "evidence_ids": ["evidence_cookie_http_only"],
  "title": "Session-like cookie `session` does not set HttpOnly",
  "description": "No HttpOnly attribute evidence was detected for this cookie-setting call.",
  "suggested_fix": "Set HttpOnly on session cookies so client-side scripts cannot read them.",
  "reviewer_question": "Is this cookie intended to be inaccessible to browser JavaScript?"
}
```

The full JSON contract is documented in [docs/SCHEMA.md](docs/SCHEMA.md); end-to-end examples live in [docs/USAGE.md](docs/USAGE.md).

## What you get

**Evidence-bound lifecycle map.** SessionScope models auth artifacts through eight stages: `issue`, `store`, `transmit`, `validate`, `refresh`, `revoke`, `expire`, and `introspect`. Reports state precise things such as "No audience validation evidence detected near JWT verification" and avoid unsupported impact claims.

**Four review capabilities.** The CLI groups lifecycle evidence into cookie posture, claim and validation evidence, logout and revocation evidence, and refresh-token lifecycle evidence. Focused aliases route through the same scanner, detector registry, classifier, redaction, and reporting pipeline.

**Reviewer workflows in CI.** Capture a JSON baseline of accepted findings, diff future scans against it, and resolve any finding ID back to supporting context.

```bash
sessionscope scan --path . --format json --output sessions.json
sessionscope baseline create --from sessions.json --output sessionscope-baseline.json
sessionscope diff --baseline sessionscope-baseline.json --current sessions.json --format markdown
sessionscope explain finding_0001 --report sessions.json
```

**Multi-framework, multi-language coverage.** SessionScope covers session, cookie, JWT, refresh-token, OAuth/OIDC, and identity-provider patterns across Express, Next.js, FastAPI, Django, generic JS/TS/Python JWT libraries, and selected provider SDKs. Coverage is evidence-bound and pattern-based; see [docs/FRAMEWORK_COVERAGE.md](docs/FRAMEWORK_COVERAGE.md) and [docs/PROVIDER_LIBRARY_COVERAGE.md](docs/PROVIDER_LIBRARY_COVERAGE.md).

**Defensive by design.** SessionScope is offline-only and never prints token values, private keys, bearer strings, or cookie values. Source text passes through `sessionscope-core::redaction` before it reaches any report. The full trust boundary is documented in [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md).

## Supported frameworks

| Framework | Language(s) |
| --------- | ----------- |
| Express | Node.js / TypeScript |
| Next.js (App Router) | TypeScript |
| FastAPI | Python |
| Django | Python |
| Generic JWT handling | TypeScript, JavaScript, Python |
| OAuth/OIDC and provider SDK patterns | TypeScript, JavaScript, Python |

Detectors are heuristics that look for known middleware, decorators, library calls, provider configuration, token operations, and cookie-setting APIs. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the detector and classifier contracts.

## CLI overview

| Command | Purpose |
| ------- | ------- |
| `sessionscope init` | Generate a checked-in `sessionscope.toml` |
| `sessionscope scan` | Run the full analyzer against a path |
| `sessionscope cookies` / `claims` / `logout` / `refresh` | Focused views over `scan`, filtered to one capability area (Markdown or JSON only) |
| `sessionscope explain FINDING_ID --report REPORT.json` | Print supporting context for any finding ID |
| `sessionscope baseline create --from REPORT.json` | Snapshot the current finding set as a baseline |
| `sessionscope diff --baseline BASELINE.json --current REPORT.json` | Compare a fresh scan against a saved baseline |
| `sessionscope version` | Print the CLI version |

Full flags, exit semantics, enforcement options, and the complete check catalog are in [docs/USAGE.md](docs/USAGE.md). Configuration lives in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Output formats

| Format | Use it for |
| ------ | ---------- |
| Markdown | Human review, PR comments, GitHub Actions job summaries |
| JSON | Automation and downstream tooling (schema v0.5.0 contract) |
| SARIF | GitHub / GitLab code scanning, advisory alerts |
| GitHub summary | CI job summaries on `pull_request` runs |

The canonical JSON contract is documented in [docs/SCHEMA.md](docs/SCHEMA.md).

## CI enforcement

`sessionscope` exits `0` on successful advisory scans and `1` on errors. In enforce mode it writes requested reports before returning a failing status for findings that match policy.

Blocking policy can be controlled with:

- `--mode advisory|enforce`
- `--fail-severity high|medium|low|info`
- `--fail-category CATEGORY`
- `--include-finding-id ID`
- `--exclude-finding-id ID`
- `--baseline PATH`

`baseline` suppresses matching finding IDs from a prior SessionScope JSON report, or any JSON object with a top-level `findings` array. This is read-only suppression; creating and maintaining baseline files remains separate from `sessionscope baseline create`.

## Configuration

Run `sessionscope init` to create a checked-in `sessionscope.toml` file. The command is non-interactive, does not require network access, and refuses to overwrite an existing config unless `--force` is passed.

Config precedence is:

1. CLI flags such as `--path`, `--include`, `--exclude`, `--format`, `--max-file-size`, `--mode`, `--fail-severity`, `--fail-category`, `--include-finding-id`, `--exclude-finding-id`, and `--baseline`.
2. `sessionscope.toml`.
3. Built-in defaults.

`--include` replaces configured include patterns, while `--exclude` appends to configured excludes. SessionScope also respects `.gitignore` where practical, applies built-in dependency/vendor/build excludes, and skips sensitive paths such as env files and private-key material before source loading.

## Project status

- **Release target:** v0.1.0 first packaged release through GitHub Releases. Release packaging, versioning, and installation workflow are tracked in #28.
- **Complete:** v0.1 foundation, v0.2 cookie audit, v0.3 JWT validation, v0.4 lifecycle mapping, v0.5 expanded token handling, v0.6 framework/provider coverage, v0.7 CI SARIF/enforcement, v0.8 reviewer workflows.
- **Schema:** JSON contract v0.5.0.
- **Rust:** edition 2024. MSRV is 1.95.
- **Platforms:** Linux, macOS, and Windows are covered by CI where workflow support exists.
- **Versioning:** workspace `Cargo.toml` is `0.1.0`; release tags use `vMAJOR.MINOR.PATCH`.

Phase plan and upcoming work are tracked in [docs/ROADMAP.md](docs/ROADMAP.md).

## Documentation

| Document | Contents |
| -------- | -------- |
| [docs/USAGE.md](docs/USAGE.md) | End-to-end CLI usage, lifecycle stages, token types, check catalog |
| [docs/SCHEMA.md](docs/SCHEMA.md) | JSON inventory and finding schema (v0.5.0), baselines, diffs |
| [docs/SARIF_RULES.md](docs/SARIF_RULES.md) | SARIF rule IDs, descriptions, and `0.x` stability commitment |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | `sessionscope.toml` reference and precedence rules |
| [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) | Redaction trust boundary and report sensitivity |
| [docs/RELEASES.md](docs/RELEASES.md) | Versioning, compatibility, changelog, and release automation policy |
| [docs/VERIFYING_RELEASES.md](docs/VERIFYING_RELEASES.md) | Release checksum, SLSA provenance, and binary smoke-test guidance |
| [docs/FRAMEWORK_COVERAGE.md](docs/FRAMEWORK_COVERAGE.md) | Supported and unsupported framework API evidence |
| [docs/PROVIDER_LIBRARY_COVERAGE.md](docs/PROVIDER_LIBRARY_COVERAGE.md) | Provider and identity-library evidence coverage |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline, crate layout, and detector contract |
| [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) | Rationale for config, defaults, confidence levels |
| [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md) | Product framing, target users, MVP criteria |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phase plan and future milestones |

## Security

SessionScope is intended for authorized, defensive analysis of code that you own or are explicitly approved to review. Report vulnerabilities privately via [SECURITY.md](SECURITY.md).

Supply-chain posture:

- `Cargo.lock` is committed and reviewed.
- GitHub Actions in security-critical workflows are pinned to full commit SHAs,
  except the SLSA generic reusable workflow, which upstream requires to use a
  semantic version ref.
- CI runs `cargo test`, `security.yml`, `codeql.yml`, and dependency-determinism checks on every PR.

## Contributing

Design-first contributions are welcome: new framework detectors, lifecycle evidence, classifier improvements, and documentation.

- [CONTRIBUTING.md](CONTRIBUTING.md) - how to propose and submit changes
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - community standards
- [GOVERNANCE.md](GOVERNANCE.md) - maintainer and decision-making model
- [SUPPORT.md](SUPPORT.md) - getting help

## Sibling projects

Part of [Ozark Security Labs](https://github.com/Ozark-Security-Labs). See also [AuthMap](https://github.com/Ozark-Security-Labs/AuthMap), authorization coverage mapping for application code.

## Non-goals

SessionScope is not intended to:

- exploit authentication systems
- brute-force tokens
- attack live applications
- steal or decode secrets
- replace manual security review

## License

SessionScope is licensed under the [MIT License](LICENSE).
