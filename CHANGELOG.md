# Changelog

All notable user-visible changes to SessionScope should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and SessionScope uses semantic versioning as described in
[docs/RELEASES.md](docs/RELEASES.md).

## Unreleased

## 0.1.0 - 2026-05-18

### Added

- Initial defensive SessionScope CLI for offline session, cookie, JWT, and token
  lifecycle source analysis.
- JSON, Markdown, SARIF, and GitHub summary report output for evidence-bound
  product-security review.
- Focused capability aliases for cookies, claims, logout, and refresh views
  over the shared scanner pipeline.
- Reviewer workflows for baselines, diffs, explain output, advisory/enforce
  policy modes, and composite GitHub Action usage.
- Release packaging policy for GitHub Release binary archives, source archives,
  SHA-256 sidecars, SLSA provenance, and artifact verification.

### Schema compatibility

- Initial SessionScope scan report JSON schema version `0.5.0`.
- Initial baseline and diff JSON schema version `0.1.0`.
