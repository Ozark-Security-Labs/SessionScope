# Changelog

All notable user-visible changes to SessionScope should be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and SessionScope uses semantic versioning as described in
[docs/RELEASES.md](docs/RELEASES.md).

## Unreleased

### Added

- Added `docs/COVERAGE_MATRIX.md` as the per-check source of truth for supported, review-required, and intentionally not-covered SessionScope evidence patterns across languages, frameworks, libraries, lifecycle stages, finding categories, and SARIF rule IDs.
- Added v0.2 P1 cookie hardening coverage for `__Host-` / `__Secure-` prefix rules, `Partitioned` cookie review, broad non-session Domain review, and same-handler conflicting cookie writes across existing JS/TS/Python cookie detectors.
- Added v0.2 P2 JWT crypto-trust coverage for `alg:none`, HMAC/asymmetric algorithm-confusion signals, `jku`/`x5u`/embedded-JWK header trust review, missing `nbf` validation, broad clock-skew review, and unvalidated `kid` header review across existing `jsonwebtoken`, `jose`, and PyJWT detector surfaces.
- Added v0.2 P3 OAuth/OIDC flow integrity coverage for PKCE, `state`, OIDC `nonce`, broad redirect URI review, and client storage hygiene checks for localStorage, sessionStorage, URL path/fragment token exposure, and browser-path client secrets.
- Added `jwt_denylist_absent_on_logout_review` lifecycle coverage for access-JWT logout flows that lack linked denylist, blocklist, or token revocation-store evidence.
- Added `refresh_family_revocation_absent_on_logout_review` lifecycle coverage for refresh-token logout flows that lack linked family/user-scoped revocation evidence.
- Added `sliding_expiry_without_rotation_review` lifecycle coverage for rolling/sliding session expiry that lacks linked session or refresh-token rotation evidence.
- Added `password_change_global_revocation_absent_review` lifecycle coverage for password-change handlers that lack linked global session invalidation, refresh-family revocation, or token-version bump evidence.
- Added clean-baseline false-positive fixtures across Express, Next.js, FastAPI, Django, generic JS/TS, and generic Python to guard every v0.2 P1-P4 check ID.
- Added hand-rolled JSON report snapshot tests for representative Express, Next.js, FastAPI, Django, generic JS, generic TS, and generic Python fixtures.
- Extended report redaction for OAuth/OIDC `state`, `nonce`, `code_verifier`, and `code_challenge` values in assignments, object keys, and URL parameters.

### Pre-release remediation (v0.1.0 readiness)

#### Critical fixes

- **F-01** Single-pass bounded file read in `sessionscope-core::source` —
  closes a TOCTOU window and bounds allocation at read time so a growing
  target file cannot exhaust scanner memory.
- **F-02** Worker-thread panics are caught and reported as
  `SkippedReason::ReadError("detector panic")` instead of aborting the
  scan. `ScanSummary.worker_panic_count` surfaces the count.

#### High-severity fixes

- **F-03** Discovery refuses symbolic links and verifies each entry stays
  under the canonical scan root (defense-in-depth against hostile target
  repositories that point in-tree links at host secrets).
- **F-04** `scripts/github-action.sh` rejects `..` segments in the action
  `path` input and resolves the path inside `$GITHUB_WORKSPACE`.
- **F-05** Stable-ID FNV separator changed from `0` (no-op) to `0xFF` so
  `("ab","c")` and `("a","bc")` produce distinct hashes. All stable
  artifact, evidence, finding, lifecycle-path, and baseline fingerprint
  IDs change pre-release — no v0.1.0 contract has been published yet.
- **F-06** `SanitizedExcerpt` is now non-constructible from raw `String`;
  every detector excerpt must flow through `safe_excerpt`,
  `safe_excerpt_at_location`, or `sanitize_excerpt`. Two `compile_fail`
  doctests enforce the boundary.
- **F-07** Baseline fingerprints use the new serde-stable `stable_name()`
  helpers on `FindingCategory`, `Severity`, `Confidence`, and
  `LifecycleStage` instead of `format!("{:?}", …)`, so future rustc
  Debug-format tweaks cannot silently invalidate every saved baseline.
- **F-08** `zmij 1.0.21` (transitive of `serde_json 1.0.149`) reviewed
  and accepted: legitimate dtolnay-authored Schubfach/Żmij float-to-string
  port. Audit recorded in `docs/DEPENDENCY_REVIEW.md`.

#### Medium-severity fixes

- **F-09** Excerpt redaction is context-aware: under
  `RedactionContext::Cookies`, `Jwt`, `Bearer`, or `ApiKey` any string
  literal ≥16 chars is stripped even when the variable name is not in
  the sensitive allowlist.
- **F-10** Per-file CPU and memory budgets — default
  `max_file_size_bytes` lowered to 512 KB, worker count clamped to
  `min(available_parallelism(), 4)`, per-file wall-clock budget defaults
  to 2 s, minified files get half the budget. New `SkippedReason::Timeout`
  variant.
- **F-11** Action `baseline` input now passed via `--baseline -- "$baseline"`
  so smuggled flags cannot disable policy enforcement.
- **F-12** `sessionscope evaluate` now honours `sessionscope.toml` policy
  config the same way `scan` does, via the shared `commands::policy`
  helper. Closes a CI-bypass where TOML-configured enforce mode silently
  degraded to advisory on the evaluate command.
- **F-13** `ScanSummary.skipped_by_reason: BTreeMap<SkippedReasonKind, u32>`
  and `ScanReport::has_critical_failures()` expose per-reason skip counts
  so CI integrations can detect crippled scans.
- **F-14** `ProjectConfig::load_default()` distinguishes `NotFound` (use
  empty config) from `PermissionDenied` (surface error) when reading
  `sessionscope.toml`.
- **F-15** `SkippedReason::ReadError` strings carry only the
  `io::ErrorKind` label (e.g. `"permission denied"`); raw OS error
  strings that can leak absolute paths and operator usernames no longer
  reach reports.

#### Low-severity polish

- **F-16** `WalkBuilder::parents(false)` — scanner never reads
  `.gitignore`/`.ignore` files above the scan root.
- **F-17** Directories and files that do not strip-prefix cleanly
  against the scan root are skipped with `SkippedReason::Excluded` and a
  basename-only display, never under their absolute filesystem path.
- **F-18** SARIF emits `originalUriBaseIds.SRCROOT` with percent-encoded
  relative `artifactLocation.uri` values per SARIF 2.1.0 §3.4.4. Output
  round-trips through `serde-sarif`.
- **F-19** All CLI report paths use `println!` for consistent trailing
  newlines; renderers strip embedded trailing newlines via a shared
  helper.
- **F-20** `ScanError::source()` is implemented so error chains surface
  the underlying `io::Error`.
- **F-21** `CommandResult` type alias is documented as intentional at
  the CLI boundary.
- **F-22** `sanitize_evidence` short-circuits when the excerpt is
  already canonical, halving regex work on common second-pass paths.
- **F-23** Canonical FNV hash lives in `sessionscope_model::stable_hash`;
  `baseline.rs::stable_fingerprint` delegates so the two sites cannot
  drift.
- **F-24** GitHub Action wrapper writes the rewritten SARIF to
  `<path>.tmp` then `os.replace`, so a crash mid-rewrite cannot leave a
  zero-byte SARIF.

#### Informational / supply chain

- **F-25** Dependabot watches `slsa-framework/slsa-github-generator`;
  trust decision (pin-by-tag for the reusable workflow) documented in
  `RELEASING.md`.
- **F-26** Release workflow includes a cold/warm reproducibility check
  asserting `sha256sum` equality across two builds.
- **F-27** Release workflow generates a CycloneDX SBOM
  (`sessionscope-<version>.cdx.json`) and attaches it to GitHub Releases.
- **F-28** `cargo audit` advisory database cached across CI runs via
  `actions/cache@<sha>`.
- **F-29** SARIF rule-ID stability commitment documented in
  `docs/SARIF_RULES.md`.
- **F-30** Independent versioning policy (crate, report schema,
  baseline/diff schema) documented in `docs/SCHEMA.md` and
  `docs/RELEASES.md`.

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
