# v0.2 Edge-Case Hardening — Design Spec

- Status: Approved (plan-mode brainstorm, 2026-05-21)
- Author: Brian Corder
- Round target: SessionScope v0.2
- Predecessor: v0.1.0 (2026-05-21 release; see CHANGELOG)

## Context

SessionScope just released v0.1.0 with detectors for cookies, JWTs, bearer
tokens, query-param tokens, session lifecycle, refresh lifecycle, and
reset/verification tokens across Express, Next.js, FastAPI, and Django on
JavaScript/TypeScript/Python via tree-sitter. The release shipped a stable
JSON schema (v0.5.0), five finding categories with SARIF rule IDs committed
stable in 0.x, and 33 fixtures.

The next round of work fleshes out the project in line with its documented
purpose without changing functional scope. Two goals were specified:

- Increase coverage for different languages/frameworks
- Ensure existing coverage is comprehensive and catches as many edge cases
  as possible

Brainstorming concluded that this round is **depth first, then breadth**.
New language and framework coverage (Go, Flask, NestJS, Rails, Spring, .NET,
etc.) is deferred to a later round. This round hardens the existing
JS/TS/Python detector surface against high-value edge cases that today
produce neither evidence nor findings.

The output of this round begins as **GitHub milestones, a parent tracker
issue, and detailed child issues** that structure the phased execution
work. Code lands only against an assigned child issue.

## Scope and non-goals

### In scope (four phases)

- **Phase 1** — Cookie prefix and inter-attribute rules: `__Host-`,
  `__Secure-`, `SameSite=None` without `Secure`, `Partitioned` (CHIPS),
  broad `Domain` attribute, conflicting `Set-Cookie` writes for the same
  name within one handler scope.
- **Phase 2** — JWT crypto-trust hardening: `alg:none` acceptance,
  asymmetric→symmetric algorithm-confusion signals, `jku`/`x5u`/embedded-JWK
  header trust, missing `nbf`, clock-skew leniency, unvalidated `kid`.
- **Phase 3** — OAuth/OIDC flow integrity and storage hygiene: PKCE
  missing, `state` missing/static/unverified, OIDC `nonce` missing/
  unverified, wildcard `redirect_uri`, tokens in `localStorage` /
  `sessionStorage`, tokens in URL path or fragment, client secret in
  browser-shipped code.
- **Phase 4** — Lifecycle deepening and test hygiene: JWT denylist absent
  on logout, refresh-family revocation absent on logout, sliding-expiry
  without rotation, password-change without global revocation, plus
  false-positive fixtures, JSON snapshot tests, CLI exit-code matrix tests,
  and consolidated category-audit decision.

### Out of scope (functional-scope guardrails)

- No new framework or language coverage in this round.
- No new lifecycle stages added to the model — the eight existing stages
  remain canonical.
- No new artifact types unless an `audit-then-decide` review concludes one
  is genuinely required.
- No live network probing, no token-decoding to verify content, no
  exploitation. The offline, evidence-bound, redaction-first contract
  documented in `AGENTS.md` and `docs/DATA_HANDLING.md` is preserved.
- The 0.x SARIF rule stability commitment in `docs/SARIF_RULES.md` is
  preserved by default. Any proposed new category requires a documented
  `audit-then-decide` outcome and a consolidated schema increment in P4.

## Category strategy: audit-then-decide

For every proposed new check, the originating issue must classify it into
one of the five existing finding categories first:

- `high_confidence_misconfiguration`
- `missing_validation_evidence`
- `lifecycle_gap`
- `dynamic_review_required`
- `framework_default_assumed`

Only checks that genuinely do not fit any existing category get flagged for
new-category review. The known candidate is the JWT algorithm-confusion /
header-trust family, which may justify a `cryptographic_trust_violation`
category. The final consolidated decision lands in Phase 4 issue **P4.8**
as a new `SS-DEC-*` entry in `docs/DESIGN_DECISIONS.md`, with any required
`docs/SCHEMA.md` and `docs/SARIF_RULES.md` updates batched into one
schema-increment PR.

## Where the changes will land (reference map)

The pipeline (`detector → evidence → classifier → finding → reporter`) is
unchanged. Edits are scoped to:

- `crates/sessionscope-detectors/src/cookies/mod.rs` — P1 extensions
- `crates/sessionscope-detectors/src/jwt/mod.rs` — P2 extensions
- `crates/sessionscope-detectors/src/oauth_flow/mod.rs` *(new)* — P3
- `crates/sessionscope-detectors/src/client_storage/mod.rs` *(new)* — P3
- `crates/sessionscope-detectors/src/sessions/mod.rs` — P4 extensions
- `crates/sessionscope-detectors/src/registry.rs` — register two new
  detectors in P3
- `crates/sessionscope-classifier/src/{cookies,jwt,oauth_flow,client_storage,lifecycle}.rs`
- `crates/sessionscope-core/src/redaction.rs` — extend redaction for
  OAuth `state`, `nonce`, `code_verifier`, `code_challenge` values (P3)
- `fixtures/**` — new positive, negative, and false-positive fixtures per
  phase
- `docs/USAGE.md`, `docs/FRAMEWORK_COVERAGE.md`,
  `docs/PROVIDER_LIBRARY_COVERAGE.md`, `CHANGELOG.md` — per-phase
- `docs/COVERAGE_MATRIX.md` *(new)* — per "Coverage documentation
  requirement" below
- `docs/SARIF_RULES.md`, `docs/SCHEMA.md`, `docs/DESIGN_DECISIONS.md` —
  touched only by the consolidated P4.8 audit outcome

Existing detector/classifier traits
(`crates/sessionscope-detectors/src/traits.rs` and
`crates/sessionscope-classifier/src/lib.rs`) are reused unchanged.

## GitHub artifact plan

### Parent tracker issue

Create one parent tracker issue titled
**`v0.2 — Edge-case hardening tracker`** that:

- Links the four phase milestones below
- Holds the link to this spec document
- Owns the cross-phase category-audit consolidation, resolved in P4.8
- Owns the cumulative fixture-inventory check
- Owns the cumulative per-language / per-framework **coverage matrix**
  (see "Coverage documentation requirement" below): no phase may close
  its docs issue without complete matrix rows for every new check ID
  it introduced
- Records the phase ordering and stop-the-line conditions: if a phase's
  category audit forces a new SARIF rule, downstream phases pause until
  the consolidated schema increment in P4.8 lands

### Milestones (four, one per phase)

1. `v0.2 — Edge-case hardening, P1: cookie prefix/attribute rules`
2. `v0.2 — Edge-case hardening, P2: JWT crypto-trust`
3. `v0.2 — Edge-case hardening, P3: OAuth flow + client storage`
4. `v0.2 — Edge-case hardening, P4: lifecycle + test hygiene`

Each milestone holds its phase's child issues. Each child issue includes:
acceptance criteria, list of files touched, list of new check IDs, fixture
expectations (positive / negative / false-positive), the audit-then-decide
category mapping for each new check, and a doc-update checklist.

### Phase 1 child issues — cookie prefix and inter-attribute rules

- **P1.0** — Coverage-matrix scaffold and v0.1 back-fill. Create
  `docs/COVERAGE_MATRIX.md` with the schema described in the "Coverage
  documentation requirement" section. Populate it with one row per
  existing v0.1 check ID across all currently supported frameworks
  (Express, Next.js, FastAPI, Django, generic JS/TS/Python) and
  provider/library families (Auth0, Okta, Cognito, Azure AD, Firebase,
  Supabase, Clerk, Passport, NextAuth/AuthJS, OAuth/OIDC generic). Add
  an explicit "Not covered" section listing the deferred languages and
  frameworks (Flask, Tornado, Sanic, Starlette, NestJS, Koa, Fastify,
  Hapi, Remix, Hono, SvelteKit, Go, Ruby/Rails, Java/Spring, .NET, PHP,
  python-jose, authlib) so users understand intentional gaps. Update
  the README to link to the matrix from the "Supported frameworks"
  section. **This issue is a strict prerequisite for every other docs
  issue in the round.**
- **P1.1** — Detector: cookie-name prefix recognition. Extend
  `cookies/mod.rs` to tag `__Host-` and `__Secure-` cookies with a
  `cookie_name_prefix` evidence attribute. Framework-default cookies
  carry the existing `framework_default` flag.
- **P1.2** — Classifier: prefix-rule violations. New check IDs
  `cookie_host_prefix_path_violation`,
  `cookie_host_prefix_domain_violation`,
  `cookie_host_prefix_secure_violation`,
  `cookie_secure_prefix_secure_violation`. Category candidates:
  `high_confidence_misconfiguration` for literal violations,
  `dynamic_review_required` when Path/Domain comes from a variable.
- **P1.3** — Classifier: cross-attribute rules. New check IDs
  `cookie_samesite_none_without_secure` (high-confidence on literal),
  `cookie_partitioned_review` (review-required),
  `cookie_domain_leak_review` (review-required, literal-only).
- **P1.4** — Detector: conflicting `Set-Cookie` writes per handler.
  Within one function scope, track multiple writes of the same name across
  `res.cookie`, `cookies().set`, `response.set_cookie`,
  `NextResponse.cookies.set`. Emit `cookie_conflicting_writes_review`
  (review-required only — last-write-wins is dynamic).
- **P1.5** — Fixtures under
  `fixtures/{express,nextjs,fastapi,django}/cookie-prefix-rules/` and
  `fixtures/{express,nextjs,fastapi,django}/cookie-conflicting-writes/`.
  Each ships `expected.json` with artifacts, evidence, and findings.
  Django's runtime `set_cookie` coverage is narrower than its
  settings-based coverage; this is documented in the issue.
- **P1.6** — Docs: `docs/USAGE.md` check catalog,
  `docs/FRAMEWORK_COVERAGE.md` per-framework cookie sections,
  `CHANGELOG.md`. **Every new P1 check ID must add a row to the
  per-language / per-framework coverage matrix described in
  "Coverage documentation requirement" below**, stating exactly which
  languages and frameworks the check fires on and which patterns trigger
  it. `docs/SARIF_RULES.md` is touched only if the P1.2 audit decision
  lands a new category.

**Phase 1 exit gate:** every new check is evidence-bound, the four
supported frameworks have applicable fixtures, `cargo test --workspace
--all-targets` and `cargo clippy --workspace --all-targets -- -D warnings`
pass, and no new false-positive fixtures fire findings.

### Phase 2 child issues — JWT crypto-trust hardening

- **P2.1** — Detector: verify-options key extraction in `jwt/mod.rs` for
  `algorithms`, `algorithm`, `audience`, `issuer`, `subject`, `nonce`,
  `clockTolerance`, `clockTimestamp`, `complete`, `ignoreNotBefore`,
  `ignoreExpiration` and equivalents on `jsonwebtoken`, `jose`, and
  `PyJWT`. Library expansion (python-jose, authlib) is explicitly out of
  scope this round.
- **P2.2** — Classifier: `jwt_alg_none_accepted`. Literal-`none` is
  `high_confidence_misconfiguration`; library-default-permissive is
  `framework_default_assumed`.
- **P2.3** — Classifier: `jwt_alg_confusion_signal` when an HMAC and
  asymmetric algorithm coexist in the accepted list, or the key argument
  is named/typed as a public key while HMAC algorithms are accepted.
  **Candidate for new `cryptographic_trust_violation` category — flag for
  audit.**
- **P2.4** — Classifier: header-trust risks. New check IDs
  `jwt_jku_header_trust`, `jwt_x5u_header_trust`,
  `jwt_embedded_jwk_trust` when `complete: true` is set and downstream
  code reads those headers and passes them to key resolution.
  Review-required.
- **P2.5** — Classifier: `jwt_nbf_missing` (verify option absent),
  `jwt_clock_skew_review` (`clockTolerance` set high or from a variable),
  `jwt_kid_unvalidated_review` (header `kid` read with no visible
  allow-list or lookup function).
- **P2.6** — Fixtures under
  `fixtures/generic-{js,ts,python}/jwt-crypto-trust-*/` with positive,
  negative, and false-positive variants for each check.
- **P2.7** — Docs: check catalog, `CHANGELOG.md`, and the per-language /
  per-framework coverage matrix row(s) for every new P2 check ID (listing
  which JWT libraries — `jsonwebtoken`, `jose`, `PyJWT` — and which
  framework hosts the check fires on). Schema/SARIF updates only if the
  P2.3 audit lands a new category.

**Phase 2 exit gate:** all checks deterministic and evidence-bound, the
P2.3 audit outcome documented (deferred consolidation lands in P4.8), and
redaction excerpt scan confirms no key material leaks through verify-call
evidence.

### Phase 3 child issues — OAuth flow + storage hygiene

- **P3.1** — Detector scaffold: `oauth_flow/mod.rs` registered in
  `registry.rs`. Detect auth-code flow construction across
  `passport-oauth2`, `openid-client`, `next-auth` provider blocks,
  `authlib` (`OAuth2Client`, `OAuth2Session`), and generic crypto-near-
  identifier patterns. Emit artifact type `oauth_auth_code_flow`. **Audit
  whether to add a new artifact type or reuse an existing one.**
- **P3.2** — Classifier: `oauth_pkce_missing_review`. Review-required
  because some libraries enable PKCE by provider default.
- **P3.3** — Classifier: `oauth_state_missing`,
  `oauth_state_static_review`, `oauth_state_unverified_review`.
  Categories per audit-then-decide.
- **P3.4** — Classifier: `oidc_nonce_missing` (authorize-URL builder),
  `oidc_nonce_unverified_review` (verify-call lacks `nonce` option when
  scope includes `openid`). Likely category:
  `missing_validation_evidence`.
- **P3.5** — Classifier: `oauth_redirect_uri_wildcard_review` when a
  `redirect_uris` array literal contains a wildcard, empty path, or
  top-level-domain match. Review-required.
- **P3.6** — Detector: `client_storage/mod.rs` registered in
  `registry.rs`. Detect `localStorage.setItem`, `sessionStorage.setItem`,
  `document.cookie =`, and URL-builder patterns where the key matches a
  token-shaped name pattern (`access_token`, `id_token`, `refresh_token`,
  `jwt`, `bearer`, `auth`, `session`).
- **P3.7** — Classifier: `token_in_local_storage`,
  `token_in_session_storage`, `token_in_url_path_or_fragment`,
  `client_secret_in_browser_code`. Last one is review-required since
  SessionScope cannot prove browser-only execution.
- **P3.8** — Fixtures across
  `fixtures/generic-ts/oauth-flow-{pkce,state,nonce,redirect-uri}/`,
  `fixtures/nextjs/authjs-{pkce,state,nonce}-evidence/`,
  `fixtures/express/passport-oauth2-{pkce,state}/`,
  `fixtures/generic-python/authlib-{pkce,state,nonce}/`,
  `fixtures/generic-{js,ts}/client-storage-{localstorage,sessionstorage,url-fragment}/`.
- **P3.9** — Redaction extension in
  `crates/sessionscope-core/src/redaction.rs` for OAuth `state`, `nonce`,
  `code_verifier`, `code_challenge` values. Snapshot test confirms no
  literal high-entropy value reaches reports.
- **P3.10** — Docs: check catalog, new "OAuth/OIDC flow integrity"
  section in `docs/PROVIDER_LIBRARY_COVERAGE.md`, updates to
  `docs/FRAMEWORK_COVERAGE.md` for Next.js / Express / FastAPI flow
  coverage, `CHANGELOG.md`, and per-language / per-framework coverage
  matrix rows for every new P3 check ID. P3 in particular must document
  which OAuth/OIDC client libraries (`passport-oauth2`, `openid-client`,
  `next-auth`, `authlib`, generic) and which client-storage APIs
  (`localStorage`, `sessionStorage`, `document.cookie`, URL builders)
  each new check fires on.

**Phase 3 exit gate:** both new detectors registered and evidence-bound,
new false-positive fixtures produce zero findings, the P3.1 artifact-type
audit decision documented, and redaction snapshot tests pass on a fixture
containing fake-but-high-entropy `state`/`nonce` values.

### Phase 4 child issues — lifecycle deepening + test hygiene

- **P4.1** — Classifier: `jwt_denylist_absent_on_logout_review` when a
  logout handler is detected but no token-denylist insertion evidence is
  linked.
- **P4.2** — Classifier: `refresh_family_revocation_absent_on_logout_review`,
  building on the existing refresh-lifecycle linker.
- **P4.3** — Classifier: `sliding_expiry_without_rotation_review` when a
  session/refresh handler resets a TTL on each use but no rotation
  evidence is linked.
- **P4.4** — Classifier: `password_change_global_revocation_absent_review`.
- **P4.5** — False-positive fixtures across
  `fixtures/{express,nextjs,fastapi,django,generic-js,generic-ts,generic-python}/clean-baseline-*/`.
  **Every new check ID in P1–P4 must have at least one false-positive
  fixture proving it does not fire on clean code.**
- **P4.6** — JSON snapshot tests under `tests/integration/snapshots/`,
  one representative fixture per framework family. Tooling choice
  (`insta` vs hand-rolled comparison) decided in this issue. Regenerating
  snapshots is a documented one-line command.
- **P4.7** — CLI exit-code matrix tests
  (`tests/cli/test_exit_codes.sh` or Rust equivalent) covering advisory
  vs enforce, `--fail-severity`, `--fail-category`,
  `--include-finding-id`, `--exclude-finding-id`, and `--baseline`
  precedence per `docs/USAGE.md`. Every documented exit-code path gets a
  covering row.
- **P4.8** — Consolidated category-audit decision. New `SS-DEC-*` entry
  in `docs/DESIGN_DECISIONS.md` summarising every new check's category
  mapping across P1–P4. If any new category is required (most likely the
  P2.3 `cryptographic_trust_violation` candidate), the one consolidated
  schema increment lands here, including `docs/SCHEMA.md` and
  `docs/SARIF_RULES.md` updates.
- **P4.9** — Docs: final `CHANGELOG.md` entry for v0.2, `README.md`
  sample-output refresh if any new check appears in the headline cookie
  example, `docs/ROADMAP.md` updated to mark v0.2 phases complete, and a
  final pass on the per-language / per-framework coverage matrix to
  ensure every new P1–P4 check ID has a complete row and that the
  matrix's introductory section explains how users should read it to
  determine which checks will fire on their stack.

**Phase 4 exit gate:** every new check has at least one positive, one
negative where applicable, and one false-positive fixture; snapshot tests
green on a clean checkout; CLI exit-code matrix covers every documented
exit path; consolidated category-audit decision committed.

## Coverage documentation requirement

So that users know exactly what SessionScope processes on their project,
this round introduces and maintains an explicit **per-language /
per-framework coverage matrix**. The matrix lives in `docs/FRAMEWORK_COVERAGE.md`
(extended) plus a new companion document `docs/COVERAGE_MATRIX.md` that
consolidates the cross-product into one scannable table.

**Matrix shape.** Rows are check IDs (every existing v0.1 check plus every
new P1–P4 check). Columns include: language(s) the check applies to,
framework(s) and library/SDK families it fires on, the specific APIs or
option keys that trigger the evidence, the lifecycle stage, the finding
category mapped by the audit-then-decide rule, the SARIF rule ID, and a
one-line "What this means for your project" note. Cells must distinguish
**supported** (deterministic patterns), **review-required** (dynamic /
framework-default), and **not covered** (intentional gap) states.

**Authoring rules.**

- Every new check ID added in P1–P4 must arrive with at least one matrix
  row before its issue can close.
- The parent tracker issue holds the cumulative coverage-matrix check: no
  phase may close until its rows are present and accurate.
- Existing v0.1 checks get back-filled into the matrix once during Phase
  1 setup (issue P1.0) so the document is complete from day one rather
  than partial.
- The matrix must clearly label what is **not** covered (e.g., Flask, Go,
  python-jose, authlib JWT path) so users understand the absence of
  findings on certain stacks is by design, not a SessionScope bug.
- The matrix is the single source of truth for "will SessionScope find X
  on Y stack?" — `docs/FRAMEWORK_COVERAGE.md` and
  `docs/PROVIDER_LIBRARY_COVERAGE.md` continue to host narrative context
  but link to the matrix for per-check truth.

## Cross-cutting concerns

- **Redaction first.** Every new detector touches `redaction.rs` review
  before merging. P3 adds `state`/`nonce`/`code_verifier`/`code_challenge`
  to the high-entropy redaction set.
- **Stable IDs.** New finding IDs follow `{domain}_{rule}` and detector
  IDs follow `{domain}.{operation}.{attribute}`. Artifact/evidence IDs
  derive only from non-secret facts per `AGENTS.md`.
- **Performance.** No new tree-sitter parsers. New rules go in adjacent
  submodules where natural to avoid further enlarging `cookies/mod.rs`
  (already 2,731 lines) or `jwt/mod.rs`.
- **Backwards compatibility.** No existing check ID renamed, no existing
  category removed, no existing evidence shape altered. The 33 existing
  fixtures' `expected.json` files must continue to pass unchanged.
- **Documentation discipline.** Every issue includes a `docs/USAGE.md`
  check-catalog update line **and** a coverage-matrix row update per the
  "Coverage documentation requirement" section. The category audit
  decision is the only path to touching `docs/SCHEMA.md` or
  `docs/SARIF_RULES.md`, and only via P4.8.

## Verification

- **Per-phase exit gate:** `cargo fmt --check && cargo clippy --workspace
  --all-targets -- -D warnings && cargo test --workspace --all-targets`
  plus new fixtures' `expected.json` assertions.
- **End-to-end smoke per phase:** `cargo run -p sessionscope-cli -- scan
  --path fixtures/<new-fixture>/ --format markdown,json,sarif` for one
  representative fixture per phase, confirming reporters render new
  findings correctly.
- **Regression guardrail:** the 33 existing fixtures continue to produce
  identical `expected.json` outputs after each phase.
- **Redaction audit:** a dedicated test scans every fixture's rendered
  Markdown and JSON for forbidden patterns — JWT-shape, bearer-shape, and
  high-entropy strings in `state` / `nonce` positions.

## Execution sequence after spec approval

The first execution actions are **not Rust code**:

1. Commit this spec document.
2. Create the four GitHub milestones listed above.
3. Open the parent tracker issue and link the four milestones.
4. Open each child issue (P1.0 through P4.9) under the correct milestone,
   each with: acceptance criteria, file list, new check IDs, fixture
   expectations, audit-then-decide category mapping, doc-update checklist.
5. Triage ordering so Phase 1 starts first (P1.0 is a strict prerequisite
   for any other docs issue) and downstream phases pause if a category
   audit forces a new SARIF rule that must consolidate in P4.8.

Only after these artifacts exist does any detector, classifier, or fixture
code get written, and only against an assigned child issue.
