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

Finding IDs are also persisted in `partialFingerprints` via the
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

## Remediation guidance

The examples below show common vulnerable patterns and the corresponding fix. All secret-shaped values use the `PLACEHOLDER_SECRET` convention and must be replaced with real secrets from environment variables or a secrets manager.

### Cookie findings (`high_confidence_misconfiguration`, `framework_default_assumed`)

**Express — missing HttpOnly, Secure, SameSite**

```js
// Vulnerable: no HttpOnly, no Secure, no SameSite
res.cookie("session", token, { maxAge: 900_000 });

// Fixed
res.cookie("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 900_000,
});
```

**FastAPI/Django — missing HttpOnly or Secure**

```python
# Vulnerable (FastAPI): no httponly, no secure
response.set_cookie("session", value, max_age=900)

# Fixed
response.set_cookie(
    "session", value,
    httponly=True,
    secure=True,
    samesite="lax",
    max_age=900,
)
```

**Excessive lifetime**

```js
// Vulnerable: 90-day max-age
res.cookie("session", token, { maxAge: 90 * 24 * 60 * 60 * 1000 });

// Fixed: 15-minute session window
res.cookie("session", token, { maxAge: 15 * 60 * 1000, httpOnly: true, secure: true, sameSite: "lax" });
```

### JWT findings (`high_confidence_misconfiguration`, `missing_validation_evidence`)

**JS/TS — missing issuer, audience, expiry**

```ts
// Vulnerable: no issuer, no audience, no expiration
const token = jwt.sign({ sub: userId }, PLACEHOLDER_SECRET);
jwt.verify(token, PLACEHOLDER_SECRET);

// Fixed
const token = jwt.sign(
  { sub: userId, iss: "https://api.example.com", aud: "web-app" },
  PLACEHOLDER_SECRET,
  { expiresIn: "15m" }
);
jwt.verify(token, PLACEHOLDER_SECRET, {
  issuer: "https://api.example.com",
  audience: "web-app",
  algorithms: ["HS256"],
});
```

**Python (PyJWT) — disabled expiry enforcement**

```python
# Vulnerable: expiry verification disabled
payload = jwt.decode(token, PLACEHOLDER_SECRET, options={"verify_exp": False}, algorithms=["HS256"])

# Fixed
payload = jwt.decode(token, PLACEHOLDER_SECRET, algorithms=["HS256"])
```

**Algorithm confusion / accepting `none`**

```ts
// Vulnerable: none algorithm accepted
jwt.verify(token, PLACEHOLDER_SECRET, { algorithms: ["none", "HS256"] });

// Fixed: pin to one algorithm family
jwt.verify(token, PLACEHOLDER_SECRET, { algorithms: ["HS256"] });
```

### OAuth/OIDC findings (`missing_validation_evidence`, `dynamic_review_required`)

**PKCE missing**

```ts
// Vulnerable: no PKCE
const url = client.authorizationUrl({ scope: "openid profile", state: generateState() });

// Fixed: add PKCE
const { code_verifier, code_challenge } = await generatePKCEPair();
const url = client.authorizationUrl({
  scope: "openid profile",
  state: generateState(),
  code_challenge,
  code_challenge_method: "S256",
});
```

**State not verified on callback**

```ts
// Vulnerable: state value read but not compared
const { code, state } = callbackParams(req);
const tokens = await client.callback(redirectUri, { code });

// Fixed: verify state
const storedState = req.session.oauthState;
if (state !== storedState) throw new Error("CSRF: state mismatch");
const tokens = await client.callback(redirectUri, { code }, { state: storedState });
```

**Python Authlib — missing state verification**

```python
# Vulnerable: no state check in callback
def callback(request):
    token = oauth.myapp.authorize_access_token(request)

# Fixed
def callback(request):
    state = request.session.pop("oauth_state", None)
    token = oauth.myapp.authorize_access_token(request, state=state)
```

### Bearer / API-key findings (`high_confidence_misconfiguration`, `missing_validation_evidence`)

**Token accepted from URL query parameter**

```ts
// Vulnerable: token accepted from URL query
const token = req.query.access_token;

// Fixed: require Authorization header only
const authHeader = req.headers.authorization;
if (!authHeader?.startsWith("Bearer ")) return res.status(401).end();
const token = authHeader.slice(7);
```

**Token exposed in public runtime config (Next.js)**

```ts
// Vulnerable: token-shaped key in publicRuntimeConfig
const config = {
  publicRuntimeConfig: { apiToken: process.env.NEXT_PUBLIC_API_TOKEN },
};

// Fixed: keep token in server-only config
const config = {
  serverRuntimeConfig: { apiToken: process.env.API_TOKEN },
};
```

**Missing validation evidence**

```ts
// Vulnerable: bearer token used without validation
async function handler(req) {
  const token = req.headers.authorization?.slice(7);
  const userId = parseTokenUnsafe(token); // no verify
  return getUserData(userId);
}

// Fixed: verify before trusting
async function handler(req) {
  const token = req.headers.authorization?.slice(7);
  const { payload } = await jwtVerify(token, SECRET, {
    issuer: "https://api.example.com",
    audience: "web-app",
  });
  return getUserData(payload.sub);
}
```

### Client-storage findings (`high_confidence_misconfiguration`)

**localStorage token storage**

```ts
// Vulnerable: access token in localStorage
localStorage.setItem("access_token", token);

// Fixed: use an HttpOnly session cookie managed server-side;
// if client JS must hold a token, use sessionStorage for
// short-lived access tokens and consider memory-only storage
sessionStorage.setItem("access_token", token); // still review-required; prefer HttpOnly cookie
```

**Client secret in browser code**

```ts
// Vulnerable: client secret in a file under src/components/
const clientSecret = "PLACEHOLDER_SECRET_DO_NOT_USE";

// Fixed: move OAuth client-secret calls to a server-side API route;
// browser code should only hold the public client_id
```

### Lifecycle-gap findings (`lifecycle_gap`)

**Clear-cookie-only logout**

```ts
// Vulnerable: only the cookie is cleared; server-side session not invalidated
app.post("/logout", (req, res) => {
  res.clearCookie("session");
  res.redirect("/");
});

// Fixed: destroy the server-side session record before clearing the cookie
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("session");
    res.redirect("/");
  });
});
```

**Refresh token without rotation**

```ts
// Vulnerable: new access token issued but old refresh token not revoked
app.post("/refresh", async (req, res) => {
  const { refresh_token } = req.body;
  await validateRefreshToken(refresh_token);
  const newAccess = issueAccessToken(userId);
  res.json({ access_token: newAccess });
});

// Fixed: rotate the refresh token and revoke the previous one
app.post("/refresh", async (req, res) => {
  const { refresh_token } = req.body;
  const record = await validateRefreshToken(refresh_token);
  await revokeRefreshToken(refresh_token); // mark old token used
  const newRefresh = await issueRefreshToken(record.userId);
  const newAccess = issueAccessToken(record.userId);
  res.json({ access_token: newAccess, refresh_token: newRefresh });
});
```

**Password change without global session revocation**

```ts
// Vulnerable: password changed but existing sessions not invalidated
app.post("/change-password", async (req, res) => {
  await updatePassword(userId, req.body.newPassword);
  res.json({ ok: true });
});

// Fixed: revoke all active sessions after password change
app.post("/change-password", async (req, res) => {
  await updatePassword(userId, req.body.newPassword);
  await revokeAllSessions(userId); // invalidate all existing sessions/refresh tokens
  res.json({ ok: true });
});
```

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
