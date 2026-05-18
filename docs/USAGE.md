# Usage

End-to-end CLI usage, output interpretation, and the catalog of lifecycle stages, token types, and checks that SessionScope is built to surface.

## CLI reference

SessionScope is a single binary, `sessionscope`. All commands operate on a local path, run offline, and produce reviewable reports.

```text
sessionscope init [--force]
sessionscope scan [--path PATH] [--include PATTERN] [--exclude PATTERN] [--max-file-size BYTES] [--format FORMAT[,FORMAT...]] [--output PATH|--output-dir DIR]
sessionscope cookies [scan options]
sessionscope claims [scan options]
sessionscope logout [scan options]
sessionscope refresh [scan options]
sessionscope explain FINDING_ID --report REPORT.json
sessionscope evaluate REPORT.json [--mode advisory|enforce] [policy options]
sessionscope baseline create --from REPORT.json [--output BASELINE.json]
sessionscope diff --baseline BASELINE.json --current REPORT.json [--format json|markdown] [--output PATH]
sessionscope version
```

### `sessionscope init`

Writes a checked-in `sessionscope.toml` to the current directory. Non-interactive and refuses to overwrite an existing config unless `--force` is passed. See [CONFIGURATION.md](CONFIGURATION.md) for the file contents.

### `sessionscope scan`

The main analyzer. Walks `--path` (default `.`), applies include/exclude globs, loads supported source files, runs detectors and classifiers, and renders a report.

Flags:

- `--path PATH` — root to scan. Defaults to the first `scan_paths` entry in `sessionscope.toml`, otherwise `.`.
- `--include PATTERN` — glob to include. Repeatable, or comma-separated. Replaces config `include`.
- `--exclude PATTERN` — glob to exclude. Repeatable, or comma-separated. Appends to config `exclude`.
- `--max-file-size BYTES` — skip files larger than this. Defaults to the config value.
- `--format FORMAT[,FORMAT...]` — one or more of `markdown`, `json`, `sarif`, `github-summary`.
- `--output PATH` — write the report to this file. Defaults to stdout.
- `--output-dir DIR` — write report files into a directory. Required when more than one format is requested.

Multi-format scans walk the source tree once, then render each requested format.
Output directory filenames are `sessionscope.json`, `sessionscope.md`,
`sessionscope.sarif`, and `sessionscope-summary.md`.

### Capability aliases

`sessionscope cookies`, `claims`, `logout`, and `refresh` are focused views over `scan`. They accept the same flags as `scan` but filter findings to the named capability area. Only `markdown` and `json` formats are supported on these aliases.

### `sessionscope explain FINDING_ID --report REPORT.json`

Resolves any finding ID against a JSON scan report and prints the supporting context — artifacts, lifecycle paths, and linked evidence. Useful during PR review.

### `sessionscope evaluate REPORT.json`

Evaluates an existing JSON scan report with the same policy options accepted by
`scan`: `--mode`, `--fail-severity`, `--fail-category`,
`--include-finding-id`, `--exclude-finding-id`, and `--baseline`. This lets CI
reuse a JSON report already produced by a scan instead of walking the source
tree again.

### `sessionscope baseline create --from REPORT.json [--output BASELINE.json]`

Reads a JSON scan report and writes a baseline document. Without `--output`, the baseline is written to stdout. Baselines are stable, evidence-anchored snapshots of the current finding set.

### `sessionscope diff --baseline BASELINE.json --current REPORT.json`

Compares the current JSON report against a saved baseline and reports added, removed, and changed findings. Supports `--format markdown` (default) or `--format json`, and `--output PATH` to write to file.

### `sessionscope version`

Prints the CLI version and exits.

### Exit semantics

`sessionscope` exits `0` on successful advisory scans and `1` on errors. In
enforce mode, `scan` writes requested reports before returning a failing status
for findings that match policy. `evaluate` applies the same policy to an
existing JSON report without scanning source files.

## Lifecycle stages

SessionScope models authentication artifacts through eight stages. Detectors emit evidence tagged with the stage it represents, and reports group evidence into per-artifact lifecycle paths.

| Stage | Meaning |
| ----- | ------- |
| `issue` | Token is created, signed, or returned to a client. |
| `store` | Token is persisted in a cookie, header, session, or server-side store. |
| `transmit` | Token is sent over the wire — request headers, cookies, query strings. |
| `validate` | Token is verified — signature, issuer, audience, expiry, scope. |
| `refresh` | A new access token is issued from a refresh token, rotated, or reused. |
| `revoke` | Server-side state is invalidated — logout, password change, admin action. |
| `expire` | Time-based or session-bound expiry takes effect. |
| `introspect` | Token claims or session state are inspected — introspection endpoint, decoded claim use. |

## Token types

SessionScope classifies the artifacts it identifies into the following categories:

- session cookies
- signed cookies
- access JWTs
- refresh JWTs
- opaque bearer tokens
- API keys
- service tokens
- unknown token flows
- password-reset tokens
- email-verification tokens
- device or session records
- token scope and trust-boundary evidence

## Potential checks

SessionScope is built around defensive, evidence-bound checks. The current and planned check set covers:

- Cookie missing `HttpOnly`
- Cookie missing `Secure`
- Unsafe or review-required cookie posture, including excessive lifetime, broad `Domain`/`Path` scope, and `SameSite=None` handling
- JWT verification without issuer validation
- JWT verification without audience validation
- Tokens issued without explicit expiry
- Refresh tokens without rotation evidence
- Logout without revocation evidence
- Password-reset tokens without expiry or single-use evidence
- Session fixation risk signals
- Token accepted from query parameters
- Review-required token reuse across services, environments, or trust boundaries

## JSON report shape

The canonical schema is documented in [SCHEMA.md](SCHEMA.md). A cookie audit fragment from a real scan looks like this:

```json
{
  "schema_version": "0.5.0",
  "summary": {
    "files_discovered": 1,
    "files_scanned": 1,
    "files_skipped": 0,
    "diagnostics": []
  },
  "artifacts": [
    {
      "id": "artifact_...",
      "artifact_type": "session_cookie",
      "display_name": "session",
      "locations": [{ "path": "src/app.ts", "line": 12, "column": 3 }],
      "lifecycle_evidence": {
        "issue": [],
        "store": ["evidence_cookie_store"],
        "transmit": ["evidence_cookie_secure"],
        "validate": [],
        "refresh": [],
        "revoke": [],
        "expire": [],
        "introspect": []
      },
      "confidence": "high",
      "framework_hints": ["express"],
      "cookie_attributes": {
        "http_only": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_http_only"],
          "confidence": "high"
        },
        "secure": {
          "state": "present",
          "value": "true",
          "evidence_ids": ["evidence_cookie_secure"],
          "confidence": "high"
        },
        "same_site": {
          "state": "present",
          "value": "lax",
          "evidence_ids": ["evidence_cookie_same_site"],
          "confidence": "high"
        },
        "max_age": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_max_age"],
          "confidence": "high"
        },
        "expires": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_expires"],
          "confidence": "high"
        },
        "path": {
          "state": "framework_default",
          "value": "/",
          "evidence_ids": ["evidence_cookie_path"],
          "confidence": "low"
        },
        "domain": {
          "state": "missing",
          "evidence_ids": ["evidence_cookie_domain"],
          "confidence": "high"
        }
      }
    }
  ],
  "evidence": [
    {
      "id": "evidence_cookie_store",
      "lifecycle_stage": "store",
      "location": { "path": "src/app.ts", "line": 12, "column": 3 },
      "detector_id": "cookie.set",
      "confidence": "high",
      "excerpt": "response.cookie(\"session\", [REDACTED], ...)",
      "dynamic": false,
      "framework_default": false
    }
  ],
  "lifecycle_paths": [
    {
      "id": "lifecycle_path_...",
      "artifact_ids": ["artifact_..."],
      "stages": [
        {
          "stage": "store",
          "evidence_ids": ["evidence_cookie_store"]
        }
      ],
      "confidence": "high",
      "dynamic": false,
      "reviewer_question": null
    }
  ],
  "findings": [
    {
      "id": "finding_...",
      "category": "high_confidence_misconfiguration",
      "severity": "high",
      "artifact_ids": ["artifact_..."],
      "evidence_ids": ["evidence_cookie_http_only"],
      "title": "Session-like cookie `session` does not set HttpOnly",
      "description": "No HttpOnly attribute evidence was detected for this cookie-setting call.",
      "suggested_fix": "Set HttpOnly on session cookies so client-side scripts cannot read them.",
      "reviewer_question": "Is this cookie intended to be inaccessible to browser JavaScript?"
    }
  ],
  "files": []
}
```

Token values, cookie values, bearer strings, private keys, and high-entropy literals are replaced with `[REDACTED]` before any report is rendered. See [DATA_HANDLING.md](DATA_HANDLING.md) for the redaction trust boundary.
