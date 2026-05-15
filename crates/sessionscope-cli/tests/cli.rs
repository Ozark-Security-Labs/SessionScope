use std::path::Path;
use std::process::{Command, Output};
use std::{fs, str};

fn run_sessionscope(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .args(args)
        .output()
        .expect("failed to run sessionscope")
}

fn run_sessionscope_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to run sessionscope")
}

fn fixture_path(segments: &[&str]) -> std::path::PathBuf {
    segments.iter().fold(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures"),
        |mut path, segment| {
            path.push(segment);
            path
        },
    )
}

#[test]
fn help_succeeds() {
    let output = run_sessionscope(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "sessionscope init",
        "sessionscope scan",
        "sessionscope cookies",
        "sessionscope claims",
        "sessionscope logout",
        "sessionscope refresh",
        "sessionscope explain",
        "sessionscope baseline create",
        "sessionscope diff",
        "sessionscope version",
    ] {
        assert!(stdout.contains(command), "help output missing {command}");
    }
    assert!(stdout.contains("focused views over sessionscope scan"));
}

#[test]
fn version_succeeds() {
    let output = run_sessionscope(&["version"]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sessionscope"));
}

#[test]
fn version_flag_matches_version_command() {
    let command_output = run_sessionscope(&["version"]);
    let flag_output = run_sessionscope(&["--version"]);

    assert!(command_output.status.success());
    assert!(flag_output.status.success());
    assert_eq!(command_output.stdout, flag_output.stdout);
}

#[test]
fn unknown_command_fails_without_panicking() {
    let output = run_sessionscope(&["definitely-not-a-command"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command"));
}

#[test]
fn baseline_create_writes_versioned_baseline_from_scan_report() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    let baseline_path = temp.path().join("baseline.json");
    fs::write(
        &report_path,
        scan_report_json(&[finding_json(
            "finding_existing",
            "Existing finding",
            "description",
            "evidence_existing",
            7,
        )])
        .to_string(),
    )
    .expect("scan report should be written");

    let output = run_sessionscope(&[
        "baseline",
        "create",
        "--from",
        report_path.to_str().expect("report path should be UTF-8"),
        "--output",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
    ]);

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let baseline = fs::read_to_string(baseline_path).expect("baseline should be written");
    let parsed: serde_json::Value =
        serde_json::from_str(&baseline).expect("baseline JSON should parse");
    assert_eq!(parsed["schema_version"], "0.1.0");
    assert_eq!(parsed["report_schema_version"], "0.5.0");
    assert_eq!(parsed["findings"][0]["id"], "finding_existing");
    assert!(
        parsed["findings"][0]["semantic_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("fingerprint_"))
    );
}

#[test]
fn baseline_create_redacts_secret_like_report_text() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    fs::write(
        &report_path,
        scan_report_json(&[finding_json(
            "finding_secret",
            "PLACEHOLDER_SECRET_DO_NOT_USE in title",
            "description PLACEHOLDER_SECRET_DO_NOT_USE",
            "evidence_secret",
            7,
        )])
        .to_string(),
    )
    .expect("scan report should be written");

    let output = run_sessionscope(&[
        "baseline",
        "create",
        "--from",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(!stdout.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    assert!(stdout.contains("[REDACTED]"));
}

#[test]
fn explain_known_finding_from_json_report() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    fs::write(
        &report_path,
        scan_report_json(&[finding_json(
            "finding_existing",
            "Existing finding",
            "Confirm this evidence-bound finding.",
            "evidence_existing",
            7,
        )])
        .to_string(),
    )
    .expect("scan report should be written");

    let output = run_sessionscope(&[
        "explain",
        "finding_existing",
        "--report",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("# SessionScope Finding Explain"));
    assert!(stdout.contains("Existing finding"));
    assert!(stdout.contains("- Finding ID: `finding_existing`"));
    assert!(stdout.contains("- Severity: `medium`"));
    assert!(stdout.contains("- Category: `lifecycle_gap`"));
    assert!(stdout.contains("lifecycle evidence that appears incomplete"));
    assert!(stdout.contains("| `evidence_existing` | `validate` | src/auth.ts:7:1 | test.detector | `high` | `no` | `no` | evidence for Existing finding |"));
    assert!(stdout.contains("- Suggested fix: no specific remediation"));
    assert!(stdout.contains("- Reviewer question: none attached"));
    assert!(stdout.contains("docs/SCHEMA.md"));
}

#[test]
fn explain_unknown_finding_does_not_echo_supplied_id() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    fs::write(&report_path, scan_report_json(&[]).to_string())
        .expect("scan report should be written");
    let sensitive_finding_id = "aaa.bbb.cccccccccccccccccccccc";

    let output = run_sessionscope(&[
        "explain",
        sensitive_finding_id,
        "--report",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("finding not found in report"));
    assert!(!stderr.contains(sensitive_finding_id));
}

#[test]
fn explain_malformed_report_does_not_echo_secret_like_report_contents() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    fs::write(
        &report_path,
        "{\"secret\":\"PLACEHOLDER_SECRET_DO_NOT_USE\",",
    )
    .expect("invalid scan report should be written");

    let output = run_sessionscope(&[
        "explain",
        "finding_existing",
        "--report",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("failed to parse scan report"));
    assert!(!stderr.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
}

#[test]
fn diff_json_classifies_incremental_finding_changes() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let baseline_report_path = temp.path().join("baseline-scan.json");
    let baseline_path = temp.path().join("baseline.json");
    let current_report_path = temp.path().join("current-scan.json");

    fs::write(
        &baseline_report_path,
        scan_report_json(&[
            finding_json(
                "finding_moved_old",
                "Moved finding",
                "description",
                "evidence_moved_old",
                7,
            ),
            finding_json(
                "finding_resolved",
                "Resolved finding",
                "description",
                "evidence_resolved",
                11,
            ),
        ])
        .to_string(),
    )
    .expect("baseline scan report should be written");
    fs::write(
        &current_report_path,
        scan_report_json(&[
            finding_json(
                "finding_moved_new",
                "Moved finding",
                "description",
                "evidence_moved_new",
                17,
            ),
            finding_json(
                "finding_new",
                "New finding",
                "description",
                "evidence_new",
                19,
            ),
        ])
        .to_string(),
    )
    .expect("current scan report should be written");

    let baseline_output = run_sessionscope(&[
        "baseline",
        "create",
        "--from",
        baseline_report_path
            .to_str()
            .expect("baseline report path should be UTF-8"),
        "--output",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
    ]);
    assert!(baseline_output.status.success());

    let diff_output = run_sessionscope(&[
        "diff",
        "--baseline",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
        "--current",
        current_report_path
            .to_str()
            .expect("current report path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(diff_output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&diff_output.stdout).expect("diff JSON should parse");
    assert_eq!(parsed["summary"]["moved"], 1);
    assert_eq!(parsed["summary"]["new"], 1);
    assert_eq!(parsed["summary"]["resolved"], 1);
    assert!(
        parsed["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .any(|change| change["kind"] == "moved"
                && change["baseline"]["id"] == "finding_moved_old"
                && change["current"]["id"] == "finding_moved_new")
    );
}

#[test]
fn diff_markdown_renders_reviewer_summary() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    let baseline_path = temp.path().join("baseline.json");
    fs::write(
        &report_path,
        scan_report_json(&[finding_json(
            "finding_existing",
            "Existing finding",
            "description",
            "evidence_existing",
            7,
        )])
        .to_string(),
    )
    .expect("scan report should be written");

    let baseline_output = run_sessionscope(&[
        "baseline",
        "create",
        "--from",
        report_path.to_str().expect("report path should be UTF-8"),
        "--output",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
    ]);
    assert!(baseline_output.status.success());

    let diff_output = run_sessionscope(&[
        "diff",
        "--baseline",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
        "--current",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(diff_output.status.success());
    let stdout = str::from_utf8(&diff_output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("# SessionScope Diff"));
    assert!(stdout.contains("## Summary"));
    assert!(stdout.contains("- Unchanged: 1"));
    assert!(stdout.contains("Existing finding"));
}

#[test]
fn diff_markdown_redacts_and_escapes_report_controlled_text() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let baseline_path = temp.path().join("baseline.json");
    let current_report_path = temp.path().join("current-scan.json");
    fs::write(
        &baseline_path,
        serde_json::json!({
            "schema_version": "0.1.0",
            "report_schema_version": "0.5.0",
            "created_by": "sessionscope",
            "findings": [{
                "id": "finding_secret",
                "category": "lifecycle_gap",
                "severity": "medium",
                "title": "PLACEHOLDER_SECRET_DO_NOT_USE [link](x)",
                "semantic_fingerprint": "fingerprint_secret",
                "evidence_fingerprint": "fingerprint_secret",
                "artifact_ids": [],
                "evidence_ids": [],
                "source_locations": [{
                    "path": "src/[auth](x)|file.ts",
                    "line": 7,
                    "column": 1
                }]
            }]
        })
        .to_string(),
    )
    .expect("baseline should be written");
    fs::write(&current_report_path, scan_report_json(&[]).to_string())
        .expect("current report should be written");

    let output = run_sessionscope(&[
        "diff",
        "--baseline",
        baseline_path
            .to_str()
            .expect("baseline path should be UTF-8"),
        "--current",
        current_report_path
            .to_str()
            .expect("current report path should be UTF-8"),
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(!stdout.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    assert!(stdout.contains("\\[REDACTED\\] \\[link\\]\\(x\\)"));
    assert!(stdout.contains("src/[auth](x)|file.ts:7:1"));
}

#[test]
fn baseline_parse_error_does_not_echo_secret_like_report_contents() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("scan.json");
    fs::write(
        &report_path,
        "{\"secret\":\"PLACEHOLDER_SECRET_DO_NOT_USE\",",
    )
    .expect("invalid scan report should be written");

    let output = run_sessionscope(&[
        "baseline",
        "create",
        "--from",
        report_path.to_str().expect("report path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("failed to parse scan report"));
    assert!(!stderr.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
}

#[test]
fn scan_accepts_include_exclude_and_max_file_size() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::create_dir_all(temp.path().join("src")).expect("src dir should be created");
    fs::write(temp.path().join("src/app.ts"), "const app = true;")
        .expect("app source should be written");
    fs::write(temp.path().join("src/app.test.ts"), "const test = true;")
        .expect("test source should be written");
    fs::write(temp.path().join("README.md"), "docs").expect("readme should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--include",
        "src/**/*.ts",
        "--exclude",
        "**/*.test.ts",
        "--max-file-size",
        "1000",
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON should parse");
    assert_eq!(parsed["summary"]["files_scanned"], 1);
    assert_eq!(parsed["summary"]["files_skipped"], 2);
}

#[test]
fn scan_json_runs_builtin_cookie_detector() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("app.ts"),
        r#"response.cookie("session", "PLACEHOLDER_RESET_TOKEN", { signed: true });"#,
    )
    .expect("app source should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON should parse");

    assert_eq!(parsed["schema_version"], "0.5.0");
    let findings = parsed["findings"].as_array().expect("findings array");
    assert!(
        parsed["lifecycle_paths"]
            .as_array()
            .is_some_and(|paths| !paths.is_empty()),
        "scan JSON should include linked lifecycle paths"
    );
    assert!(
        findings.iter().any(|finding| {
            finding["category"] == "high_confidence_misconfiguration"
                && finding["severity"] == "high"
                && finding["title"]
                    .as_str()
                    .expect("finding title")
                    .contains("HttpOnly")
        }),
        "scan JSON should include a high-confidence missing HttpOnly finding"
    );
    let artifacts = parsed["artifacts"].as_array().expect("artifacts array");
    assert!(
        artifacts.iter().any(|artifact| {
            artifact["artifact_type"] == "signed_cookie"
                && artifact["display_name"] == "session"
                && !artifact["lifecycle_evidence"]["store"]
                    .as_array()
                    .expect("store array")
                    .is_empty()
                && artifact["cookie_attributes"]["http_only"]["state"] == "missing"
                && artifact["cookie_attributes"]["path"]["state"] == "framework_default"
        }),
        "scan JSON should include the detected signed session cookie"
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("PLACEHOLDER_RESET_TOKEN"));
}

#[test]
fn cookies_json_filters_to_cookie_capability() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("app.ts"),
        concat!(
            "response.cookie(\"session\", \"PLACEHOLDER_RESET_TOKEN\", { signed: true });\n",
            "const apiKey = \"PLACEHOLDER_API_KEY_DO_NOT_USE\";\n",
            "localStorage.setItem(\"api_key\", apiKey);\n"
        ),
    )
    .expect("app source should be written");

    let output = run_sessionscope(&[
        "cookies",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cookies JSON should parse");
    let artifacts = parsed["artifacts"].as_array().expect("artifacts");
    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact["artifact_type"] == "signed_cookie")
    );
    assert!(
        !artifacts
            .iter()
            .any(|artifact| artifact["artifact_type"] == "api_key")
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("PLACEHOLDER_RESET_TOKEN"));
    assert!(!serialized.contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));
}

#[test]
fn claims_json_filters_to_identity_claim_inventory() {
    let fixture = fixture_path(&["generic-ts", "jwt-validation"]);

    let output = run_sessionscope(&[
        "claims",
        "--path",
        fixture.to_str().expect("fixture path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("claims JSON should parse");
    assert!(
        parsed["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(
                |artifact| artifact["jwt_attributes"]["identity_claims"]["subject"]["state"]
                    == "present"
            )
    );
    assert!(
        parsed["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|evidence| evidence["detector_id"] == "jwt.attribute.subject")
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("has no explicit expiry evidence"));
    assert!(!serialized.contains("does not show signature verification"));
    assert!(!serialized.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
}

#[test]
fn logout_markdown_filters_to_logout_capability() {
    let fixture = fixture_path(&["express", "clear-cookie-only-logout"]);

    let output = run_sessionscope(&[
        "logout",
        "--path",
        fixture.to_str().expect("fixture path should be UTF-8"),
        "--format",
        "markdown",
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("logout.cookie\\_clear") || stdout.contains("logout.cookie_clear"));
    assert!(stdout.contains("cleared on logout"));
    assert!(!stdout.contains("has no explicit expiry evidence"));
    assert!(!stdout.contains("PLACEHOLDER_RESET_TOKEN"));
}

#[test]
fn refresh_json_filters_to_refresh_capability() {
    let fixture = fixture_path(&["express", "refresh-without-rotation"]);

    let output = run_sessionscope(&[
        "refresh",
        "--path",
        fixture.to_str().expect("fixture path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("refresh JSON should parse");
    assert!(
        parsed["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["artifact_type"] == "refresh_jwt"
                || artifact["display_name"]
                    .as_str()
                    .is_some_and(|name| name.contains("refresh")))
    );
    assert!(
        parsed["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding["title"]
                .as_str()
                .is_some_and(|title| title.contains("refresh evidence")))
    );
}

#[test]
fn capability_aliases_reject_unsupported_formats_and_unknown_options() {
    let sarif = run_sessionscope(&["cookies", "--format", "sarif"]);
    assert!(!sarif.status.success());
    assert!(
        str::from_utf8(&sarif.stderr)
            .expect("stderr should be UTF-8")
            .contains("unsupported capability format")
    );

    let github_summary = run_sessionscope(&["refresh", "--format", "github-summary"]);
    assert!(!github_summary.status.success());
    assert!(
        str::from_utf8(&github_summary.stderr)
            .expect("stderr should be UTF-8")
            .contains("unsupported capability format")
    );

    let unknown = run_sessionscope(&["logout", "--typo"]);
    assert!(!unknown.status.success());
    assert!(
        str::from_utf8(&unknown.stderr)
            .expect("stderr should be UTF-8")
            .contains("unknown capability option")
    );
}

#[test]
fn scan_json_runs_builtin_jwt_detector() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("auth.ts"),
        concat!(
            "import jwt from \"jsonwebtoken\";\n",
            "const JWT_SECRET = \"PLACEHOLDER_SECRET_DO_NOT_USE\";\n",
            "export function issueAccessJwt(userId: string, tenantId: string) {\n",
            "  return jwt.sign({ sub: userId, tenant_id: tenantId, email: \"person@example.com\" }, JWT_SECRET, { expiresIn: \"15m\" });\n",
            "}\n",
            "export function verifyAccessJwt(token: string) {\n",
            "  return jwt.verify(token, JWT_SECRET);\n",
            "}\n"
        ),
    )
    .expect("auth source should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON should parse");
    assert_eq!(parsed["schema_version"], "0.5.0");
    assert!(
        parsed["lifecycle_paths"]
            .as_array()
            .is_some_and(|paths| !paths.is_empty()),
        "scan JSON should include linked lifecycle paths"
    );
    assert!(
        parsed["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| {
                artifact["artifact_type"] == "access_jwt"
                    && artifact["jwt_attributes"]["issuer"]["state"] == "missing"
                    && artifact["jwt_attributes"]["audience"]["state"] == "missing"
                    && artifact["jwt_attributes"]["signature_verification"]["state"] == "present"
                    && artifact["jwt_attributes"]["expiry_enforcement"]["state"]
                        == "framework_default"
                    && artifact["jwt_attributes"]["identity_claims"]["subject"]["state"]
                        == "present"
                    && artifact["jwt_attributes"]["identity_claims"]["tenant_id"]["state"]
                        == "present"
                    && artifact["jwt_attributes"]["identity_claims"]["email"]["value"]
                        == "[literal]"
            })
    );
    assert!(
        parsed["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| {
                finding["category"] == "missing_validation_evidence"
                    && finding["title"]
                        .as_str()
                        .expect("finding title")
                        .contains("issuer")
            })
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    assert!(!serialized.contains("person@example.com"));
}

#[test]
fn scan_json_runs_builtin_bearer_detector() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("tokens.ts"),
        concat!(
            "const API_KEY = \"PLACEHOLDER_API_KEY_DO_NOT_USE\";\n",
            "export async function callApi(accessToken: string) {\n",
            "  localStorage.setItem(\"api_key\", API_KEY);\n",
            "  return fetch(`/callback?access_token=${accessToken}`, { headers: { \"X-API-Key\": API_KEY } });\n",
            "}\n"
        ),
    )
    .expect("token source should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
    ]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON should parse");
    assert_eq!(parsed["schema_version"], "0.5.0");
    assert!(
        parsed["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["artifact_type"] == "api_key"
                && artifact["display_name"] == "api_key")
    );
    assert!(
        parsed["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| {
                finding["category"] == "high_confidence_misconfiguration"
                    && finding["title"]
                        .as_str()
                        .expect("finding title")
                        .contains("browser storage")
            })
    );
    let serialized = String::from_utf8_lossy(&output.stdout);
    assert!(!serialized.contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));
}

#[test]
fn scan_json_output_writes_file_without_stdout_inventory() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("app.ts"),
        r#"response.cookie("session", "PLACEHOLDER_RESET_TOKEN", { signed: true });"#,
    )
    .expect("app source should be written");
    let output_path = temp.path().join("sessions.json");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
        "--output",
        output_path.to_str().expect("output path should be UTF-8"),
    ]);

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "--output should not echo inventory JSON to stdout"
    );
    let written = fs::read_to_string(output_path).expect("JSON output should be written");
    let parsed: serde_json::Value =
        serde_json::from_str(&written).expect("written scan JSON should parse");
    assert_eq!(parsed["schema_version"], "0.5.0");
    assert!(
        parsed["artifacts"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert!(!written.contains("PLACEHOLDER_RESET_TOKEN"));
}

#[test]
fn scan_json_output_write_failure_includes_path_context() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(temp.path().join("app.ts"), "const app = true;")
        .expect("app source should be written");
    let output_path = temp.path().join("missing").join("sessions.json");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "json",
        "--output",
        output_path.to_str().expect("output path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("failed to write scan output"));
    assert!(stderr.contains("sessions.json"));
}

#[test]
fn scan_markdown_stdout_renders_lifecycle_report_for_cookie_fixture() {
    let fixture = fixture_path(&["express", "cookie-session-lifecycle"]);

    let output = run_sessionscope(&[
        "scan",
        "--path",
        fixture.to_str().expect("fixture path should be UTF-8"),
        "--format",
        "markdown",
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("# SessionScope Report"));
    assert!(stdout.contains("## Findings"));
    assert!(stdout.contains("## Lifecycle Paths"));
    assert!(stdout.contains("## Artifacts"));
    assert!(stdout.contains("### `session_cookie`"));
    assert!(stdout.contains("Category: `high_confidence_misconfiguration`"));
    assert!(stdout.contains("| Stage | Evidence ID | Location | Confidence | Detector | Dynamic | Framework default | Excerpt |"));
    assert!(stdout.contains("**Suggested fix:**"));
    assert!(stdout.contains("**Reviewer question:**"));
    assert!(!stdout.contains("PLACEHOLDER_RESET_TOKEN"));
    assert!(!stdout.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
}

#[test]
fn scan_markdown_stdout_renders_jwt_identity_claims() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("auth.ts"),
        concat!(
            "import jwt from \"jsonwebtoken\";\n",
            "const JWT_SECRET = \"PLACEHOLDER_SECRET_DO_NOT_USE\";\n",
            "export function issueAccessJwt(userId: string) {\n",
            "  return jwt.sign({ sub: userId, scope: \"read:sessions\", email: \"person@example.com\" }, JWT_SECRET, { expiresIn: \"15m\" });\n",
            "}\n"
        ),
    )
    .expect("auth source should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "markdown",
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    assert!(stdout.contains("| JWT identity claim | State | Value | Confidence | Evidence |"));
    assert!(stdout.contains("| Subject | `present` | userId | `high` | 1 |"));
    assert!(stdout.contains("| Scopes | `present` | \\[literal\\] | `high` | 1 |"));
    assert!(!stdout.contains("person@example.com"));
    assert!(!stdout.contains("read:sessions"));
    assert!(!stdout.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
}

#[test]
fn scan_markdown_output_writes_file_without_stdout_report() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let fixture = fixture_path(&["express", "cookie-session-lifecycle"]);
    let output_path = temp.path().join("sessions.md");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        fixture.to_str().expect("fixture path should be UTF-8"),
        "--format",
        "markdown",
        "--output",
        output_path.to_str().expect("output path should be UTF-8"),
    ]);

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "--output should not echo Markdown report to stdout"
    );
    let written = fs::read_to_string(output_path).expect("Markdown output should be written");
    assert!(written.contains("# SessionScope Report"));
    assert!(written.contains("## Findings"));
    assert!(written.contains("## Artifacts"));
    assert!(written.contains("legacy_session"));
    assert!(!written.contains("PLACEHOLDER_RESET_TOKEN"));
}

#[test]
fn scan_sarif_renders_findings_and_locations() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("app.ts"),
        r#"response.cookie("session", "PLACEHOLDER_RESET_TOKEN", { sameSite: "none" });"#,
    )
    .expect("app source should be written");

    let output = run_sessionscope(&[
        "scan",
        "--path",
        temp.path().to_str().expect("temp path should be UTF-8"),
        "--format",
        "sarif",
    ]);

    assert!(output.status.success());
    let stdout = str::from_utf8(&output.stdout).expect("stdout should be UTF-8");
    let parsed: serde_json::Value =
        serde_json::from_str(stdout).expect("SARIF output should parse");
    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    let results = parsed["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(!rules.is_empty(), "SARIF should include finding rules");
    assert!(!results.is_empty(), "SARIF should include finding results");
    assert_eq!(parsed["version"], "2.1.0");
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app.ts"
    );
    assert!(!stdout.contains("PLACEHOLDER_RESET_TOKEN"));
}

#[test]
fn scan_rejects_invalid_max_file_size() {
    let output = run_sessionscope(&["scan", "--max-file-size", "0"]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("max file size"));
}

#[test]
fn init_creates_documented_config() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let output = run_sessionscope_in(temp.path(), &["init"]);

    assert!(output.status.success());
    let config = fs::read_to_string(temp.path().join("sessionscope.toml"))
        .expect("config should be created");
    assert!(config.contains("scan_paths"));
    assert!(config.contains("include"));
    assert!(config.contains("exclude"));
    assert!(config.contains("formats"));
    assert!(config.contains("mode = \"advisory\""));
    assert!(config.contains("framework_hints"));
    assert!(config.contains("provider_hints"));
    assert!(!config.contains("PLACEHOLDER_SECRET"));
}

#[test]
fn init_protects_existing_config_unless_forced() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("sessionscope.toml");
    fs::write(&config_path, "mode = \"enforce\"\n").expect("config should be written");

    let output = run_sessionscope_in(temp.path(), &["init"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(&config_path).expect("config should remain readable"),
        "mode = \"enforce\"\n"
    );

    let forced = run_sessionscope_in(temp.path(), &["init", "--force"]);
    assert!(forced.status.success());
    let config = fs::read_to_string(config_path).expect("config should be overwritten");
    assert!(config.contains("scan_paths"));
    assert!(config.contains("mode = \"advisory\""));
}

#[test]
fn init_rejects_unknown_options() {
    let temp = tempfile::tempdir().expect("tempdir should be created");

    let output = run_sessionscope_in(temp.path(), &["init", "--typo"]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("unknown init option"));
    assert!(!temp.path().join("sessionscope.toml").exists());
}

#[test]
fn scan_uses_project_config_defaults() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::create_dir_all(temp.path().join("src")).expect("src dir should be created");
    fs::write(temp.path().join("src/app.ts"), "const app = true;")
        .expect("app source should be written");
    fs::write(temp.path().join("src/app.skip.ts"), "const skip = true;")
        .expect("skip source should be written");
    fs::write(
        temp.path().join("sessionscope.toml"),
        concat!(
            "scan_paths = [\"src\"]\n",
            "include = [\"**/*.ts\"]\n",
            "exclude = [\"**/*.skip.ts\"]\n",
            "formats = [\"json\"]\n",
            "mode = \"advisory\"\n",
            "max_file_size_bytes = 1000\n",
            "framework_hints = [\"express\"]\n",
            "provider_hints = []\n",
        ),
    )
    .expect("config should be written");

    let output = run_sessionscope_in(temp.path(), &["scan"]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("configured scan JSON should parse");
    assert_eq!(parsed["summary"]["files_scanned"], 1);
    assert_eq!(parsed["summary"]["files_skipped"], 1);
}

#[test]
fn scan_cli_flags_override_config_values() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::create_dir_all(temp.path().join("config-src")).expect("config dir should be created");
    fs::create_dir_all(temp.path().join("cli-src")).expect("cli dir should be created");
    fs::write(temp.path().join("config-src/app.py"), "print('config')")
        .expect("config source should be written");
    fs::write(temp.path().join("cli-src/app.ts"), "const cli = true;")
        .expect("cli source should be written");
    fs::write(
        temp.path().join("sessionscope.toml"),
        concat!(
            "scan_paths = [\"config-src\"]\n",
            "include = [\"**/*.py\"]\n",
            "formats = [\"markdown\"]\n",
            "mode = \"enforce\"\n",
            "max_file_size_bytes = 4\n",
        ),
    )
    .expect("config should be written");

    let output = run_sessionscope_in(
        temp.path(),
        &[
            "scan",
            "--path",
            "cli-src",
            "--include",
            "**/*.ts",
            "--max-file-size",
            "1000",
            "--format",
            "json",
        ],
    );

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("override scan JSON should parse");
    assert_eq!(parsed["summary"]["files_scanned"], 1);
    assert_eq!(parsed["files"][0]["path"], "app.ts");
}

#[test]
fn scan_cli_exclude_appends_to_config_excludes() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::create_dir_all(temp.path().join("src")).expect("src dir should be created");
    fs::write(temp.path().join("src/app.ts"), "const app = true;")
        .expect("app source should be written");
    fs::write(temp.path().join("src/app.skip.ts"), "const skip = true;")
        .expect("skip source should be written");
    fs::write(temp.path().join("src/app.cli.ts"), "const cli = true;")
        .expect("cli source should be written");
    fs::write(
        temp.path().join("sessionscope.toml"),
        concat!(
            "scan_paths = [\"src\"]\n",
            "include = [\"**/*.ts\"]\n",
            "exclude = [\"**/*.skip.ts\"]\n",
            "formats = [\"json\"]\n",
        ),
    )
    .expect("config should be written");

    let output = run_sessionscope_in(temp.path(), &["scan", "--exclude", "**/*.cli.ts"]);

    assert!(output.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("append exclude scan JSON should parse");
    assert_eq!(parsed["summary"]["files_scanned"], 1);
    assert_eq!(parsed["summary"]["files_skipped"], 2);
}

#[test]
fn scan_rejects_invalid_project_config() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(temp.path().join("sessionscope.toml"), "mode = \"block\"\n")
        .expect("config should be written");

    let output = run_sessionscope_in(temp.path(), &["scan"]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("invalid sessionscope.toml"));
}

#[test]
fn scan_invalid_toml_error_does_not_echo_secret_values() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    fs::write(
        temp.path().join("sessionscope.toml"),
        "client_secret = \"super-secret-value\n",
    )
    .expect("config should be written");

    let output = run_sessionscope_in(temp.path(), &["scan"]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("invalid sessionscope.toml"));
    assert!(stderr.contains("line 1"));
    assert!(!stderr.contains("client_secret"));
    assert!(!stderr.contains("super-secret-value"));
}

fn scan_report_json(findings: &[serde_json::Value]) -> serde_json::Value {
    let evidence = findings
        .iter()
        .map(|finding| {
            let evidence_id = finding["evidence_ids"][0]
                .as_str()
                .expect("test finding should contain evidence ID");
            let line = finding["test_line"]
                .as_u64()
                .expect("test finding should contain line");
            serde_json::json!({
                "id": evidence_id,
                "lifecycle_stage": "validate",
                "location": {
                    "path": "src/auth.ts",
                    "line": line,
                    "column": 1
                },
                "detector_id": "test.detector",
                "confidence": "high",
                "excerpt": format!("evidence for {}", finding["title"].as_str().expect("title")),
                "dynamic": false,
                "framework_default": false
            })
        })
        .collect::<Vec<_>>();
    let mut clean_findings = findings.to_vec();
    for finding in &mut clean_findings {
        finding
            .as_object_mut()
            .expect("finding should be object")
            .remove("test_line");
    }

    serde_json::json!({
        "schema_version": "0.5.0",
        "summary": {
            "files_discovered": 1,
            "files_scanned": 1,
            "files_skipped": 0,
            "diagnostics": []
        },
        "files": [],
        "artifacts": [],
        "evidence": evidence,
        "lifecycle_paths": [],
        "findings": clean_findings
    })
}

fn finding_json(
    id: &str,
    title: &str,
    description: &str,
    evidence_id: &str,
    line: u64,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "category": "lifecycle_gap",
        "severity": "medium",
        "artifact_ids": [],
        "evidence_ids": [evidence_id],
        "title": title,
        "description": description,
        "suggested_fix": null,
        "reviewer_question": null,
        "test_line": line
    })
}
