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
        "sessionscope explain",
        "sessionscope baseline create",
        "sessionscope diff",
        "sessionscope version",
    ] {
        assert!(stdout.contains(command), "help output missing {command}");
    }
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
fn explain_scaffold_does_not_echo_finding_id() {
    let sensitive_finding_id = "aaa.bbb.cccccccccccccccccccccc";
    let output = run_sessionscope(&["explain", sensitive_finding_id]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("explain is scaffolded"));
    assert!(!stdout.contains(sensitive_finding_id));
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

    assert_eq!(parsed["schema_version"], "0.2.0");
    let findings = parsed["findings"].as_array().expect("findings array");
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
    assert_eq!(parsed["schema_version"], "0.2.0");
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
