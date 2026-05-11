use std::process::Command;
use std::{fs, str};

fn run_sessionscope(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .args(args)
        .output()
        .expect("failed to run sessionscope")
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
fn scan_rejects_invalid_max_file_size() {
    let output = run_sessionscope(&["scan", "--max-file-size", "0"]);

    assert!(!output.status.success());
    let stderr = str::from_utf8(&output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("max file size"));
}
