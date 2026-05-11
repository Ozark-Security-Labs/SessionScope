use std::process::Command;

#[test]
fn help_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .arg("--help")
        .output()
        .expect("failed to run sessionscope --help");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sessionscope scan"));
}

#[test]
fn version_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .arg("version")
        .output()
        .expect("failed to run sessionscope version");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sessionscope"));
}
