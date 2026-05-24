use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::json;

#[derive(Clone, Copy)]
struct FindingSpec {
    id: &'static str,
    severity: &'static str,
    category: &'static str,
}

const HIGH_LIFECYCLE: FindingSpec = FindingSpec {
    id: "finding_high_lifecycle",
    severity: "high",
    category: "lifecycle_gap",
};
const MEDIUM_MISSING: FindingSpec = FindingSpec {
    id: "finding_medium_missing",
    severity: "medium",
    category: "missing_validation_evidence",
};
const LOW_DYNAMIC: FindingSpec = FindingSpec {
    id: "finding_low_dynamic",
    severity: "low",
    category: "dynamic_review_required",
};
const INFO_FRAMEWORK: FindingSpec = FindingSpec {
    id: "finding_info_framework",
    severity: "info",
    category: "framework_default_assumed",
};

#[test]
fn documented_exit_code_policy_matrix() {
    let cases = [
        MatrixCase {
            name: "advisory mode ignores findings",
            findings: &[HIGH_LIFECYCLE],
            args: &["--mode", "advisory"],
            expect_success: true,
        },
        MatrixCase {
            name: "enforce default blocks high findings",
            findings: &[HIGH_LIFECYCLE],
            args: &["--mode", "enforce"],
            expect_success: false,
        },
        MatrixCase {
            name: "enforce default allows lower severities",
            findings: &[MEDIUM_MISSING, LOW_DYNAMIC, INFO_FRAMEWORK],
            args: &["--mode", "enforce"],
            expect_success: true,
        },
        MatrixCase {
            name: "fail severity medium blocks medium",
            findings: &[MEDIUM_MISSING],
            args: &["--mode", "enforce", "--fail-severity", "medium"],
            expect_success: false,
        },
        MatrixCase {
            name: "fail severity low blocks low",
            findings: &[LOW_DYNAMIC],
            args: &["--mode", "enforce", "--fail-severity", "low"],
            expect_success: false,
        },
        MatrixCase {
            name: "fail severity info blocks info",
            findings: &[INFO_FRAMEWORK],
            args: &["--mode", "enforce", "--fail-severity", "info"],
            expect_success: false,
        },
        MatrixCase {
            name: "category filter excludes nonmatching category",
            findings: &[HIGH_LIFECYCLE],
            args: &[
                "--mode",
                "enforce",
                "--fail-category",
                "missing_validation_evidence",
            ],
            expect_success: true,
        },
        MatrixCase {
            name: "category filter accepts comma-separated categories",
            findings: &[INFO_FRAMEWORK],
            args: &[
                "--mode",
                "enforce",
                "--fail-severity",
                "info",
                "--fail-category",
                "dynamic_review_required,framework_default_assumed",
            ],
            expect_success: false,
        },
        MatrixCase {
            name: "empty category filter behaves like no category filter",
            findings: &[HIGH_LIFECYCLE],
            args: &["--mode", "enforce", "--fail-category", ""],
            expect_success: false,
        },
        MatrixCase {
            name: "include finding id blocks below threshold",
            findings: &[LOW_DYNAMIC],
            args: &[
                "--mode",
                "enforce",
                "--include-finding-id",
                "finding_low_dynamic",
            ],
            expect_success: false,
        },
        MatrixCase {
            name: "exclude finding id wins over include",
            findings: &[HIGH_LIFECYCLE],
            args: &[
                "--mode",
                "enforce",
                "--include-finding-id",
                "finding_high_lifecycle",
                "--exclude-finding-id",
                "finding_high_lifecycle",
            ],
            expect_success: true,
        },
    ];

    for case in cases {
        run_matrix_case(case);
    }
}

#[test]
fn baseline_suppression_and_include_precedence_are_documented() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("report.json");
    let baseline_path = temp.path().join("baseline.json");
    write_report(&report_path, &[HIGH_LIFECYCLE]);
    write_report(&baseline_path, &[HIGH_LIFECYCLE]);

    let suppressed = run_sessionscope_in(
        temp.path(),
        &[
            "evaluate",
            report_path.to_str().expect("path should be UTF-8"),
            "--no-policy-config",
            "--mode",
            "enforce",
            "--baseline",
            baseline_path.to_str().expect("path should be UTF-8"),
        ],
    );
    assert!(
        suppressed.status.success(),
        "baseline should suppress matching high finding: {}",
        String::from_utf8_lossy(&suppressed.stderr)
    );

    let included = run_sessionscope_in(
        temp.path(),
        &[
            "evaluate",
            report_path.to_str().expect("path should be UTF-8"),
            "--no-policy-config",
            "--mode",
            "enforce",
            "--baseline",
            baseline_path.to_str().expect("path should be UTF-8"),
            "--include-finding-id",
            "finding_high_lifecycle",
        ],
    );
    assert!(
        !included.status.success(),
        "include-finding-id should block unless excluded, even when baseline matches"
    );
}

struct MatrixCase {
    name: &'static str,
    findings: &'static [FindingSpec],
    args: &'static [&'static str],
    expect_success: bool,
}

fn run_matrix_case(case: MatrixCase) {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let report_path = temp.path().join("report.json");
    write_report(&report_path, case.findings);

    let mut args = vec![
        "evaluate".to_string(),
        report_path
            .to_str()
            .expect("path should be UTF-8")
            .to_string(),
        "--no-policy-config".to_string(),
    ];
    args.extend(case.args.iter().map(|arg| arg.to_string()));
    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run_sessionscope_in(temp.path(), &borrowed);

    assert_eq!(
        output.status.success(),
        case.expect_success,
        "{}: stdout={} stderr={}",
        case.name,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_report(path: &Path, findings: &[FindingSpec]) {
    let findings = findings
        .iter()
        .map(|finding| {
            json!({
                "id": finding.id,
                "category": finding.category,
                "severity": finding.severity,
                "artifact_ids": [],
                "evidence_ids": [],
                "title": format!("{} {}", finding.severity, finding.category),
                "description": "policy matrix fixture",
                "suggested_fix": null,
                "reviewer_question": null
            })
        })
        .collect::<Vec<_>>();
    let report = json!({
        "schema_version": "0.5.0",
        "summary": {
            "files_discovered": 0,
            "files_scanned": 0,
            "files_skipped": 0,
            "diagnostics": [],
            "worker_panic_count": 0
        },
        "files": [],
        "artifacts": [],
        "evidence": [],
        "lifecycle_paths": [],
        "findings": findings
    });
    fs::write(
        path,
        serde_json::to_string_pretty(&report).expect("report serializes"),
    )
    .expect("report should be written");
}

fn run_sessionscope_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sessionscope"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to run sessionscope")
}
