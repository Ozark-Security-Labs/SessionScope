use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sessionscope_classifier::classify;
use sessionscope_core::{ScanConfig, scan_path};
use sessionscope_detectors::DetectorRegistry;
use sessionscope_reporters::{ReportFormat, render};
use sessionscope_testing::fixtures::fixture_root;
use sessionscope_testing::snapshots::normalize_snapshot_paths;

const SNAPSHOT_CASES: &[SnapshotCase] = &[
    SnapshotCase {
        name: "express-cookie-session-lifecycle",
        fixture_segments: &["express", "cookie-session-lifecycle"],
    },
    SnapshotCase {
        name: "nextjs-route-handler-auth",
        fixture_segments: &["nextjs", "route-handler-auth"],
    },
    SnapshotCase {
        name: "fastapi-dependency-auth-lifecycle",
        fixture_segments: &["fastapi", "dependency-auth-lifecycle"],
    },
    SnapshotCase {
        name: "django-session-and-reset-flow",
        fixture_segments: &["django", "session-and-reset-flow"],
    },
    SnapshotCase {
        name: "generic-js-jwt-crypto-trust-alg-none",
        fixture_segments: &["generic-js", "jwt-crypto-trust-alg-none"],
    },
    SnapshotCase {
        name: "generic-ts-jwt-validation",
        fixture_segments: &["generic-ts", "jwt-validation"],
    },
    SnapshotCase {
        name: "generic-python-jwt-and-reset",
        fixture_segments: &["generic-python", "jwt-and-reset"],
    },
];

struct SnapshotCase {
    name: &'static str,
    fixture_segments: &'static [&'static str],
}

#[test]
fn json_snapshots_match_representative_framework_fixtures() {
    let update = std::env::var_os("SESSIONSCOPE_UPDATE_JSON_SNAPSHOTS").is_some();
    let snapshot_root = snapshot_root();

    for case in SNAPSHOT_CASES {
        let rendered = render_snapshot(case);
        let snapshot_path = snapshot_root.join(format!("{}.json", case.name));

        if update {
            fs::write(&snapshot_path, &rendered).unwrap_or_else(|error| {
                panic!("failed to update {}: {error}", snapshot_path.display())
            });
            continue;
        }

        let expected = fs::read_to_string(&snapshot_path).unwrap_or_else(|error| {
            panic!(
                "failed to read snapshot {}: {error}",
                snapshot_path.display()
            )
        });
        assert_eq!(
            normalize_snapshot_paths(&expected),
            normalize_snapshot_paths(&rendered),
            "JSON snapshot mismatch for {}; regenerate with `SESSIONSCOPE_UPDATE_JSON_SNAPSHOTS=1 cargo test -p sessionscope-testing --test json_snapshots`",
            case.name
        );
    }
}

fn render_snapshot(case: &SnapshotCase) -> String {
    let root = case
        .fixture_segments
        .iter()
        .fold(fixture_root(), |path, segment| path.join(segment));
    let report = classify(
        scan_path(
            ScanConfig::new(&root),
            Arc::new(DetectorRegistry::builtin()),
        )
        .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
    );
    render(&report, ReportFormat::Json)
}

fn snapshot_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("integration")
        .join("snapshots")
}
