use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExpectedFixture {
    pub fixture_id: String,
    pub framework: String,
    pub source_files: Vec<String>,
    pub expected_artifacts: Vec<String>,
    pub expected_lifecycle_stages: Vec<String>,
    pub expected_findings: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureCase {
    pub root: PathBuf,
    pub expected_path: PathBuf,
    pub expected: ExpectedFixture,
}

pub fn fixture_path(root: &Path, segments: &[&str]) -> PathBuf {
    segments
        .iter()
        .fold(root.to_path_buf(), |mut path, segment| {
            path.push(segment);
            path
        })
}

pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

pub fn fixture_cases() -> io::Result<Vec<FixtureCase>> {
    let root = fixture_root();
    let mut cases = Vec::new();

    for family in fs::read_dir(root)? {
        let family = family?;
        if !family.file_type()?.is_dir() {
            continue;
        }

        for case in fs::read_dir(family.path())? {
            let case = case?;
            if !case.file_type()?.is_dir() {
                continue;
            }

            let case_root = case.path();
            let expected_path = case_root.join("expected.json");
            let expected = load_expected_fixture(&expected_path)?;

            cases.push(FixtureCase {
                root: case_root,
                expected_path,
                expected,
            });
        }
    }

    cases.sort_by(|left, right| left.expected.fixture_id.cmp(&right.expected.fixture_id));
    Ok(cases)
}

pub fn load_expected_fixture(path: &Path) -> io::Result<ExpectedFixture> {
    let contents = fs::read_to_string(path)?;
    serde_json::from_str(&contents)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

pub fn fixture_source_text(case: &FixtureCase) -> io::Result<Vec<(String, String)>> {
    case.expected
        .source_files
        .iter()
        .map(|source_file| {
            let text = fs::read_to_string(case.root.join(source_file))?;
            Ok((source_file.clone(), text))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sessionscope_core::{ScanConfig, scan_path};
    use sessionscope_detectors::DetectorRegistry;
    use sessionscope_model::{ArtifactType, SkippedReason};

    use super::{fixture_cases, fixture_root, fixture_source_text};

    const PLACEHOLDER_JWT: &str = "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
    const ALLOWED_PLACEHOLDERS: &[&str] = &[
        PLACEHOLDER_JWT,
        "PLACEHOLDER_SECRET_DO_NOT_USE",
        "PLACEHOLDER_RESET_TOKEN",
        "PLACEHOLDER_RESET_TOKEN_ROTATED",
    ];

    #[test]
    fn fixture_cases_have_expected_metadata_and_sources() {
        let cases = fixture_cases().expect("fixture cases should load");

        assert!(
            cases.len() >= 6,
            "expected at least one case for each fixture family"
        );

        for case in cases {
            assert!(
                case.expected_path.exists(),
                "{} should have expected.json",
                case.expected.fixture_id
            );
            assert!(!case.expected.fixture_id.is_empty());
            assert!(!case.expected.framework.is_empty());
            assert!(!case.expected.notes.is_empty());
            assert!(!case.expected.source_files.is_empty());
            assert!(
                !case.expected.expected_artifacts.is_empty()
                    || !case.expected.expected_lifecycle_stages.is_empty()
                    || !case.expected.expected_findings.is_empty(),
                "{} should include at least one expectation",
                case.expected.fixture_id
            );

            for source_file in &case.expected.source_files {
                assert!(
                    case.root.join(source_file).exists(),
                    "{} references missing source file {}",
                    case.expected.fixture_id,
                    source_file
                );
            }
        }
    }

    #[test]
    fn fixture_cases_scan_with_empty_detector_registry() {
        for case in fixture_cases().expect("fixture cases should load") {
            let report = scan_path(
                ScanConfig::new(&case.root),
                Arc::new(DetectorRegistry::empty()),
            )
            .unwrap_or_else(|error| panic!("{} should scan: {error}", case.expected.fixture_id));

            assert!(
                report.summary.files_scanned > 0,
                "{} should scan at least one supported file",
                case.expected.fixture_id
            );

            for file in report.files {
                if let Some(reason) = file.skipped_reason {
                    assert!(
                        matches!(
                            reason,
                            SkippedReason::Excluded
                                | SkippedReason::Unsupported
                                | SkippedReason::TooLarge
                                | SkippedReason::Binary
                                | SkippedReason::SensitivePath
                                | SkippedReason::Ignored
                        ),
                        "{} should only expose non-sensitive skip reasons",
                        case.expected.fixture_id
                    );
                }
            }
        }
    }

    #[test]
    fn cookie_fixtures_scan_with_builtin_cookie_detector() {
        let cases = [
            (
                fixture_root()
                    .join("express")
                    .join("cookie-session-lifecycle"),
                vec![
                    (Some("session"), ArtifactType::SignedCookie),
                    (Some("legacy_session"), ArtifactType::SessionCookie),
                    (Some("refresh_token"), ArtifactType::Unknown),
                ],
            ),
            (
                fixture_root()
                    .join("fastapi")
                    .join("dependency-auth-lifecycle"),
                vec![(Some("session"), ArtifactType::SessionCookie)],
            ),
        ];

        for (root, expected_artifacts) in cases {
            let report = scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display()));

            assert!(
                report.findings.is_empty(),
                "cookie detector should not classify risk in {}",
                root.display()
            );

            for (display_name, artifact_type) in expected_artifacts {
                assert!(
                    report.artifacts.iter().any(|artifact| {
                        artifact.display_name.as_deref() == display_name
                            && artifact.artifact_type == artifact_type
                            && !artifact.lifecycle_evidence.store.is_empty()
                    }),
                    "{} should include {artifact_type:?} named {display_name:?}",
                    root.display()
                );
            }
        }
    }

    #[test]
    fn fixture_sources_use_only_obvious_placeholder_secrets() {
        for case in fixture_cases().expect("fixture cases should load") {
            for (path, text) in fixture_source_text(&case).expect("source text should load") {
                assert!(
                    !contains_banned_secret_marker(&text),
                    "{} contains a banned secret marker in {}",
                    case.expected.fixture_id,
                    path
                );
                assert!(
                    !contains_unlabelled_token_like_value(&text),
                    "{} contains an unlabelled token-like value in {}",
                    case.expected.fixture_id,
                    path
                );
            }
        }
    }

    #[test]
    fn placeholder_token_values_are_labelled() {
        let mut saw_placeholder_jwt = false;

        for case in fixture_cases().expect("fixture cases should load") {
            for (_, text) in fixture_source_text(&case).expect("source text should load") {
                if text.contains(PLACEHOLDER_JWT) {
                    saw_placeholder_jwt = true;
                    assert!(text.contains("PLACEHOLDER"));
                }
            }
        }

        assert!(
            saw_placeholder_jwt,
            "fixture corpus should include placeholder JWT values"
        );
    }

    fn contains_banned_secret_marker(text: &str) -> bool {
        [
            "BEGIN PRIVATE KEY",
            "AKIA",
            "ghp_",
            "xoxb-",
            "sk_live_",
            "sk_test_",
        ]
        .iter()
        .any(|marker| text.contains(marker))
    }

    fn contains_unlabelled_token_like_value(text: &str) -> bool {
        text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'))
            .filter(|part| part.len() >= 32)
            .any(|part| {
                !ALLOWED_PLACEHOLDERS
                    .iter()
                    .any(|allowed| part.contains(allowed))
                    && !part.contains("PLACEHOLDER")
            })
    }
}
