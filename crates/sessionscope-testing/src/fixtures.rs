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

    use sessionscope_classifier::classify;
    use sessionscope_core::{ScanConfig, scan_path};
    use sessionscope_detectors::DetectorRegistry;
    use sessionscope_model::{
        ArtifactType, FindingCategory, LifecycleStage, Severity, SkippedReason,
    };
    use sessionscope_reporters::{ReportFormat, render};

    use crate::snapshots::normalize_snapshot_paths;

    use super::{fixture_cases, fixture_root, fixture_source_text};

    const PLACEHOLDER_JWT: &str = "PLACEHOLDER_HEADER.PLACEHOLDER_PAYLOAD.PLACEHOLDER_SIGNATURE";
    const ALLOWED_PLACEHOLDERS: &[&str] = &[
        PLACEHOLDER_JWT,
        "PLACEHOLDER_SECRET_DO_NOT_USE",
        "PLACEHOLDER_RESET_TOKEN",
        "PLACEHOLDER_RESET_TOKEN_ROTATED",
        "PLACEHOLDER_API_KEY_DO_NOT_USE",
        "PLACEHOLDER_SERVICE_TOKEN_DO_NOT_USE",
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
    fn issue_18_framework_fixtures_emit_documented_coverage() {
        let cases = [
            (
                fixture_root().join("nextjs").join("nextresponse-session"),
                "nextjs",
                [
                    "cookie.set",
                    "jwt.validate",
                    "logout.cookie_clear",
                    "refresh.rotate",
                ],
            ),
            (
                fixture_root().join("express").join("session-middleware"),
                "express",
                [
                    "cookie.set",
                    "session.regenerate",
                    "logout.session_destroy",
                    "refresh.revoke",
                ],
            ),
            (
                fixture_root().join("fastapi").join("security-dependencies"),
                "fastapi",
                [
                    "cookie.set",
                    "fastapi.security_dependency",
                    "logout.cookie_clear",
                    "refresh.revoke",
                ],
            ),
            (
                fixture_root().join("django").join("settings-session-auth"),
                "django",
                [
                    "cookie.set",
                    "session.regenerate",
                    "logout.session_destroy",
                    "refresh.revoke",
                ],
            ),
        ];

        for (root, framework, detector_ids) in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            assert!(
                report.artifacts.iter().any(|artifact| artifact
                    .framework_hints
                    .iter()
                    .any(|hint| hint == framework)),
                "{} should include {framework} framework hints",
                root.display()
            );
            for detector_id in detector_ids {
                assert!(
                    report
                        .evidence
                        .iter()
                        .any(|evidence| evidence.detector_id == detector_id),
                    "{} should include {detector_id} evidence",
                    root.display()
                );
            }
            assert!(report.evidence.iter().any(|evidence| {
                matches!(
                    evidence.lifecycle_stage,
                    LifecycleStage::Store | LifecycleStage::Validate | LifecycleStage::Revoke
                )
            }));

            for format in [
                ReportFormat::Json,
                ReportFormat::Markdown,
                ReportFormat::Sarif,
            ] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
                assert!(!rendered.contains("PLACEHOLDER_RESET_TOKEN"));
                assert!(!rendered.contains("PLACEHOLDER_RESET_TOKEN_ROTATED"));
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
                            && artifact.cookie_attributes.is_some()
                    }),
                    "{} should include {artifact_type:?} named {display_name:?}",
                    root.display()
                );
            }
        }
    }

    #[test]
    fn express_cookie_fixture_classifies_legacy_cookie_findings() {
        let root = fixture_root()
            .join("express")
            .join("cookie-session-lifecycle");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("express cookie fixture should scan"),
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("legacy_session")
                && finding.title.contains("HttpOnly")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("legacy_session")
                && finding.title.contains("Secure")
        }));
    }

    #[test]
    fn expanded_cookie_posture_fixtures_emit_findings_and_safe_reports() {
        let cases = [
            fixture_root()
                .join("express")
                .join("cookie-posture-expanded"),
            fixture_root()
                .join("fastapi")
                .join("cookie-posture-expanded"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            for artifact_name in ["legacy_session", "cross_site_session", "header_session"] {
                assert!(
                    report.artifacts.iter().any(|artifact| {
                        artifact.display_name.as_deref() == Some(artifact_name)
                            && artifact.cookie_attributes.is_some()
                    }),
                    "{} should include cookie artifact {artifact_name}",
                    root.display()
                );
            }

            for title_part in [
                "excessive Max-Age",
                "broad Domain",
                "broad Path",
                "does not set SameSite",
                "SameSite=None",
                "dynamic",
            ] {
                assert!(
                    report.findings.iter().any(|finding| {
                        finding.title.contains(title_part)
                            && finding.reviewer_question.is_some()
                            && !finding.evidence_ids.is_empty()
                    }),
                    "{} should include expanded cookie finding containing {title_part:?}",
                    root.display()
                );
            }

            if root.to_string_lossy().contains("express") {
                assert!(report.findings.iter().any(|finding| {
                    finding.title.contains("browser storage")
                        && finding.category == FindingCategory::HighConfidenceMisconfiguration
                }));
            }

            for format in [
                ReportFormat::Json,
                ReportFormat::Markdown,
                ReportFormat::Sarif,
            ] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("PLACEHOLDER_RESET_TOKEN"));
                assert!(rendered.contains("cookie"));
            }
        }
    }

    #[test]
    fn jwt_fixtures_scan_with_builtin_jwt_detector() {
        let cases = [
            (
                fixture_root().join("generic-ts").join("jwt-validation"),
                vec![
                    (Some("access_jwt"), ArtifactType::AccessJwt),
                    (Some("legacy_access_jwt"), ArtifactType::AccessJwt),
                ],
            ),
            (
                fixture_root().join("generic-python").join("jwt-and-reset"),
                vec![
                    (Some("access_jwt"), ArtifactType::AccessJwt),
                    (Some("legacy_access_jwt"), ArtifactType::AccessJwt),
                ],
            ),
            (
                fixture_root().join("nextjs").join("route-handler-auth"),
                vec![(Some("access_jwt"), ArtifactType::AccessJwt)],
            ),
            (
                fixture_root()
                    .join("fastapi")
                    .join("dependency-auth-lifecycle"),
                vec![(Some("access_jwt"), ArtifactType::AccessJwt)],
            ),
        ];

        for (root, expected_artifacts) in cases {
            let report = scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display()));

            for (display_name, artifact_type) in expected_artifacts {
                assert!(
                    report.artifacts.iter().any(|artifact| {
                        artifact.display_name.as_deref() == display_name
                            && artifact.artifact_type == artifact_type
                            && artifact.jwt_attributes.is_some()
                            && (!artifact.lifecycle_evidence.issue.is_empty()
                                || !artifact.lifecycle_evidence.validate.is_empty())
                    }),
                    "{} should include JWT artifact {artifact_type:?} named {display_name:?}",
                    root.display()
                );
            }
        }
    }

    #[test]
    fn generic_ts_jwt_fixture_classifies_missing_and_decode_evidence() {
        let root = fixture_root().join("generic-ts").join("jwt-validation");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("generic TS JWT fixture should scan"),
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::MissingValidationEvidence
                && finding.title.contains("legacy_access_jwt")
                && finding.title.contains("issuer")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("without signature verification")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("expiry enforcement")
        }));
    }

    #[test]
    fn logout_fixtures_emit_revoke_evidence() {
        let cases = [
            (
                fixture_root()
                    .join("express")
                    .join("cookie-session-lifecycle"),
                "logout.session_destroy",
            ),
            (
                fixture_root()
                    .join("fastapi")
                    .join("dependency-auth-lifecycle"),
                "logout.session_destroy",
            ),
            (
                fixture_root().join("django").join("session-and-reset-flow"),
                "logout.session_destroy",
            ),
            (
                fixture_root().join("nextjs").join("route-handler-auth"),
                "logout.cookie_clear",
            ),
        ];

        for (root, detector_id) in cases {
            let report = scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display()));

            assert!(
                report.evidence.iter().any(|evidence| {
                    evidence.lifecycle_stage == LifecycleStage::Revoke
                        && evidence.detector_id == detector_id
                }),
                "{} should include revoke evidence from {detector_id}",
                root.display()
            );
        }
    }

    #[test]
    fn clear_cookie_only_fixture_produces_review_required_gap() {
        let root = fixture_root()
            .join("express")
            .join("clear-cookie-only-logout");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("clear-cookie-only fixture should scan"),
        );

        assert!(report.lifecycle_paths.iter().any(|path| {
            path.stages
                .iter()
                .any(|step| step.stage == LifecycleStage::Revoke)
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("cleared on logout")
                && finding.reviewer_question.is_some()
        }));
    }

    #[test]
    fn issue_27_provider_library_fixtures_emit_documented_coverage() {
        let cases = [
            (
                fixture_root()
                    .join("nextjs")
                    .join("authjs-nextauth-provider"),
                ["nextauth", "auth0"].as_slice(),
                [
                    "refresh.provider",
                    "logout.provider_revoke",
                    "bearer.dynamic_provider",
                ]
                .as_slice(),
            ),
            (
                fixture_root()
                    .join("express")
                    .join("passport-oauth-strategy"),
                ["passport", "oauth"].as_slice(),
                [
                    "refresh.provider",
                    "logout.provider_revoke",
                    "bearer.dynamic_provider",
                ]
                .as_slice(),
            ),
            (
                fixture_root().join("generic-ts").join("oidc-client-config"),
                ["oidc"].as_slice(),
                ["refresh.provider", "bearer.dynamic_provider"].as_slice(),
            ),
            (
                fixture_root().join("generic-ts").join("cloud-identity-sdk"),
                ["auth0", "okta", "cognito", "azure-ad", "firebase"].as_slice(),
                [
                    "refresh.provider",
                    "logout.provider_revoke",
                    "bearer.dynamic_provider",
                ]
                .as_slice(),
            ),
        ];

        for (root, provider_hints, detector_ids) in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            for provider_hint in provider_hints {
                assert!(
                    report.artifacts.iter().any(|artifact| artifact
                        .framework_hints
                        .iter()
                        .any(|hint| hint == provider_hint)),
                    "{} should include {provider_hint} provider hints",
                    root.display()
                );
            }
            for detector_id in detector_ids {
                assert!(
                    report
                        .evidence
                        .iter()
                        .any(|evidence| evidence.detector_id == *detector_id),
                    "{} should include {detector_id} evidence",
                    root.display()
                );
            }
            assert!(report.evidence.iter().any(|evidence| evidence.dynamic));
            assert!(report.artifacts.iter().any(|artifact| {
                artifact
                    .token_boundary_attributes
                    .as_ref()
                    .is_some_and(|attributes| {
                        attributes.provider.evidence_ids.len()
                            + attributes.audience.evidence_ids.len()
                            + attributes.issuer.evidence_ids.len()
                            + attributes.scope.evidence_ids.len()
                            > 0
                    })
            }));
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.severity == Severity::High)
            );
        }
    }

    #[test]
    fn provider_revoke_fixture_emits_provider_revoke_evidence() {
        let root = fixture_root().join("generic-ts").join("provider-revoke");
        let report = scan_path(
            ScanConfig::new(&root),
            Arc::new(DetectorRegistry::builtin()),
        )
        .expect("provider revoke fixture should scan");

        assert!(report.evidence.iter().any(|evidence| {
            evidence.lifecycle_stage == LifecycleStage::Revoke
                && evidence.detector_id == "logout.provider_revoke"
        }));
        assert!(report.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("refresh_token")
                && !artifact.lifecycle_evidence.revoke.is_empty()
        }));
    }

    #[test]
    fn refresh_fixtures_emit_lifecycle_evidence() {
        let cases = [
            (
                fixture_root().join("express").join("refresh-rotation"),
                vec![
                    ("refresh.handler", LifecycleStage::Refresh),
                    ("refresh.validate", LifecycleStage::Validate),
                    ("refresh.rotate", LifecycleStage::Revoke),
                    ("refresh.store", LifecycleStage::Store),
                    ("refresh.expire", LifecycleStage::Expire),
                ],
            ),
            (
                fixture_root()
                    .join("generic-ts")
                    .join("refresh-reuse-detection"),
                vec![
                    ("refresh.reuse_detection", LifecycleStage::Validate),
                    ("refresh.revoke", LifecycleStage::Revoke),
                ],
            ),
            (
                fixture_root()
                    .join("django")
                    .join("password-change-refresh-revoke"),
                vec![("refresh.revoke", LifecycleStage::Revoke)],
            ),
            (
                fixture_root().join("generic-ts").join("provider-refresh"),
                vec![("refresh.provider", LifecycleStage::Refresh)],
            ),
        ];

        for (root, expected) in cases {
            let report = scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display()));

            for (detector_id, stage) in expected {
                assert!(
                    report.evidence.iter().any(|evidence| {
                        evidence.detector_id == detector_id && evidence.lifecycle_stage == stage
                    }),
                    "{} should include {detector_id} at {stage:?}",
                    root.display()
                );
            }
        }
    }

    #[test]
    fn refresh_rotation_fixture_has_no_missing_revoke_gap() {
        let root = fixture_root().join("express").join("refresh-rotation");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("refresh rotation fixture should scan"),
        );

        assert!(report.lifecycle_paths.iter().any(|path| {
            path.stages
                .iter()
                .any(|step| step.stage == LifecycleStage::Refresh)
                && path
                    .stages
                    .iter()
                    .any(|step| step.stage == LifecycleStage::Revoke)
        }));
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.title.contains("refresh evidence"))
        );
    }

    #[test]
    fn refresh_without_rotation_fixture_produces_lifecycle_gap() {
        let root = fixture_root()
            .join("express")
            .join("refresh-without-rotation");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("refresh-without-rotation fixture should scan"),
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("refresh evidence")
        }));
    }

    #[test]
    fn unrelated_refresh_fixtures_do_not_satisfy_each_other() {
        let root = fixture_root().join("express");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("express fixtures should scan together"),
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("refresh evidence")
                && finding.evidence_ids.iter().any(|evidence_id| {
                    report.evidence.iter().any(|evidence| {
                        evidence.id == *evidence_id
                            && evidence.location.path.contains("refresh-without-rotation")
                    })
                })
        }));
    }

    #[test]
    fn django_sessionid_logout_revocation_prevents_clear_only_gap() {
        let root = fixture_root().join("django").join("session-and-reset-flow");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("django session fixture should scan"),
        );

        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.title.contains("sessionid")
                    && finding.title.contains("cleared on logout")),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn provider_refresh_fixture_produces_dynamic_review() {
        let root = fixture_root().join("generic-ts").join("provider-refresh");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("provider refresh fixture should scan"),
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("dynamic refresh behavior")
        }));
    }

    #[test]
    fn existing_logout_fixture_links_refresh_revocation() {
        let root = fixture_root()
            .join("express")
            .join("cookie-session-lifecycle");
        let report = classify(
            scan_path(
                ScanConfig::new(&root),
                Arc::new(DetectorRegistry::builtin()),
            )
            .expect("express cookie fixture should scan"),
        );

        assert!(report.lifecycle_paths.iter().any(|path| {
            path.stages
                .iter()
                .any(|step| step.stage == LifecycleStage::Refresh)
                && path
                    .stages
                    .iter()
                    .any(|step| step.stage == LifecycleStage::Revoke)
        }));
    }

    #[test]
    fn generic_jwt_fixtures_render_sanitized_identity_claims() {
        for root in [
            fixture_root().join("generic-ts").join("jwt-validation"),
            fixture_root().join("generic-python").join("jwt-and-reset"),
        ] {
            let rendered = render_classified_json(&root);
            let parsed: serde_json::Value =
                serde_json::from_str(&rendered).expect("rendered JSON should parse");
            assert!(
                parsed["artifacts"]
                    .as_array()
                    .expect("artifacts")
                    .iter()
                    .any(|artifact| {
                        artifact["display_name"] == "access_jwt"
                            && artifact["jwt_attributes"]["identity_claims"]["subject"]["state"]
                                == "present"
                    }),
                "{} should include sanitized JWT identity claims",
                root.display()
            );
            assert!(!rendered.contains("person@example.com"));
            assert!(!rendered.contains("placeholder-tenant"));
            assert!(!rendered.contains("placeholder-workspace"));
            assert!(!rendered.contains("read:sessions"));
            assert!(!rendered.contains("urn:mfa"));
            assert!(!rendered.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
            assert!(!rendered.contains(PLACEHOLDER_JWT));
        }
    }

    #[test]
    fn bearer_api_key_fixtures_emit_lifecycle_evidence_and_findings() {
        let cases = [
            fixture_root()
                .join("generic-ts")
                .join("bearer-api-key-lifecycle"),
            fixture_root()
                .join("generic-python")
                .join("bearer-api-key-lifecycle"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            for (display_name, artifact_type) in [
                (Some("api_key"), ArtifactType::ApiKey),
                (Some("service_token"), ArtifactType::ServiceToken),
                (
                    Some("authorization_bearer"),
                    ArtifactType::OpaqueBearerToken,
                ),
            ] {
                assert!(
                    report.artifacts.iter().any(|artifact| {
                        artifact.display_name.as_deref() == display_name
                            && artifact.artifact_type == artifact_type
                    }),
                    "{} should include {artifact_type:?} named {display_name:?}",
                    root.display()
                );
            }

            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "bearer.transmit"
                    && evidence.lifecycle_stage == LifecycleStage::Transmit
            }));
            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "bearer.validate"
                    && evidence.lifecycle_stage == LifecycleStage::Validate
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::HighConfidenceMisconfiguration
                    && finding.title.contains("URL query")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::DynamicReviewRequired
                    && finding.title.contains("provider-managed")
            }));

            let rendered = render(&report, ReportFormat::Json);
            assert!(!rendered.contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));
            assert!(!rendered.contains("internal-api"));
        }
    }

    #[test]
    fn unsafe_bearer_fixtures_classify_reviewable_findings() {
        let cases = [
            fixture_root()
                .join("generic-ts")
                .join("unsafe-bearer-handling"),
            fixture_root()
                .join("generic-python")
                .join("unsafe-bearer-handling"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::HighConfidenceMisconfiguration
                    && (finding.title.contains("URL query")
                        || finding.title.contains("public runtime config")
                        || finding.title.contains("frontend bundle")
                        || finding.title.contains("browser storage"))
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::LifecycleGap
                    && finding.title.contains("expiry")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::LifecycleGap
                    && finding.title.contains("rotation or revocation")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::MissingValidationEvidence
                    && finding.title.contains("scope")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::DynamicReviewRequired
                    && finding.reviewer_question.is_some()
            }));

            for format in [
                ReportFormat::Json,
                ReportFormat::Markdown,
                ReportFormat::Sarif,
            ] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("PLACEHOLDER_API_KEY_DO_NOT_USE"));
                assert!(!rendered.contains("internal-api"));
            }
        }
    }

    #[test]
    fn query_param_token_fixtures_classify_acceptance_findings() {
        let cases = [
            fixture_root()
                .join("generic-ts")
                .join("query-param-token-acceptance"),
            fixture_root()
                .join("generic-python")
                .join("query-param-token-acceptance"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            for (display_name, artifact_type) in [
                (Some("access_token"), ArtifactType::AccessJwt),
                (Some("api_key"), ArtifactType::ApiKey),
                (Some("refresh_token"), ArtifactType::RefreshJwt),
                (
                    Some("password_reset_token"),
                    ArtifactType::PasswordResetToken,
                ),
                (
                    Some("email_verification_token"),
                    ArtifactType::EmailVerificationToken,
                ),
                (Some("dynamic_query_token"), ArtifactType::UnknownToken),
            ] {
                assert!(
                    report.artifacts.iter().any(|artifact| {
                        artifact.display_name.as_deref() == display_name
                            && artifact.artifact_type == artifact_type
                            && !artifact.lifecycle_evidence.transmit.is_empty()
                    }),
                    "{} should include {artifact_type:?} named {display_name:?}",
                    root.display()
                );
            }

            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "query_param.read"
                    && evidence.lifecycle_stage == LifecycleStage::Transmit
            }));
            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "query_param.read.dynamic"
                    && evidence.dynamic
                    && evidence.lifecycle_stage == LifecycleStage::Transmit
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::HighConfidenceMisconfiguration
                    && finding.title.contains("URL query parameter")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::DynamicReviewRequired
                    && finding.title.contains("reset or verification")
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::DynamicReviewRequired
                    && finding.title.contains("needs review")
            }));

            for format in [
                ReportFormat::Json,
                ReportFormat::Markdown,
                ReportFormat::Sarif,
            ] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("PLACEHOLDER"));
                assert!(!rendered.contains("configured-token-value"));
            }
        }
    }

    #[test]
    fn session_fixation_fixtures_emit_review_required_findings() {
        let cases = [
            fixture_root()
                .join("express")
                .join("session-fixation-signals"),
            fixture_root()
                .join("django")
                .join("session-fixation-signals"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "session.auth_transition"
                    && evidence.lifecycle_stage == LifecycleStage::Issue
            }));
            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "session.store_after_auth"
                    && evidence.lifecycle_stage == LifecycleStage::Store
            }));
            assert!(report.evidence.iter().any(|evidence| {
                matches!(
                    evidence.detector_id.as_str(),
                    "session.regenerate"
                        | "session.reissue"
                        | "session.framework_default_regenerate"
                ) && evidence.lifecycle_stage == LifecycleStage::Refresh
            }));
            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id == "session.privilege_transition"
                    && evidence.lifecycle_stage == LifecycleStage::Issue
            }));
            assert!(report.findings.iter().any(|finding| {
                finding.category == FindingCategory::DynamicReviewRequired
                    && finding.title.contains("Session regeneration evidence")
                    && finding.reviewer_question.is_some()
            }));
            assert!(
                report.findings.iter().any(|finding| {
                    finding.category == FindingCategory::DynamicReviewRequired
                        && finding.title.contains("privilege transition")
                        && finding.reviewer_question.is_some()
                }),
                "{} should include privilege transition review",
                root.display()
            );

            for format in [ReportFormat::Json, ReportFormat::Markdown] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("password\":"));
                assert!(!rendered.contains("PLACEHOLDER"));
            }
        }
    }

    #[test]
    fn trust_boundary_fixtures_emit_boundary_inventory_and_reviews() {
        let cases = [
            fixture_root()
                .join("generic-ts")
                .join("trust-boundary-token-reuse"),
            fixture_root()
                .join("generic-python")
                .join("trust-boundary-token-reuse"),
        ];

        for root in cases {
            let report = classify(
                scan_path(
                    ScanConfig::new(&root),
                    Arc::new(DetectorRegistry::builtin()),
                )
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
            );

            assert!(report.artifacts.iter().any(|artifact| {
                artifact
                    .token_boundary_attributes
                    .as_ref()
                    .is_some_and(|attributes| {
                        attributes.audience.evidence_ids.len()
                            + attributes.service.evidence_ids.len()
                            + attributes.environment.evidence_ids.len()
                            + attributes.provider.evidence_ids.len()
                            + attributes.trust_boundary.evidence_ids.len()
                            > 0
                    })
            }));
            assert!(report.evidence.iter().any(|evidence| {
                evidence.detector_id.starts_with("bearer.boundary.")
                    && evidence.lifecycle_stage == LifecycleStage::Introspect
            }));
            for title_part in [
                "inbound and outbound trust boundaries",
                "frontend and backend contexts",
                "multiple environment boundaries",
                "Provider-managed token",
            ] {
                assert!(
                    report.findings.iter().any(|finding| {
                        finding.category == FindingCategory::DynamicReviewRequired
                            && finding.title.contains(title_part)
                            && finding.reviewer_question.is_some()
                    }),
                    "{} should include trust-boundary finding containing {title_part:?}",
                    root.display()
                );
            }

            for format in [
                ReportFormat::Json,
                ReportFormat::Markdown,
                ReportFormat::Sarif,
            ] {
                let rendered = render(&report, format);
                assert!(!rendered.contains("PLACEHOLDER_SERVICE_TOKEN_DO_NOT_USE"));
                assert!(!rendered.contains("PLACEHOLDER_RESET_TOKEN"));
                assert!(!rendered.contains("Bearer PLACEHOLDER"));
                assert!(rendered.contains("trust"));
            }
        }
    }

    #[test]
    fn express_cookie_fixture_renders_deterministic_json_inventory() {
        let root = fixture_root()
            .join("express")
            .join("cookie-session-lifecycle");

        let first = render_classified_json(&root);
        let second = render_classified_json(&root);

        assert_eq!(
            normalize_snapshot_paths(&first),
            normalize_snapshot_paths(&second)
        );
        assert_ids_match(&first, &second, "artifacts");
        assert_ids_match(&first, &second, "evidence");
        assert_ids_match(&first, &second, "lifecycle_paths");
        assert_ids_match(&first, &second, "findings");
        let parsed: serde_json::Value =
            serde_json::from_str(&first).expect("rendered JSON should parse");
        assert!(
            parsed["lifecycle_paths"]
                .as_array()
                .is_some_and(|paths| !paths.is_empty()),
            "fixture should include linked lifecycle paths"
        );
        assert!(!first.contains(PLACEHOLDER_JWT));
        assert!(!first.contains("PLACEHOLDER_RESET_TOKEN"));
        assert!(!first.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
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

    fn render_classified_json(root: &std::path::Path) -> String {
        let report = classify(
            scan_path(ScanConfig::new(root), Arc::new(DetectorRegistry::builtin()))
                .unwrap_or_else(|error| panic!("{} should scan: {error}", root.display())),
        );

        render(&report, ReportFormat::Json)
    }

    fn assert_ids_match(first: &str, second: &str, key: &str) {
        assert_eq!(
            ids(first, key),
            ids(second, key),
            "{key} IDs should be stable"
        );
    }

    fn ids(rendered: &str, key: &str) -> Vec<String> {
        let parsed: serde_json::Value =
            serde_json::from_str(rendered).expect("rendered JSON should parse");

        parsed[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} should be an array"))
            .iter()
            .map(|item| {
                item["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{key} item should have an id"))
                    .to_string()
            })
            .collect()
    }
}
