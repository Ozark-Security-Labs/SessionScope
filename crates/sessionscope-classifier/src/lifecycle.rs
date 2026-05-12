use std::collections::BTreeMap;

use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, EvidenceId, Finding, FindingCategory,
    LifecycleEvidence, LifecyclePath, LifecyclePathStep, LifecycleStage, ScanReport, Severity,
    SourceLocation, stable_finding_id, stable_lifecycle_path_id,
};

const STAGES: [LifecycleStage; 8] = [
    LifecycleStage::Issue,
    LifecycleStage::Store,
    LifecycleStage::Transmit,
    LifecycleStage::Validate,
    LifecycleStage::Refresh,
    LifecycleStage::Revoke,
    LifecycleStage::Expire,
    LifecycleStage::Introspect,
];

pub fn link(report: &ScanReport) -> Vec<LifecyclePath> {
    let evidence_by_id = evidence_by_id(report);
    let mut paths = report
        .artifacts
        .iter()
        .filter_map(|artifact| path_for_artifact(artifact, &evidence_by_id))
        .collect::<Vec<_>>();
    sort_paths(&mut paths);
    paths
}

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in &report.lifecycle_paths {
        let Some(artifact) = artifact_for_path(report, path) else {
            continue;
        };

        findings.extend(classify_issue_without_validate(artifact, path));
        findings.extend(classify_refresh_without_revoke(artifact, path));
        findings.extend(classify_reset_without_single_use(artifact, path));
    }

    findings
}

pub fn sort_paths(paths: &mut [LifecyclePath]) {
    for path in paths.iter_mut() {
        path.artifact_ids.sort();
        for step in &mut path.stages {
            step.evidence_ids.sort();
            step.evidence_ids.dedup();
        }
        path.stages.sort_by_key(|step| step.stage);
    }

    paths.sort_by(|left, right| {
        left.artifact_ids
            .cmp(&right.artifact_ids)
            .then_with(|| left.stages.cmp(&right.stages))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn path_for_artifact(
    artifact: &Artifact,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<LifecyclePath> {
    let mut stages = Vec::new();
    let mut all_evidence_ids = Vec::new();
    let mut evidence_locations = Vec::new();
    let mut confidence = artifact.confidence;
    let mut dynamic = false;
    let mut framework_default = false;

    for stage in STAGES {
        let mut evidence_ids = lifecycle_ids_for_stage(&artifact.lifecycle_evidence, stage);
        evidence_ids.sort();
        evidence_ids.dedup();
        if evidence_ids.is_empty() {
            continue;
        }

        for evidence_id in &evidence_ids {
            all_evidence_ids.push(evidence_id.clone());
            if let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) {
                confidence = min_confidence(confidence, evidence.confidence);
                dynamic |= evidence.dynamic;
                framework_default |= evidence.framework_default;
                evidence_locations.push(location_part(&evidence.location));
            }
        }

        stages.push(LifecyclePathStep {
            stage,
            evidence_ids,
        });
    }

    if stages.is_empty() {
        return None;
    }

    all_evidence_ids.sort();
    all_evidence_ids.dedup();
    evidence_locations.sort();
    evidence_locations.dedup();

    let mut id_parts = vec![
        "lifecycle_path".to_string(),
        artifact.id.0.clone(),
        artifact_type_part(artifact.artifact_type).to_string(),
    ];
    id_parts.extend(
        stages
            .iter()
            .map(|step| format_stage(step.stage).to_string()),
    );
    id_parts.extend(all_evidence_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(evidence_locations);

    Some(LifecyclePath {
        id: stable_lifecycle_path_id(&id_parts),
        artifact_ids: vec![artifact.id.clone()],
        stages,
        confidence,
        dynamic,
        reviewer_question: reviewer_question_for_path(dynamic, framework_default, artifact),
    })
}

fn classify_issue_without_validate(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !is_jwt_artifact(artifact.artifact_type)
        || !has_stage(path, LifecycleStage::Issue)
        || has_stage(path, LifecycleStage::Validate)
    {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("JWT");
    Some(finding(
        "lifecycle_issue_without_validate",
        FindingCategory::LifecycleGap,
        Severity::Medium,
        artifact,
        path,
        evidence_ids_for_stage(path, LifecycleStage::Issue),
        format!("JWT `{name}` is issued without linked validation evidence"),
        "JWT issue evidence was linked into a lifecycle path, but no validation evidence was linked for the same artifact."
            .to_string(),
        "Add or identify verification evidence that validates this token before claims are trusted."
            .to_string(),
        "Where is this issued JWT validated before use?".to_string(),
    ))
}

fn classify_refresh_without_revoke(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !has_stage(path, LifecycleStage::Refresh) || has_stage(path, LifecycleStage::Revoke) {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("token");
    Some(finding(
        "lifecycle_refresh_without_revoke",
        FindingCategory::LifecycleGap,
        Severity::Medium,
        artifact,
        path,
        evidence_ids_for_stage(path, LifecycleStage::Refresh),
        format!("Token `{name}` has refresh evidence without linked revocation evidence"),
        "Refresh lifecycle evidence was linked, but no source-bound revoke or rotation evidence was linked for the same artifact."
            .to_string(),
        "Rotate refresh tokens and revoke the previous token when issuing a replacement."
            .to_string(),
        "Where is the previous refresh token revoked or marked used during refresh?".to_string(),
    ))
}

fn classify_reset_without_single_use(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::PasswordResetToken | ArtifactType::EmailVerificationToken
    ) || !has_stage(path, LifecycleStage::Issue)
        || has_stage(path, LifecycleStage::Revoke)
    {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("reset token");
    Some(finding(
        "lifecycle_reset_without_single_use",
        FindingCategory::LifecycleGap,
        Severity::Low,
        artifact,
        path,
        fallback_path_ids(path),
        format!("Token `{name}` has no linked single-use or revocation evidence"),
        "Reset or verification token evidence was linked, but no source-bound single-use, consume, or revocation evidence was linked for the same artifact."
            .to_string(),
        "Store reset and verification tokens with expiry and mark them consumed after successful use."
            .to_string(),
        "Where is this reset or verification token consumed so it cannot be reused?".to_string(),
    ))
}

fn finding(
    rule_id: &str,
    category: FindingCategory,
    severity: Severity,
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
) -> Finding {
    let evidence_part = evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let id = stable_finding_id(&[
        rule_id,
        path.id.0.as_str(),
        artifact.id.0.as_str(),
        evidence_part,
    ]);

    Finding {
        id,
        category,
        severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids,
        title,
        description,
        suggested_fix: Some(suggested_fix),
        reviewer_question: Some(reviewer_question),
    }
}

fn evidence_by_id(report: &ScanReport) -> BTreeMap<&str, &Evidence> {
    report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect()
}

fn artifact_for_path<'a>(report: &'a ScanReport, path: &LifecyclePath) -> Option<&'a Artifact> {
    let artifact_id = path.artifact_ids.first()?;
    report
        .artifacts
        .iter()
        .find(|artifact| &artifact.id == artifact_id)
}

fn lifecycle_ids_for_stage(
    lifecycle_evidence: &LifecycleEvidence,
    stage: LifecycleStage,
) -> Vec<EvidenceId> {
    match stage {
        LifecycleStage::Issue => lifecycle_evidence.issue.clone(),
        LifecycleStage::Store => lifecycle_evidence.store.clone(),
        LifecycleStage::Transmit => lifecycle_evidence.transmit.clone(),
        LifecycleStage::Validate => lifecycle_evidence.validate.clone(),
        LifecycleStage::Refresh => lifecycle_evidence.refresh.clone(),
        LifecycleStage::Revoke => lifecycle_evidence.revoke.clone(),
        LifecycleStage::Expire => lifecycle_evidence.expire.clone(),
        LifecycleStage::Introspect => lifecycle_evidence.introspect.clone(),
    }
}

fn has_stage(path: &LifecyclePath, stage: LifecycleStage) -> bool {
    path.stages.iter().any(|step| step.stage == stage)
}

fn evidence_ids_for_stage(path: &LifecyclePath, stage: LifecycleStage) -> Vec<EvidenceId> {
    path.stages
        .iter()
        .find(|step| step.stage == stage)
        .map(|step| step.evidence_ids.clone())
        .unwrap_or_default()
}

fn fallback_path_ids(path: &LifecyclePath) -> Vec<EvidenceId> {
    let mut ids = path
        .stages
        .iter()
        .flat_map(|step| step.evidence_ids.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn reviewer_question_for_path(
    dynamic: bool,
    framework_default: bool,
    artifact: &Artifact,
) -> Option<String> {
    let name = artifact.display_name.as_deref().unwrap_or("this artifact");
    if dynamic {
        return Some(format!(
            "Which production code path determines the effective lifecycle behavior for `{name}`?"
        ));
    }
    if framework_default {
        return Some(format!(
            "Which framework version and deployment settings determine lifecycle behavior for `{name}`?"
        ));
    }
    None
}

fn min_confidence(left: Confidence, right: Confidence) -> Confidence {
    match (confidence_rank(left), confidence_rank(right)) {
        (left_rank, right_rank) if left_rank <= right_rank => left,
        _ => right,
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn is_jwt_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::AccessJwt | ArtifactType::RefreshJwt
    )
}

fn location_part(location: &SourceLocation) -> String {
    format!(
        "{}:{}:{}",
        location.path.replace('\\', "/"),
        location.line.unwrap_or(0),
        location.column.unwrap_or(0)
    )
}

fn format_stage(stage: LifecycleStage) -> &'static str {
    match stage {
        LifecycleStage::Issue => "issue",
        LifecycleStage::Store => "store",
        LifecycleStage::Transmit => "transmit",
        LifecycleStage::Validate => "validate",
        LifecycleStage::Refresh => "refresh",
        LifecycleStage::Revoke => "revoke",
        LifecycleStage::Expire => "expire",
        LifecycleStage::Introspect => "introspect",
    }
}

fn artifact_type_part(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::SessionCookie => "session_cookie",
        ArtifactType::SignedCookie => "signed_cookie",
        ArtifactType::AccessJwt => "access_jwt",
        ArtifactType::RefreshJwt => "refresh_jwt",
        ArtifactType::OpaqueBearerToken => "opaque_bearer_token",
        ArtifactType::ApiKey => "api_key",
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, LifecyclePathId, SCHEMA_VERSION, ScanSummary, SourceLocation,
    };

    use super::*;

    fn report_with_artifacts(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> ScanReport {
        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts,
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn artifact(
        id: &str,
        artifact_type: ArtifactType,
        name: &str,
        lifecycle_evidence: LifecycleEvidence,
    ) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location("auth.ts", 1, 1)],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: Vec::new(),
            cookie_attributes: None,
            jwt_attributes: None,
        }
    }

    fn evidence(id: &str, stage: LifecycleStage, line: usize, dynamic: bool) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location("auth.ts", line, 1),
            detector_id: format!("test.{}", format_stage(stage)),
            confidence: if dynamic {
                Confidence::Medium
            } else {
                Confidence::High
            },
            excerpt: None,
            dynamic,
            framework_default: false,
        }
    }

    fn location(path: &str, line: usize, column: usize) -> SourceLocation {
        SourceLocation {
            path: path.to_string(),
            line: Some(line),
            column: Some(column),
        }
    }

    fn classified_report(artifact: Artifact, evidence: Vec<Evidence>) -> ScanReport {
        let mut report = report_with_artifacts(vec![artifact], evidence);
        report.lifecycle_paths = link(&report);
        report
    }

    #[test]
    fn links_issue_to_validate_jwt_path() {
        let artifact = artifact(
            "artifact_access",
            ArtifactType::AccessJwt,
            "access_jwt",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                validate: vec![EvidenceId("evidence_validate".to_string())],
                ..LifecycleEvidence::default()
            },
        );

        let report = report_with_artifacts(
            vec![artifact],
            vec![
                evidence("evidence_validate", LifecycleStage::Validate, 20, false),
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0].artifact_ids,
            vec![ArtifactId("artifact_access".to_string())]
        );
        assert!(has_stage(&paths[0], LifecycleStage::Issue));
        assert!(has_stage(&paths[0], LifecycleStage::Validate));
        assert!(
            classify(&ScanReport {
                lifecycle_paths: paths,
                ..report
            })
            .is_empty()
        );
    }

    #[test]
    fn path_ids_are_deterministic_for_shuffled_evidence() {
        let first = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    issue: vec![
                        EvidenceId("evidence_b".to_string()),
                        EvidenceId("evidence_a".to_string()),
                    ],
                    validate: vec![EvidenceId("evidence_c".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_c", LifecycleStage::Validate, 30, false),
                evidence("evidence_b", LifecycleStage::Issue, 20, false),
                evidence("evidence_a", LifecycleStage::Issue, 10, false),
            ],
        );
        let second = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    validate: vec![EvidenceId("evidence_c".to_string())],
                    issue: vec![
                        EvidenceId("evidence_a".to_string()),
                        EvidenceId("evidence_b".to_string()),
                    ],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_a", LifecycleStage::Issue, 10, false),
                evidence("evidence_b", LifecycleStage::Issue, 20, false),
                evidence("evidence_c", LifecycleStage::Validate, 30, false),
            ],
        );

        assert_eq!(link(&first)[0].id, link(&second)[0].id);
    }

    #[test]
    fn dynamic_path_gets_reviewer_question() {
        let report = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence("evidence_issue", LifecycleStage::Issue, 10, true)],
        );

        let path = link(&report).pop().expect("path");

        assert!(path.dynamic);
        assert_eq!(path.confidence, Confidence::Medium);
        assert!(path.reviewer_question.is_some());
    }

    #[test]
    fn refresh_with_revoke_has_no_gap() {
        let report = classified_report(
            artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_jwt",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    revoke: vec![EvidenceId("evidence_revoke".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_refresh", LifecycleStage::Refresh, 10, false),
                evidence("evidence_revoke", LifecycleStage::Revoke, 11, false),
            ],
        );

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn refresh_without_revoke_is_lifecycle_gap() {
        let report = classified_report(
            artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_jwt",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![evidence(
                "evidence_refresh",
                LifecycleStage::Refresh,
                10,
                false,
            )],
        );

        let findings = classify(&report);

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("refresh evidence")
        }));
    }

    #[test]
    fn reset_token_with_expire_and_revoke_has_no_gap() {
        let report = classified_report(
            artifact(
                "artifact_reset",
                ArtifactType::PasswordResetToken,
                "password_reset_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    expire: vec![EvidenceId("evidence_expire".to_string())],
                    revoke: vec![EvidenceId("evidence_single_use".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence("evidence_expire", LifecycleStage::Expire, 11, false),
                evidence("evidence_single_use", LifecycleStage::Revoke, 12, false),
            ],
        );

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn reset_token_missing_single_use_is_reviewable_gap() {
        let report = classified_report(
            artifact(
                "artifact_reset",
                ArtifactType::PasswordResetToken,
                "password_reset_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    expire: vec![EvidenceId("evidence_expire".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence("evidence_expire", LifecycleStage::Expire, 11, false),
            ],
        );

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.category == FindingCategory::LifecycleGap)
            .expect("reset token gap finding");

        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn sort_paths_orders_paths_by_artifact() {
        let mut paths = vec![
            LifecyclePath {
                id: LifecyclePathId("lifecycle_path_b".to_string()),
                artifact_ids: vec![ArtifactId("artifact_b".to_string())],
                stages: Vec::new(),
                confidence: Confidence::High,
                dynamic: false,
                reviewer_question: None,
            },
            LifecyclePath {
                id: LifecyclePathId("lifecycle_path_a".to_string()),
                artifact_ids: vec![ArtifactId("artifact_a".to_string())],
                stages: Vec::new(),
                confidence: Confidence::High,
                dynamic: false,
                reviewer_question: None,
            },
        ];

        sort_paths(&mut paths);

        assert_eq!(
            paths[0].artifact_ids[0],
            ArtifactId("artifact_a".to_string())
        );
    }
}
