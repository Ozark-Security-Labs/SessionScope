use std::collections::{BTreeMap, BTreeSet};

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
    merge_revoke_only_paths(report, &evidence_by_id, &mut paths);
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
        let evidence_by_id = evidence_by_id(report);
        findings.extend(classify_refresh_without_revoke(
            artifact,
            path,
            &evidence_by_id,
        ));
        findings.extend(classify_reset_without_single_use(artifact, path));
        findings.extend(classify_clear_cookie_only_logout(
            artifact,
            path,
            &evidence_by_id,
        ));
    }

    findings
}

fn merge_revoke_only_paths(
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    paths: &mut Vec<LifecyclePath>,
) {
    let artifact_by_id = artifact_by_id(report);
    let mut absorbed = BTreeSet::new();

    for source_index in 0..paths.len() {
        if !is_revoke_only_path(&paths[source_index]) {
            continue;
        }
        let Some(source_artifact) =
            artifact_for_path_with_lookup(&artifact_by_id, &paths[source_index])
        else {
            continue;
        };

        let target_index = (0..paths.len()).find(|target_index| {
            *target_index != source_index
                && !absorbed.contains(target_index)
                && !is_revoke_only_path(&paths[*target_index])
                && artifact_for_path_with_lookup(&artifact_by_id, &paths[*target_index])
                    .is_some_and(|target_artifact| {
                        compatible_revoke_artifacts(source_artifact, target_artifact)
                    })
        });

        let Some(target_index) = target_index else {
            continue;
        };

        let source_path = paths[source_index].clone();
        merge_path(&source_path, &mut paths[target_index]);
        refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut paths[target_index]);
        absorbed.insert(source_index);
    }

    if !absorbed.is_empty() {
        let mut index = 0usize;
        paths.retain(|_| {
            let keep = !absorbed.contains(&index);
            index += 1;
            keep
        });
    }
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

    let mut path = LifecyclePath {
        id: stable_lifecycle_path_id(&id_parts),
        artifact_ids: vec![artifact.id.clone()],
        stages,
        confidence,
        dynamic,
        reviewer_question: reviewer_question_for_path(dynamic, framework_default, artifact),
    };
    let artifact_by_id = [(artifact.id.0.as_str(), artifact)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut path);
    Some(path)
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

fn classify_refresh_without_revoke(
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !has_stage(path, LifecycleStage::Refresh) || has_server_revoke(path, evidence_by_id) {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("token");
    let reviewer_question = if has_client_cookie_clear(path, evidence_by_id) {
        "Where is the previous refresh token revoked or marked used server-side, beyond clearing the client cookie?"
    } else {
        "Where is the previous refresh token revoked or marked used during refresh?"
    };
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
        reviewer_question.to_string(),
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

fn classify_clear_cookie_only_logout(
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !has_client_cookie_clear(path, evidence_by_id) || has_server_revoke(path, evidence_by_id) {
        return None;
    }
    if !matches!(
        artifact.artifact_type,
        ArtifactType::SessionCookie
            | ArtifactType::SignedCookie
            | ArtifactType::SessionRecord
            | ArtifactType::RefreshJwt
            | ArtifactType::Unknown
    ) {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("session");
    Some(finding(
        "lifecycle_clear_cookie_only_logout",
        FindingCategory::LifecycleGap,
        Severity::Low,
        artifact,
        path,
        client_cookie_clear_ids(path, evidence_by_id),
        format!("Cookie `{name}` is cleared on logout without linked server-side revocation"),
        "Logout evidence clears a client-side cookie, but no linked server-side session, token, or provider revocation evidence was found for the same lifecycle path."
            .to_string(),
        "Invalidate the server-side session or refresh token in addition to deleting the browser cookie."
            .to_string(),
        format!(
            "Where is the server-side session or token behind `{name}` revoked during logout?"
        ),
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

fn artifact_by_id(report: &ScanReport) -> BTreeMap<&str, &Artifact> {
    report
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.0.as_str(), artifact))
        .collect()
}

fn artifact_for_path<'a>(report: &'a ScanReport, path: &LifecyclePath) -> Option<&'a Artifact> {
    let artifact_by_id = artifact_by_id(report);
    artifact_for_path_with_lookup(&artifact_by_id, path)
}

fn artifact_for_path_with_lookup<'a>(
    artifact_by_id: &BTreeMap<&str, &'a Artifact>,
    path: &LifecyclePath,
) -> Option<&'a Artifact> {
    path.artifact_ids
        .iter()
        .filter_map(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        .find(|artifact| !artifact_has_only_revoke_evidence(artifact))
        .or_else(|| {
            path.artifact_ids
                .first()
                .and_then(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        })
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

fn has_client_cookie_clear(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "logout.cookie_clear")
        })
}

fn has_server_revoke(path: &LifecyclePath, evidence_by_id: &BTreeMap<&str, &Evidence>) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id != "logout.cookie_clear")
        })
}

fn client_cookie_clear_ids(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<EvidenceId> {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .into_iter()
        .filter(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "logout.cookie_clear")
        })
        .collect()
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

fn is_revoke_only_path(path: &LifecyclePath) -> bool {
    path.stages.len() == 1 && has_stage(path, LifecycleStage::Revoke)
}

fn artifact_has_only_revoke_evidence(artifact: &Artifact) -> bool {
    !artifact.lifecycle_evidence.revoke.is_empty()
        && artifact.lifecycle_evidence.issue.is_empty()
        && artifact.lifecycle_evidence.store.is_empty()
        && artifact.lifecycle_evidence.transmit.is_empty()
        && artifact.lifecycle_evidence.validate.is_empty()
        && artifact.lifecycle_evidence.refresh.is_empty()
        && artifact.lifecycle_evidence.expire.is_empty()
        && artifact.lifecycle_evidence.introspect.is_empty()
}

fn compatible_revoke_artifacts(source: &Artifact, target: &Artifact) -> bool {
    if normalized_artifact_name(source) != normalized_artifact_name(target) {
        return false;
    }
    source.artifact_type == target.artifact_type
        || source.artifact_type == ArtifactType::Unknown
        || target.artifact_type == ArtifactType::Unknown
        || compatible_cookie_session_types(source.artifact_type, target.artifact_type)
        || compatible_token_types(source.artifact_type, target.artifact_type)
}

fn compatible_cookie_session_types(left: ArtifactType, right: ArtifactType) -> bool {
    matches!(
        (left, right),
        (
            ArtifactType::SessionCookie | ArtifactType::SignedCookie | ArtifactType::SessionRecord,
            ArtifactType::SessionCookie | ArtifactType::SignedCookie | ArtifactType::SessionRecord
        )
    )
}

fn compatible_token_types(left: ArtifactType, right: ArtifactType) -> bool {
    matches!(
        (left, right),
        (
            ArtifactType::RefreshJwt | ArtifactType::AccessJwt | ArtifactType::OpaqueBearerToken,
            ArtifactType::RefreshJwt | ArtifactType::AccessJwt | ArtifactType::OpaqueBearerToken
        )
    )
}

fn normalized_artifact_name(artifact: &Artifact) -> String {
    artifact
        .display_name
        .as_deref()
        .unwrap_or("artifact")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn merge_path(source: &LifecyclePath, target: &mut LifecyclePath) {
    target.artifact_ids.extend(source.artifact_ids.clone());
    for source_step in &source.stages {
        if let Some(target_step) = target
            .stages
            .iter_mut()
            .find(|step| step.stage == source_step.stage)
        {
            target_step
                .evidence_ids
                .extend(source_step.evidence_ids.clone());
        } else {
            target.stages.push(source_step.clone());
        }
    }
}

fn refresh_path_metadata(
    artifact_by_id: &BTreeMap<&str, &Artifact>,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    path: &mut LifecyclePath,
) {
    path.artifact_ids.sort();
    path.artifact_ids.dedup();
    for step in &mut path.stages {
        step.evidence_ids.sort();
        step.evidence_ids.dedup();
    }
    path.stages.sort_by_key(|step| step.stage);

    let artifacts = path
        .artifact_ids
        .iter()
        .filter_map(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        .collect::<Vec<_>>();
    let Some(primary_artifact) = artifact_for_path_with_lookup(artifact_by_id, path) else {
        return;
    };

    let mut confidence = primary_artifact.confidence;
    let mut dynamic = false;
    let mut framework_default = false;
    let mut evidence_locations = Vec::new();
    let mut all_evidence_ids = Vec::new();

    for artifact in artifacts {
        confidence = min_confidence(confidence, artifact.confidence);
    }
    for step in &path.stages {
        for evidence_id in &step.evidence_ids {
            all_evidence_ids.push(evidence_id.clone());
            if let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) {
                confidence = min_confidence(confidence, evidence.confidence);
                dynamic |= evidence.dynamic;
                framework_default |= evidence.framework_default;
                evidence_locations.push(location_part(&evidence.location));
            }
        }
    }

    evidence_locations.sort();
    evidence_locations.dedup();
    all_evidence_ids.sort();
    all_evidence_ids.dedup();

    let mut id_parts = vec!["lifecycle_path".to_string()];
    id_parts.extend(path.artifact_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(
        path.stages
            .iter()
            .map(|step| format_stage(step.stage).to_string()),
    );
    id_parts.extend(all_evidence_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(evidence_locations);

    path.id = stable_lifecycle_path_id(&id_parts);
    path.confidence = confidence;
    path.dynamic = dynamic;
    path.reviewer_question =
        reviewer_question_for_path(dynamic, framework_default, primary_artifact);
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

    fn evidence_with_detector(
        id: &str,
        stage: LifecycleStage,
        detector_id: &str,
        line: usize,
        dynamic: bool,
    ) -> Evidence {
        Evidence {
            detector_id: detector_id.to_string(),
            ..evidence(id, stage, line, dynamic)
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
    fn same_name_revoke_only_artifact_merges_into_existing_path() {
        let report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_session_store",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        store: vec![EvidenceId("evidence_store".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_clear",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_store", LifecycleStage::Store, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].artifact_ids.len(), 2);
        assert!(has_stage(&paths[0], LifecycleStage::Store));
        assert!(has_stage(&paths[0], LifecycleStage::Revoke));
    }

    #[test]
    fn client_cookie_clear_does_not_satisfy_refresh_server_revoke() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_refresh",
                    ArtifactType::RefreshJwt,
                    "refresh_token",
                    LifecycleEvidence {
                        refresh: vec![EvidenceId("evidence_refresh".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_clear",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_refresh", LifecycleStage::Refresh, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(findings.iter().any(|finding| {
            finding.title.contains("refresh evidence")
                && finding
                    .reviewer_question
                    .as_deref()
                    .is_some_and(|question| question.contains("server-side"))
        }));
    }

    #[test]
    fn server_revoke_prevents_clear_cookie_only_finding() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_session_store",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        store: vec![EvidenceId("evidence_store".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_clear",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_destroy",
                    ArtifactType::SessionRecord,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_destroy".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_store", LifecycleStage::Store, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
                evidence_with_detector(
                    "evidence_destroy",
                    LifecycleStage::Revoke,
                    "logout.session_destroy",
                    21,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("cleared on logout"))
        );
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
