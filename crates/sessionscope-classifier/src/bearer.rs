use std::collections::BTreeMap;

use sessionscope_model::{
    Artifact, ArtifactType, Evidence, EvidenceId, Finding, FindingCategory, LifecycleEvidence,
    LifecycleStage, ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        if !is_bearer_like_artifact(artifact.artifact_type) {
            continue;
        }

        findings.extend(classify_deterministic_risks(artifact, &evidence_by_id));
        findings.extend(classify_missing_validation(
            artifact,
            report,
            &evidence_by_id,
        ));
        findings.extend(classify_issue_without_expiry(artifact, report));
        findings.extend(classify_dynamic_provider(artifact, &evidence_by_id));
    }

    findings
}

fn classify_deterministic_risks(
    artifact: &Artifact,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for evidence in evidence_for_artifact(artifact, evidence_by_id) {
        match evidence.detector_id.as_str() {
            "bearer.transmit.url_query" => findings.push(finding(
                "bearer_token_in_url_query",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` is transmitted in a URL query parameter",
                    artifact_name(artifact)
                ),
                "Bearer/API-key token evidence appears in a URL query parameter, which can be logged, cached, or forwarded outside the intended trust boundary."
                    .to_string(),
                "Transmit tokens in headers or another channel that is not embedded in URLs."
                    .to_string(),
                "Can this token be moved out of query parameters on every request path?"
                    .to_string(),
            )),
            "bearer.store.browser" => findings.push(finding(
                "bearer_token_browser_storage",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                vec![evidence.id.clone()],
                format!("Token `{}` is stored in browser storage", artifact_name(artifact)),
                "Bearer/API-key token evidence is stored in localStorage or sessionStorage, where browser JavaScript can read it."
                    .to_string(),
                "Use an HttpOnly cookie or another storage pattern that prevents direct script access when possible."
                    .to_string(),
                "Is this token intended to be readable by browser JavaScript?".to_string(),
            )),
            "bearer.literal.static" => findings.push(finding(
                "bearer_static_secret_literal",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` has static secret-like literal evidence",
                    artifact_name(artifact)
                ),
                "Source evidence contains a static token/API-key style literal. The value is redacted in reports, but the code path should not carry runtime secrets in source."
                    .to_string(),
                "Move runtime token values to approved secret storage and keep source/config references value-free."
                    .to_string(),
                "Is this placeholder-only fixture code, or can production source contain a token value here?"
                    .to_string(),
            )),
            _ => {}
        }
    }

    findings
}

fn classify_missing_validation(
    artifact: &Artifact,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    let inbound_ids = evidence_for_artifact(artifact, evidence_by_id)
        .into_iter()
        .filter(|evidence| evidence.detector_id == "bearer.read.inbound")
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();

    if inbound_ids.is_empty() || has_related_stage(artifact, report, LifecycleStage::Validate) {
        return None;
    }

    Some(finding(
        "bearer_missing_validation",
        FindingCategory::MissingValidationEvidence,
        Severity::Medium,
        artifact,
        inbound_ids,
        format!(
            "Inbound token `{}` is read without linked validation evidence",
            artifact_name(artifact)
        ),
        "Inbound bearer/API-key evidence was detected, but no local validation, lookup, or compare evidence was linked for the same token artifact."
            .to_string(),
        "Add or identify source-bound validation evidence before the token is trusted."
            .to_string(),
        "Where is this inbound token checked before it authorizes access?".to_string(),
    ))
}

fn classify_issue_without_expiry(artifact: &Artifact, report: &ScanReport) -> Option<Finding> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::ApiKey | ArtifactType::ServiceToken
    ) || artifact.lifecycle_evidence.issue.is_empty()
        || has_related_stage(artifact, report, LifecycleStage::Expire)
    {
        return None;
    }

    Some(finding(
        "bearer_issue_without_expiry",
        FindingCategory::LifecycleGap,
        Severity::Low,
        artifact,
        artifact.lifecycle_evidence.issue.clone(),
        format!(
            "Token `{}` is issued without linked expiry evidence",
            artifact_name(artifact)
        ),
        "Service/API token issue evidence was detected without linked expiry or TTL evidence."
            .to_string(),
        "Set an explicit expiry or rotation policy for issued service/API tokens.".to_string(),
        "What effective lifetime does this issued token have?".to_string(),
    ))
}

fn classify_dynamic_provider(
    artifact: &Artifact,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    let ids = evidence_for_artifact(artifact, evidence_by_id)
        .into_iter()
        .filter(|evidence| evidence.detector_id == "bearer.dynamic_provider" || evidence.dynamic)
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();

    if ids.is_empty() {
        return None;
    }

    Some(finding(
        "bearer_dynamic_provider_review",
        FindingCategory::DynamicReviewRequired,
        Severity::Low,
        artifact,
        ids,
        format!(
            "Token `{}` has dynamic provider-managed behavior",
            artifact_name(artifact)
        ),
        "Bearer/API-key token behavior appears provider-managed or wrapper-heavy, so the static evidence should be reviewed before treating it as deterministic."
            .to_string(),
        "Document the provider or wrapper policy for issuance, storage, validation, expiry, and revocation."
            .to_string(),
        "Which provider or wrapper settings govern this token lifecycle?".to_string(),
    ))
}

fn evidence_for_artifact<'a>(
    artifact: &Artifact,
    evidence_by_id: &'a BTreeMap<&str, &'a Evidence>,
) -> Vec<&'a Evidence> {
    lifecycle_evidence_ids(artifact)
        .into_iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()).copied())
        .collect()
}

fn lifecycle_evidence_ids(artifact: &Artifact) -> Vec<&EvidenceId> {
    let mut ids = Vec::new();
    ids.extend(&artifact.lifecycle_evidence.issue);
    ids.extend(&artifact.lifecycle_evidence.store);
    ids.extend(&artifact.lifecycle_evidence.transmit);
    ids.extend(&artifact.lifecycle_evidence.validate);
    ids.extend(&artifact.lifecycle_evidence.refresh);
    ids.extend(&artifact.lifecycle_evidence.revoke);
    ids.extend(&artifact.lifecycle_evidence.expire);
    ids.extend(&artifact.lifecycle_evidence.introspect);
    ids
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    category: FindingCategory,
    severity: Severity,
    artifact: &Artifact,
    mut evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
) -> Finding {
    evidence_ids.sort();
    evidence_ids.dedup();
    let evidence_part = evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let name_part = artifact.display_name.as_deref().unwrap_or("dynamic");
    let id = stable_finding_id(&[rule_id, artifact.id.0.as_str(), evidence_part, name_part]);

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

fn artifact_name(artifact: &Artifact) -> &str {
    artifact.display_name.as_deref().unwrap_or("token")
}

fn is_bearer_like_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::OpaqueBearerToken
            | ArtifactType::ApiKey
            | ArtifactType::ServiceToken
            | ArtifactType::UnknownToken
    )
}

fn has_related_stage(artifact: &Artifact, report: &ScanReport, stage: LifecycleStage) -> bool {
    report.artifacts.iter().any(|candidate| {
        is_related_token_artifact(artifact, candidate)
            && !lifecycle_ids_for_stage(&candidate.lifecycle_evidence, stage).is_empty()
    })
}

fn is_related_token_artifact(left: &Artifact, right: &Artifact) -> bool {
    if !is_bearer_like_artifact(left.artifact_type) || !is_bearer_like_artifact(right.artifact_type)
    {
        return false;
    }

    left.display_name == right.display_name
        || left.artifact_type == right.artifact_type
        || left.artifact_type == ArtifactType::UnknownToken
        || right.artifact_type == ArtifactType::UnknownToken
}

fn lifecycle_ids_for_stage(
    lifecycle_evidence: &LifecycleEvidence,
    stage: LifecycleStage,
) -> &[EvidenceId] {
    match stage {
        LifecycleStage::Issue => &lifecycle_evidence.issue,
        LifecycleStage::Store => &lifecycle_evidence.store,
        LifecycleStage::Transmit => &lifecycle_evidence.transmit,
        LifecycleStage::Validate => &lifecycle_evidence.validate,
        LifecycleStage::Refresh => &lifecycle_evidence.refresh,
        LifecycleStage::Revoke => &lifecycle_evidence.revoke,
        LifecycleStage::Expire => &lifecycle_evidence.expire,
        LifecycleStage::Introspect => &lifecycle_evidence.introspect,
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, SCHEMA_VERSION, SanitizedExcerpt, ScanSummary, SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact, evidence: Vec<Evidence>) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![artifact],
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(
        artifact_type: ArtifactType,
        name: &str,
        lifecycle_evidence: LifecycleEvidence,
    ) -> Artifact {
        Artifact {
            id: ArtifactId(format!("artifact_{name}")),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location(1)],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: vec!["test".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
        }
    }

    fn evidence(id: &str, detector_id: &str, stage: LifecycleStage) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location(3),
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt("redacted context".to_string())),
            dynamic: detector_id == "bearer.dynamic_provider",
            framework_default: false,
        }
    }

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            path: "app.ts".to_string(),
            line: Some(line),
            column: Some(1),
        }
    }

    #[test]
    fn url_query_and_browser_storage_are_high_confidence() {
        let artifact = artifact(
            ArtifactType::ApiKey,
            "api_key",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_url".to_string())],
                store: vec![EvidenceId("evidence_browser".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![
                evidence(
                    "evidence_url",
                    "bearer.transmit.url_query",
                    LifecycleStage::Transmit,
                ),
                evidence(
                    "evidence_browser",
                    "bearer.store.browser",
                    LifecycleStage::Store,
                ),
            ],
        );

        assert_eq!(
            findings
                .iter()
                .filter(
                    |finding| finding.category == FindingCategory::HighConfidenceMisconfiguration
                )
                .count(),
            2
        );
    }

    #[test]
    fn inbound_read_without_validate_is_missing_validation() {
        let artifact = artifact(
            ArtifactType::OpaqueBearerToken,
            "authorization_bearer",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_read".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_read",
                "bearer.read.inbound",
                LifecycleStage::Transmit,
            )],
        );

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::MissingValidationEvidence
                && finding.title.contains("without linked validation")
        }));
    }

    #[test]
    fn issued_service_token_without_expiry_is_lifecycle_gap() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_issue",
                "bearer.issue",
                LifecycleStage::Issue,
            )],
        );

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap && finding.severity == Severity::Low
        }));
    }

    #[test]
    fn dynamic_provider_is_review_required() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_provider".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_provider",
                "bearer.dynamic_provider",
                LifecycleStage::Transmit,
            )],
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == FindingCategory::DynamicReviewRequired)
        );
    }
}
