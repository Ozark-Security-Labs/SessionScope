use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, ArtifactType, Evidence, EvidenceId, Finding, FindingCategory, LifecycleStage,
    ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for artifact in &report.artifacts {
        let evidence = query_param_evidence(artifact, &evidence_by_id);
        if evidence.is_empty() {
            continue;
        }

        let rule_id = rule_id_for_artifact(artifact, &evidence);
        if !seen.insert((rule_id, artifact.id.0.clone())) {
            continue;
        }

        findings.push(finding_for_artifact(rule_id, artifact, evidence));
    }

    findings
}

fn query_param_evidence<'a>(
    artifact: &Artifact,
    evidence_by_id: &'a BTreeMap<&str, &'a Evidence>,
) -> Vec<&'a Evidence> {
    artifact
        .lifecycle_evidence
        .transmit
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()).copied())
        .filter(|evidence| {
            evidence.lifecycle_stage == LifecycleStage::Transmit
                && matches!(
                    evidence.detector_id.as_str(),
                    "query_param.read" | "query_param.read.dynamic"
                )
        })
        .collect()
}

fn rule_id_for_artifact(artifact: &Artifact, evidence: &[&Evidence]) -> &'static str {
    if evidence.iter().any(|evidence| evidence.dynamic)
        || artifact.artifact_type == ArtifactType::UnknownToken
    {
        "query_param_token_acceptance_review"
    } else if matches!(
        artifact.artifact_type,
        ArtifactType::PasswordResetToken | ArtifactType::EmailVerificationToken
    ) {
        "query_param_reset_or_verification_review"
    } else {
        "query_param_auth_token_acceptance"
    }
}

fn finding_for_artifact(
    rule_id: &'static str,
    artifact: &Artifact,
    evidence: Vec<&Evidence>,
) -> Finding {
    match rule_id {
        "query_param_auth_token_acceptance" => finding(
            rule_id,
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            evidence_ids(evidence),
            format!(
                "Token `{}` is accepted from a URL query parameter",
                artifact_name(artifact)
            ),
            "Authentication token evidence is read from request query parameters. URLs are commonly logged, cached, copied, and sent in referrers, so query transport can expose bearer-style credentials outside the intended boundary."
                .to_string(),
            "Accept authentication tokens in headers, secure cookies, or another non-URL transport whenever possible."
                .to_string(),
            "Which route accepts this token from the query string, and can it move to a non-URL transport?"
                .to_string(),
        ),
        "query_param_reset_or_verification_review" => finding(
            rule_id,
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            evidence_ids(evidence),
            format!(
                "Token `{}` is accepted from a reset or verification query parameter",
                artifact_name(artifact)
            ),
            "Reset or verification token evidence is read from request query parameters. This can be intentional, but reviewers should confirm expiry, single-use behavior, and redirect handling."
                .to_string(),
            "Keep reset and verification tokens short-lived, single-use, and avoid forwarding them through redirects, logs, or third-party referrers."
                .to_string(),
            "Where are expiry, single-use consumption, and post-use redirect behavior enforced for this flow?"
                .to_string(),
        ),
        _ => finding(
            rule_id,
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            evidence_ids(evidence),
            format!(
                "Token-like query parameter `{}` needs review",
                artifact_name(artifact)
            ),
            "A token-like or dynamically named query parameter was read from request data, but static analysis could not determine a precise authentication token type."
                .to_string(),
            "Confirm whether this query parameter carries credential material and move authentication tokens out of URLs when it does."
                .to_string(),
            "What runtime query parameter name is accepted here, and what token type does it carry?"
                .to_string(),
        ),
    }
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

fn evidence_ids(evidence: Vec<&Evidence>) -> Vec<EvidenceId> {
    evidence
        .into_iter()
        .map(|evidence| evidence.id.clone())
        .collect()
}

fn artifact_name(artifact: &Artifact) -> &str {
    artifact.display_name.as_deref().unwrap_or("token")
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, LifecycleEvidence, SCHEMA_VERSION, SanitizedExcerpt, ScanSummary,
        SourceLocation,
    };

    use super::*;

    fn classify_artifacts(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts,
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(id: &str, artifact_type: ArtifactType, name: &str, evidence_id: &str) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location(1)],
            lifecycle_evidence: LifecycleEvidence {
                transmit: vec![EvidenceId(evidence_id.to_string())],
                ..LifecycleEvidence::default()
            },
            confidence: Confidence::High,
            framework_hints: vec!["test".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn evidence(id: &str, detector_id: &str, dynamic: bool) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: LifecycleStage::Transmit,
            location: location(3),
            detector_id: detector_id.to_string(),
            confidence: if dynamic {
                Confidence::Medium
            } else {
                Confidence::High
            },
            excerpt: Some(SanitizedExcerpt("redacted query read".to_string())),
            dynamic,
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
    fn auth_api_and_service_query_tokens_are_high_confidence() {
        let findings = classify_artifacts(
            vec![
                artifact(
                    "artifact_access",
                    ArtifactType::AccessJwt,
                    "access_token",
                    "e1",
                ),
                artifact("artifact_api", ArtifactType::ApiKey, "api_key", "e2"),
                artifact(
                    "artifact_service",
                    ArtifactType::ServiceToken,
                    "service_token",
                    "e3",
                ),
            ],
            vec![
                evidence("e1", "query_param.read", false),
                evidence("e2", "query_param.read", false),
                evidence("e3", "query_param.read", false),
            ],
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.category == FindingCategory::HighConfidenceMisconfiguration
                        && finding.severity == Severity::High
                })
                .count(),
            3
        );
    }

    #[test]
    fn reset_and_verification_query_tokens_are_review_required() {
        let findings = classify_artifacts(
            vec![
                artifact(
                    "artifact_reset",
                    ArtifactType::PasswordResetToken,
                    "password_reset_token",
                    "e1",
                ),
                artifact(
                    "artifact_verify",
                    ArtifactType::EmailVerificationToken,
                    "email_verification_token",
                    "e2",
                ),
            ],
            vec![
                evidence("e1", "query_param.read", false),
                evidence("e2", "query_param.read", false),
            ],
        );

        assert!(findings.iter().all(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.reviewer_question.is_some()
        }));
    }

    #[test]
    fn dynamic_and_unknown_query_tokens_are_review_required() {
        let findings = classify_artifacts(
            vec![artifact(
                "artifact_dynamic",
                ArtifactType::UnknownToken,
                "dynamic_query_token",
                "e1",
            )],
            vec![evidence("e1", "query_param.read.dynamic", true)],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, FindingCategory::DynamicReviewRequired);
    }

    #[test]
    fn repeated_query_artifact_does_not_duplicate_findings() {
        let token = artifact(
            "artifact_access",
            ArtifactType::AccessJwt,
            "access_token",
            "e1",
        );
        let findings = classify_artifacts(
            vec![token.clone(), token],
            vec![evidence("e1", "query_param.read", false)],
        );

        assert_eq!(findings.len(), 1);
    }
}
