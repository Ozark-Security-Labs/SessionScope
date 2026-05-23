use std::collections::BTreeSet;

use sessionscope_model::{
    Artifact, ArtifactType, Evidence, EvidenceId, Finding, FindingCategory, ScanReport, Severity,
    stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        if artifact.artifact_type != ArtifactType::OAuthAuthCodeFlow {
            continue;
        }

        let evidence = artifact_evidence(report, artifact);
        if evidence
            .iter()
            .any(|item| item.detector_id == "oauth.flow.auth_code")
        {
            findings.extend(classify_pkce(report, artifact, &evidence));
        }
    }

    dedupe_findings(findings)
}

fn classify_pkce(
    report: &ScanReport,
    artifact: &Artifact,
    evidence: &[&Evidence],
) -> Option<Finding> {
    if evidence
        .iter()
        .any(|item| item.detector_id == "oauth.pkce.present")
    {
        return None;
    }

    let mut evidence_ids = detector_ids(evidence, "oauth.flow.auth_code");
    evidence_ids.extend(detector_ids(evidence, "oauth.flow.framework_default"));
    if evidence_ids.is_empty() {
        evidence_ids = artifact.lifecycle_evidence.issue.clone();
    }

    Some(finding(
        artifact,
        FindingSpec {
            rule_id: "oauth_pkce_missing_review",
            category: FindingCategory::DynamicReviewRequired,
            severity: Severity::Medium,
            evidence_ids,
            title: "OAuth authorization-code flow has no source-visible PKCE evidence".to_string(),
            description: "The authorization-code flow construction was detected without a source-visible `code_challenge`, `code_challenge_method`, `code_verifier`, or library PKCE option in the same flow evidence. Some providers and client libraries enable PKCE by default, so this requires review rather than a deterministic misconfiguration conclusion.".to_string(),
            suggested_fix: "Configure PKCE explicitly with an S256 code challenge when the OAuth/OIDC client library allows it, or document the provider/library default that enforces PKCE.".to_string(),
            reviewer_question: "Does this OAuth/OIDC provider or client library enforce PKCE for this authorization-code flow in production?".to_string(),
        },
        report,
    ))
}

struct FindingSpec {
    rule_id: &'static str,
    category: FindingCategory,
    severity: Severity,
    evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
}

fn finding(artifact: &Artifact, spec: FindingSpec, report: &ScanReport) -> Finding {
    let evidence_part = spec
        .evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let path_part = first_evidence(report, &spec.evidence_ids)
        .map(|evidence| evidence.location.path.as_str())
        .unwrap_or("unknown_path");
    let id = stable_finding_id(&[
        spec.rule_id,
        artifact.id.0.as_str(),
        evidence_part,
        path_part,
    ]);

    Finding {
        id,
        category: spec.category,
        severity: spec.severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids: spec.evidence_ids,
        title: spec.title,
        description: spec.description,
        suggested_fix: Some(spec.suggested_fix),
        reviewer_question: Some(spec.reviewer_question),
    }
}

fn artifact_evidence<'a>(report: &'a ScanReport, artifact: &Artifact) -> Vec<&'a Evidence> {
    let ids = artifact_evidence_ids(artifact);
    report
        .evidence
        .iter()
        .filter(|evidence| ids.contains(&evidence.id))
        .collect()
}

fn artifact_evidence_ids(artifact: &Artifact) -> BTreeSet<EvidenceId> {
    artifact
        .lifecycle_evidence
        .issue
        .iter()
        .chain(&artifact.lifecycle_evidence.store)
        .chain(&artifact.lifecycle_evidence.transmit)
        .chain(&artifact.lifecycle_evidence.validate)
        .chain(&artifact.lifecycle_evidence.refresh)
        .chain(&artifact.lifecycle_evidence.revoke)
        .chain(&artifact.lifecycle_evidence.expire)
        .chain(&artifact.lifecycle_evidence.introspect)
        .cloned()
        .collect()
}

fn detector_ids(evidence: &[&Evidence], detector_id: &str) -> Vec<EvidenceId> {
    evidence
        .iter()
        .filter(|item| item.detector_id == detector_id)
        .map(|item| item.id.clone())
        .collect()
}

fn first_evidence<'a>(report: &'a ScanReport, ids: &[EvidenceId]) -> Option<&'a Evidence> {
    ids.iter()
        .find_map(|id| report.evidence.iter().find(|item| &item.id == id))
}

fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    findings
        .into_iter()
        .filter(|finding| seen.insert(finding.id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, LifecycleEvidence, LifecycleStage, SCHEMA_VERSION, ScanSummary,
        SourceLocation,
    };

    use super::*;

    fn report_with(detector_ids: &[&str]) -> ScanReport {
        let evidence = detector_ids
            .iter()
            .enumerate()
            .map(|(index, detector_id)| Evidence {
                id: EvidenceId(format!("evidence_{index}")),
                lifecycle_stage: LifecycleStage::Issue,
                location: SourceLocation {
                    path: "src/auth.ts".to_string(),
                    line: Some(index + 1),
                    column: Some(1),
                },
                detector_id: detector_id.to_string(),
                confidence: Confidence::High,
                excerpt: None,
                dynamic: false,
                framework_default: false,
            })
            .collect::<Vec<_>>();
        let mut lifecycle_evidence = LifecycleEvidence::default();
        lifecycle_evidence.issue = evidence.iter().map(|item| item.id.clone()).collect();

        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_oauth".to_string()),
                artifact_type: ArtifactType::OAuthAuthCodeFlow,
                display_name: Some("oauth_auth_code_flow".to_string()),
                locations: Vec::new(),
                lifecycle_evidence,
                confidence: Confidence::High,
                framework_hints: Vec::new(),
                cookie_attributes: None,
                jwt_attributes: None,
                token_boundary_attributes: None,
            }],
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn flags_auth_code_flow_without_pkce() {
        let report = report_with(&["oauth.flow.auth_code"]);
        let findings = classify(&report);

        assert!(findings.iter().any(|finding| {
            finding.title.contains("PKCE")
                && finding.category == FindingCategory::DynamicReviewRequired
                && finding.severity == Severity::Medium
                && finding.evidence_ids == vec![EvidenceId("evidence_0".to_string())]
        }));
    }

    #[test]
    fn suppresses_auth_code_flow_with_pkce() {
        let report = report_with(&["oauth.flow.auth_code", "oauth.pkce.present"]);

        assert!(classify(&report).is_empty());
    }
}
