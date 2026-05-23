use std::collections::BTreeSet;

use sessionscope_model::{
    Artifact, EvidenceId, Finding, FindingCategory, ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for evidence in &report.evidence {
        let spec = match evidence.detector_id.as_str() {
            "client_storage.local_storage.set_item" => Some((
                "token_in_local_storage",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                "Token is stored in localStorage",
                "Token-shaped evidence is written to localStorage, where browser JavaScript can read it and where it can persist beyond the intended authentication lifecycle.",
                "Use an HttpOnly, Secure cookie or another storage pattern that prevents direct script access when possible.",
                "Can this token be moved out of localStorage on every production path?",
            )),
            "client_storage.session_storage.set_item" => Some((
                "token_in_session_storage",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                "Token is stored in sessionStorage",
                "Token-shaped evidence is written to sessionStorage, where browser JavaScript can read it for the lifetime of the tab/session.",
                "Use an HttpOnly, Secure cookie or another storage pattern that prevents direct script access when possible.",
                "Can this token be moved out of sessionStorage on every production path?",
            )),
            "client_storage.url_path_or_fragment.token" => Some((
                "token_in_url_path_or_fragment",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                "Token-shaped value is embedded in a URL path or fragment",
                "Token-shaped evidence appears in a URL path segment or fragment identifier. URL material can be logged, cached, copied, or exposed to browser history and referrers depending on use.",
                "Keep tokens out of URLs; transmit them through safer authorization channels or server-managed session state.",
                "Can this URL construction avoid embedding token-shaped material in the path or fragment?",
            )),
            "client_storage.browser.client_secret" => Some((
                "client_secret_in_browser_code",
                FindingCategory::DynamicReviewRequired,
                Severity::High,
                "Client secret-like evidence appears in browser-shipped code",
                "A `client_secret` / `clientSecret` literal or identifier appears in a path that matches browser-client heuristics. SessionScope cannot prove bundling/runtime reachability, so this requires review.",
                "Keep OAuth client secrets server-side only; browser clients should use public-client flows such as authorization code with PKCE and no client secret.",
                "Is this file ever bundled or served to a browser in production?",
            )),
            _ => None,
        };

        if let Some((
            rule_id,
            category,
            severity,
            title,
            description,
            suggested_fix,
            reviewer_question,
        )) = spec
        {
            let artifact_ids = artifacts_for_evidence(report, &evidence.id);
            findings.push(Finding {
                id: stable_finding_id(&[
                    rule_id,
                    evidence.id.0.as_str(),
                    evidence.location.path.as_str(),
                ]),
                category,
                severity,
                artifact_ids: artifact_ids
                    .iter()
                    .map(|artifact| artifact.id.clone())
                    .collect(),
                evidence_ids: vec![evidence.id.clone()],
                title: title.to_string(),
                description: description.to_string(),
                suggested_fix: Some(suggested_fix.to_string()),
                reviewer_question: Some(reviewer_question.to_string()),
            });
        }
    }

    dedupe_findings(findings)
}

fn artifacts_for_evidence<'a>(
    report: &'a ScanReport,
    evidence_id: &EvidenceId,
) -> Vec<&'a Artifact> {
    report
        .artifacts
        .iter()
        .filter(|artifact| artifact_has_evidence(artifact, evidence_id))
        .collect()
}

fn artifact_has_evidence(artifact: &Artifact, evidence_id: &EvidenceId) -> bool {
    artifact.lifecycle_evidence.issue.contains(evidence_id)
        || artifact.lifecycle_evidence.store.contains(evidence_id)
        || artifact.lifecycle_evidence.transmit.contains(evidence_id)
        || artifact.lifecycle_evidence.validate.contains(evidence_id)
        || artifact.lifecycle_evidence.refresh.contains(evidence_id)
        || artifact.lifecycle_evidence.revoke.contains(evidence_id)
        || artifact.lifecycle_evidence.expire.contains(evidence_id)
        || artifact.lifecycle_evidence.introspect.contains(evidence_id)
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
        ArtifactId, ArtifactType, Confidence, Evidence, LifecycleEvidence, LifecycleStage,
        SCHEMA_VERSION, ScanSummary, SourceLocation,
    };

    use super::*;

    fn report_with(detector_id: &str) -> ScanReport {
        let evidence_id = EvidenceId("evidence_storage".to_string());
        let mut lifecycle_evidence = LifecycleEvidence::default();
        lifecycle_evidence.store.push(evidence_id.clone());
        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_storage".to_string()),
                artifact_type: ArtifactType::AccessJwt,
                display_name: Some("access_token".to_string()),
                locations: Vec::new(),
                lifecycle_evidence,
                confidence: Confidence::High,
                framework_hints: Vec::new(),
                cookie_attributes: None,
                jwt_attributes: None,
                token_boundary_attributes: None,
            }],
            evidence: vec![Evidence {
                id: evidence_id,
                lifecycle_stage: LifecycleStage::Store,
                location: SourceLocation {
                    path: "src/components/auth.tsx".to_string(),
                    line: Some(12),
                    column: Some(1),
                },
                detector_id: detector_id.to_string(),
                confidence: Confidence::High,
                excerpt: None,
                dynamic: false,
                framework_default: false,
            }],
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn classifies_client_storage_findings() {
        for (detector_id, rule_title) in [
            ("client_storage.local_storage.set_item", "localStorage"),
            ("client_storage.session_storage.set_item", "sessionStorage"),
            (
                "client_storage.url_path_or_fragment.token",
                "URL path or fragment",
            ),
            ("client_storage.browser.client_secret", "Client secret-like"),
        ] {
            let findings = classify(&report_with(detector_id));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.title.contains(rule_title)),
                "missing {rule_title}"
            );
        }
    }
}
