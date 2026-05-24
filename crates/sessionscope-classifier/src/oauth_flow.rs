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
            findings.extend(classify_state(report, artifact, &evidence));
            findings.extend(classify_nonce(report, artifact, &evidence));
            findings.extend(classify_redirect_uri(report, artifact, &evidence));
        }
    }

    dedupe_findings(findings)
}

fn classify_redirect_uri(
    report: &ScanReport,
    artifact: &Artifact,
    evidence: &[&Evidence],
) -> Option<Finding> {
    if !evidence
        .iter()
        .any(|item| item.detector_id == "oauth.redirect_uri.broad")
    {
        return None;
    }

    Some(finding(
        artifact,
        FindingSpec {
            rule_id: "oauth_redirect_uri_wildcard_review",
            category: FindingCategory::DynamicReviewRequired,
            severity: Severity::Medium,
            evidence_ids: detector_ids(evidence, "oauth.redirect_uri.broad"),
            title: "OAuth redirect URI literal appears broad or wildcarded".to_string(),
            description: "A source-visible `redirect_uri` / `redirect_uris` literal contains a wildcard or broad host-only shape. Final matching is enforced by the authorization server, so this is review-required evidence rather than proof of provider-side configuration.".to_string(),
            suggested_fix: "Register exact redirect URIs with concrete hosts and callback paths; avoid wildcard or bare-host redirect URI entries unless the provider constrains them elsewhere.".to_string(),
            reviewer_question: "Does the authorization server restrict this client to exact redirect URIs despite the broad source literal?".to_string(),
        },
        report,
    ))
}

fn classify_nonce(
    report: &ScanReport,
    artifact: &Artifact,
    evidence: &[&Evidence],
) -> Vec<Finding> {
    if !evidence
        .iter()
        .any(|item| item.detector_id == "oauth.oidc.openid_scope")
    {
        return Vec::new();
    }

    let nonce_ids = detector_ids(evidence, "oauth.nonce.present");
    let has_nonce = !nonce_ids.is_empty();
    let has_verified = evidence
        .iter()
        .any(|item| item.detector_id == "oauth.nonce.verified");
    let mut findings = Vec::new();

    if !has_nonce {
        let mut ids = detector_ids(evidence, "oauth.oidc.openid_scope");
        ids.extend(detector_ids(evidence, "oauth.flow.auth_code"));
        findings.push(finding(
            artifact,
            FindingSpec {
                rule_id: "oidc_nonce_missing",
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::Medium,
                evidence_ids: ids,
                title: "OIDC authorization flow has no source-visible nonce parameter"
                    .to_string(),
                description: "The flow requests an OIDC `openid` scope, but SessionScope did not find source-visible nonce evidence in the authorization request construction.".to_string(),
                suggested_fix: "Generate a per-request nonce, include it in the OIDC authorization request, and verify the same nonce during ID-token validation.".to_string(),
                reviewer_question: "Does a framework/provider layer add an OIDC nonce for this authorization request?".to_string(),
            },
            report,
        ));
    } else if !has_verified {
        findings.push(finding(
            artifact,
            FindingSpec {
                rule_id: "oidc_nonce_unverified_review",
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::Medium,
                evidence_ids: nonce_ids,
                title: "OIDC nonce is set without visible ID-token nonce verification".to_string(),
                description: "OIDC flow evidence includes a nonce, but SessionScope did not find same-flow ID-token verification options or comparison evidence for that nonce.".to_string(),
                suggested_fix: "Pass the expected nonce to the ID-token verification API or compare the validated ID-token nonce claim with the issued nonce.".to_string(),
                reviewer_question: "Where is the OIDC nonce checked during ID-token verification?".to_string(),
            },
            report,
        ));
    }

    findings
}

fn classify_state(
    report: &ScanReport,
    artifact: &Artifact,
    evidence: &[&Evidence],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let has_state = evidence.iter().any(|item| {
        matches!(
            item.detector_id.as_str(),
            "oauth.state.present" | "oauth.state.static"
        )
    });
    let has_verified = evidence
        .iter()
        .any(|item| item.detector_id == "oauth.state.verified");

    if !has_state {
        findings.push(finding(
            artifact,
            FindingSpec {
                rule_id: "oauth_state_missing",
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::Medium,
                evidence_ids: detector_ids(evidence, "oauth.flow.auth_code"),
                title: "OAuth authorization-code flow has no source-visible state parameter"
                    .to_string(),
                description: "The authorization-code flow construction lacks source-visible `state` evidence. State is the caller-visible CSRF/correlation value that should be generated per authorization request and verified on callback.".to_string(),
                suggested_fix: "Generate a cryptographically random state value, bind it to server-side or signed client-side state, include it in the authorization request, and verify it on callback.".to_string(),
                reviewer_question: "Does another framework/provider layer add and validate OAuth state for this flow?".to_string(),
            },
            report,
        ));
    }

    if evidence
        .iter()
        .any(|item| item.detector_id == "oauth.state.static")
    {
        findings.push(finding(
            artifact,
            FindingSpec {
                rule_id: "oauth_state_static_review",
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                evidence_ids: detector_ids(evidence, "oauth.state.static"),
                title: "OAuth state appears to be assigned from a static literal".to_string(),
                description: "State evidence is source-visible but appears to come from a literal value rather than per-request cryptographic randomness. The literal value is redacted from evidence.".to_string(),
                suggested_fix: "Generate state with a cryptographically secure random source for each authorization request and avoid committing static state values.".to_string(),
                reviewer_question: "Is this literal only test code, or can production requests reuse the same OAuth state value?".to_string(),
            },
            report,
        ));
    }

    if evidence
        .iter()
        .any(|item| item.detector_id == "oauth.state.callback_read")
        && !has_verified
    {
        let mut ids = detector_ids(evidence, "oauth.state.callback_read");
        ids.extend(detector_ids(evidence, "oauth.state.present"));
        findings.push(finding(
            artifact,
            FindingSpec {
                rule_id: "oauth_state_unverified_review",
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::High,
                evidence_ids: ids,
                title: "OAuth callback reads state without visible verification".to_string(),
                description: "Callback evidence reads an OAuth `state` value, but SessionScope did not find a source-visible comparison against server-side session/cache state or a signed cookie/helper value in the same flow evidence.".to_string(),
                suggested_fix: "Compare the callback state with the value stored when the authorization request was issued, then reject mismatches before exchanging the code.".to_string(),
                reviewer_question: "Where is this callback state compared with the originally issued state value?".to_string(),
            },
            report,
        ));
    }

    findings
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
        let lifecycle_evidence = LifecycleEvidence {
            issue: evidence.iter().map(|item| item.id.clone()).collect(),
            ..Default::default()
        };

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

        assert!(
            classify(&report)
                .iter()
                .all(|finding| !finding.title.contains("PKCE"))
        );
    }

    #[test]
    fn flags_missing_static_and_unverified_state() {
        let missing = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
        ]));
        assert!(
            missing
                .iter()
                .any(|finding| finding.title.contains("no source-visible state"))
        );

        let static_state = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.static",
        ]));
        assert!(
            static_state
                .iter()
                .any(|finding| finding.title.contains("static literal"))
        );

        let unverified = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.callback_read",
        ]));
        assert!(unverified.iter().any(|finding| {
            finding.title.contains("without visible verification")
                && finding.severity == Severity::High
        }));
    }

    #[test]
    fn suppresses_state_findings_when_state_is_verified() {
        let report = report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
        ]);

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn verified_callback_state_does_not_suppress_missing_state() {
        let findings = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.callback_read",
            "oauth.state.verified",
        ]));

        assert!(findings.iter().any(|finding| {
            finding.id.0.contains("oauth_state_missing")
                || finding.title.contains("no source-visible state")
        }));
    }

    #[test]
    fn flags_oidc_nonce_missing_and_unverified() {
        let missing = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.oidc.openid_scope",
        ]));
        assert!(
            missing
                .iter()
                .any(|finding| finding.title.contains("no source-visible nonce"))
        );

        let unverified = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.oidc.openid_scope",
            "oauth.nonce.present",
        ]));
        assert!(unverified.iter().any(|finding| {
            finding
                .title
                .contains("without visible ID-token nonce verification")
        }));
    }

    #[test]
    fn suppresses_nonce_checks_for_oauth_only_and_verified_oidc() {
        let oauth_only = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
        ]));
        assert!(oauth_only.is_empty());

        let verified = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.oidc.openid_scope",
            "oauth.nonce.present",
            "oauth.nonce.verified",
        ]));
        assert!(verified.is_empty());
    }

    #[test]
    fn verified_oidc_nonce_does_not_suppress_missing_nonce() {
        let findings = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.oidc.openid_scope",
            "oauth.nonce.verified",
        ]));

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("no source-visible nonce")),
            "{findings:?}"
        );
    }

    #[test]
    fn flags_broad_redirect_uri_literals() {
        let findings = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.redirect_uri.literal",
            "oauth.redirect_uri.broad",
        ]));

        assert!(findings.iter().any(|finding| {
            finding.title.contains("redirect URI")
                && finding.category == FindingCategory::DynamicReviewRequired
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn suppresses_exact_redirect_uri_literals() {
        let findings = classify(&report_with(&[
            "oauth.flow.auth_code",
            "oauth.pkce.present",
            "oauth.state.present",
            "oauth.state.verified",
            "oauth.redirect_uri.literal",
        ]));

        assert!(findings.is_empty());
    }
}
