use sessionscope_model::{
    Artifact, EvidenceId, Finding, FindingCategory, JwtAttributeObservation, JwtAttributeState,
    ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        let Some(attributes) = &artifact.jwt_attributes else {
            continue;
        };

        let name = artifact.display_name.as_deref().unwrap_or("unknown_jwt");

        if operation_contains(&attributes.operation, "decode_without_verify")
            || attributes.signature_verification.state == JwtAttributeState::Missing
        {
            findings.push(finding(
                "jwt_decode_without_verify",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                fallback_ids(
                    &attributes.signature_verification.evidence_ids,
                    &artifact.lifecycle_evidence.introspect,
                ),
                format!("JWT `{name}` is decoded or parsed without signature verification"),
                "Evidence shows this JWT path does not verify signatures before reading claims."
                    .to_string(),
                "Use a verification API with the expected issuer, audience, and signing key before trusting claims."
                    .to_string(),
                "Is this decoded JWT used only for non-security-sensitive introspection?".to_string(),
            ));
        }

        if !artifact.lifecycle_evidence.validate.is_empty() {
            findings.extend(classify_validation_field(
                artifact,
                name,
                "issuer",
                &attributes.issuer,
            ));
            findings.extend(classify_validation_field(
                artifact,
                name,
                "audience",
                &attributes.audience,
            ));
        }

        if !artifact.lifecycle_evidence.issue.is_empty() {
            match attributes.expiration.state {
                JwtAttributeState::Missing => findings.push(finding(
                    "jwt_missing_expiration",
                    FindingCategory::LifecycleGap,
                    Severity::Low,
                    artifact,
                    fallback_ids(
                        &attributes.expiration.evidence_ids,
                        &artifact.lifecycle_evidence.expire,
                    ),
                    format!("JWT `{name}` issue evidence has no expiration evidence"),
                    "JWT issue evidence was detected without a static expiration claim or option."
                        .to_string(),
                    "Set an explicit expiration claim or library expiration option when issuing JWTs."
                        .to_string(),
                    "Should this JWT have a bounded lifetime?".to_string(),
                )),
                JwtAttributeState::Dynamic => findings.push(finding(
                    "jwt_dynamic_expiration",
                    FindingCategory::DynamicReviewRequired,
                    Severity::Medium,
                    artifact,
                    fallback_ids(
                        &attributes.expiration.evidence_ids,
                        &artifact.lifecycle_evidence.expire,
                    ),
                    format!("JWT `{name}` expiration evidence is dynamic"),
                    "JWT expiration appears to depend on unresolved runtime options.".to_string(),
                    "Confirm the effective production lifetime and make the expiration explicit when possible."
                        .to_string(),
                    "What effective JWT lifetime is configured in production?".to_string(),
                )),
                _ => {}
            }
        }

        if !artifact.lifecycle_evidence.validate.is_empty()
            || !artifact.lifecycle_evidence.introspect.is_empty()
        {
            match attributes.expiry_enforcement.state {
                JwtAttributeState::Missing => findings.push(finding(
                    "jwt_expiry_enforcement_disabled",
                    FindingCategory::HighConfidenceMisconfiguration,
                    Severity::High,
                    artifact,
                    fallback_ids(
                        &attributes.expiry_enforcement.evidence_ids,
                        &artifact.lifecycle_evidence.validate,
                    ),
                    format!("JWT `{name}` expiry enforcement is disabled or absent"),
                    "Evidence shows this JWT validation path does not enforce expiration."
                        .to_string(),
                    "Require expiration enforcement when validating JWTs.".to_string(),
                    "Can expired tokens be accepted on this path?".to_string(),
                )),
                JwtAttributeState::Dynamic => findings.push(finding(
                    "jwt_dynamic_expiry_enforcement",
                    FindingCategory::DynamicReviewRequired,
                    Severity::Medium,
                    artifact,
                    fallback_ids(
                        &attributes.expiry_enforcement.evidence_ids,
                        &artifact.lifecycle_evidence.validate,
                    ),
                    format!("JWT `{name}` expiry enforcement is dynamic"),
                    "JWT expiry enforcement appears to depend on unresolved runtime options."
                        .to_string(),
                    "Confirm production verification rejects expired JWTs.".to_string(),
                    "What expiry enforcement settings are active in production?".to_string(),
                )),
                JwtAttributeState::FrameworkDefault => findings.push(finding(
                    "jwt_default_expiry_enforcement",
                    FindingCategory::FrameworkDefaultAssumed,
                    Severity::Low,
                    artifact,
                    fallback_ids(
                        &attributes.expiry_enforcement.evidence_ids,
                        &artifact.lifecycle_evidence.validate,
                    ),
                    format!("JWT `{name}` expiry enforcement relies on library defaults"),
                    "JWT validation appears to rely on the library default for expiration enforcement."
                        .to_string(),
                    "Make expiration enforcement explicit or document the library version and default."
                        .to_string(),
                    "Which JWT library version and settings determine expiration enforcement here?"
                        .to_string(),
                )),
                _ => {}
            }
        }
    }

    findings
}

fn classify_validation_field(
    artifact: &Artifact,
    name: &str,
    field_name: &str,
    observation: &JwtAttributeObservation,
) -> Option<Finding> {
    match observation.state {
        JwtAttributeState::Missing => Some(finding(
            &format!("jwt_missing_{field_name}"),
            FindingCategory::MissingValidationEvidence,
            Severity::Medium,
            artifact,
            fallback_ids(
                &observation.evidence_ids,
                &artifact.lifecycle_evidence.validate,
            ),
            format!("JWT `{name}` verification has no {field_name} evidence"),
            format!("JWT verification evidence does not include an expected {field_name} check."),
            format!("Require an expected {field_name} when verifying JWTs."),
            format!("Should this service reject tokens with an unexpected {field_name}?"),
        )),
        JwtAttributeState::Dynamic => Some(finding(
            &format!("jwt_dynamic_{field_name}"),
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            fallback_ids(
                &observation.evidence_ids,
                &artifact.lifecycle_evidence.validate,
            ),
            format!("JWT `{name}` {field_name} validation is dynamic"),
            format!("JWT {field_name} validation appears to depend on unresolved runtime options."),
            format!(
                "Confirm the effective production {field_name} and make it explicit when possible."
            ),
            format!("What {field_name} value is accepted in production?"),
        )),
        _ => None,
    }
}

fn finding(
    rule_id: &str,
    category: FindingCategory,
    severity: Severity,
    artifact: &Artifact,
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

fn fallback_ids(primary: &[EvidenceId], fallback: &[EvidenceId]) -> Vec<EvidenceId> {
    let mut ids = if primary.is_empty() {
        fallback.to_vec()
    } else {
        primary.to_vec()
    };
    ids.sort();
    ids.dedup();
    ids
}

fn operation_contains(operation: &JwtAttributeObservation, needle: &str) -> bool {
    operation
        .value
        .as_deref()
        .is_some_and(|value| value.split(',').any(|part| part.trim() == needle))
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, ArtifactType, Confidence, JwtAttributes, LifecycleEvidence, SCHEMA_VERSION,
        ScanSummary, SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![artifact],
            evidence: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(attributes: JwtAttributes, lifecycle_evidence: LifecycleEvidence) -> Artifact {
        Artifact {
            id: ArtifactId("artifact_access_jwt".to_string()),
            artifact_type: ArtifactType::AccessJwt,
            display_name: Some("access_jwt".to_string()),
            locations: vec![SourceLocation {
                path: "auth.ts".to_string(),
                line: Some(1),
                column: Some(1),
            }],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: vec!["jsonwebtoken".to_string()],
            cookie_attributes: None,
            jwt_attributes: Some(attributes),
        }
    }

    fn attributes(
        issuer: JwtAttributeState,
        audience: JwtAttributeState,
        expiration: JwtAttributeState,
        operation: &str,
    ) -> JwtAttributes {
        let operation_evidence = EvidenceId("evidence_operation".to_string());
        JwtAttributes {
            operation: observation(
                "operation",
                JwtAttributeState::Present,
                Some(operation),
                operation_evidence,
            ),
            algorithm: observation(
                "algorithm",
                JwtAttributeState::Present,
                Some("HS256"),
                EvidenceId("evidence_algorithm".to_string()),
            ),
            key_reference: observation(
                "key",
                JwtAttributeState::Present,
                Some("JWT_SECRET"),
                EvidenceId("evidence_key".to_string()),
            ),
            issuer: observation(
                "issuer",
                issuer,
                Some("ISSUER"),
                EvidenceId("evidence_issuer".to_string()),
            ),
            audience: observation(
                "audience",
                audience,
                Some("AUDIENCE"),
                EvidenceId("evidence_audience".to_string()),
            ),
            expiration: observation(
                "expiration",
                expiration,
                Some("15m"),
                EvidenceId("evidence_expiration".to_string()),
            ),
            signature_verification: observation(
                "signature_verification",
                if operation == "decode_without_verify" {
                    JwtAttributeState::Missing
                } else {
                    JwtAttributeState::Present
                },
                Some("verified"),
                EvidenceId("evidence_signature".to_string()),
            ),
            expiry_enforcement: observation(
                "expiry_enforcement",
                JwtAttributeState::Present,
                Some("explicit"),
                EvidenceId("evidence_expiry_enforcement".to_string()),
            ),
            identity_claims: None,
        }
    }

    fn observation(
        _name: &str,
        state: JwtAttributeState,
        value: Option<&str>,
        evidence_id: EvidenceId,
    ) -> JwtAttributeObservation {
        JwtAttributeObservation {
            state,
            value: value.map(str::to_string),
            evidence_ids: vec![evidence_id],
            confidence: match state {
                JwtAttributeState::Dynamic => Confidence::Medium,
                JwtAttributeState::FrameworkDefault => Confidence::Low,
                _ => Confidence::High,
            },
        }
    }

    #[test]
    fn missing_issuer_and_audience_on_verify_are_missing_validation_evidence() {
        let findings = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Missing,
                JwtAttributeState::Missing,
                JwtAttributeState::Present,
                "validate",
            ),
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.category == FindingCategory::MissingValidationEvidence)
                .count(),
            2
        );
    }

    #[test]
    fn dynamic_audience_requires_review_not_high_confidence() {
        let findings = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Present,
                JwtAttributeState::Dynamic,
                JwtAttributeState::Present,
                "validate",
            ),
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("audience")
        }));
    }

    #[test]
    fn issue_without_expiration_is_lifecycle_gap() {
        let findings = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Present,
                JwtAttributeState::Present,
                JwtAttributeState::Missing,
                "issue",
            ),
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("expiration")
        }));
    }

    #[test]
    fn decode_without_verify_is_high_confidence_misconfiguration() {
        let findings = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Unknown,
                JwtAttributeState::Unknown,
                JwtAttributeState::Unknown,
                "decode_without_verify",
            ),
            LifecycleEvidence {
                introspect: vec![EvidenceId("evidence_decode".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("without signature verification")
        }));
    }

    #[test]
    fn framework_default_expiry_enforcement_is_assumed() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.expiry_enforcement = observation(
            "expiry_enforcement",
            JwtAttributeState::FrameworkDefault,
            Some("library default"),
            EvidenceId("evidence_expiry_enforcement".to_string()),
        );

        let findings = classify_artifact(artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::FrameworkDefaultAssumed
                && finding.severity == Severity::Low
        }));
    }

    #[test]
    fn disabled_expiry_enforcement_is_high_confidence() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.expiry_enforcement = observation(
            "expiry_enforcement",
            JwtAttributeState::Missing,
            Some("ignoreExpiration: true"),
            EvidenceId("evidence_expiry_enforcement".to_string()),
        );

        let findings = classify_artifact(artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("expiry enforcement")
        }));
    }

    #[test]
    fn safe_jwt_validation_produces_no_findings() {
        let findings = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Present,
                JwtAttributeState::Present,
                JwtAttributeState::Present,
                "issue, validate",
            ),
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                validate: vec![EvidenceId("evidence_verify".to_string())],
                expire: vec![EvidenceId("evidence_expire".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(findings.is_empty());
    }
}
