use sessionscope_model::{
    Artifact, Evidence, EvidenceId, Finding, FindingCategory, JwtAttributeObservation,
    JwtAttributeState, ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        let Some(attributes) = &artifact.jwt_attributes else {
            continue;
        };

        let name = artifact.display_name.as_deref().unwrap_or("unknown_jwt");

        if !artifact.lifecycle_evidence.validate.is_empty() {
            findings.extend(classify_alg_none(report, artifact, name, attributes));
            findings.extend(classify_alg_confusion(report, artifact, name, attributes));
        }

        if operation_contains(&attributes.operation, "decode_without_verify")
            || attributes.signature_verification.state == JwtAttributeState::Missing
        {
            findings.push(finding(
                artifact,
                FindingRequest {
                    rule_id: "jwt_decode_without_verify".to_string(),
                    category: FindingCategory::HighConfidenceMisconfiguration,
                    severity: Severity::High,
                    evidence_ids: fallback_ids(
                        &attributes.signature_verification.evidence_ids,
                        &artifact.lifecycle_evidence.introspect,
                    ),
                    title: format!(
                        "JWT `{name}` is decoded or parsed without signature verification"
                    ),
                    description:
                        "Evidence shows this JWT path does not verify signatures before reading claims."
                            .to_string(),
                    suggested_fix:
                        "Use a verification API with the expected issuer, audience, and signing key before trusting claims."
                            .to_string(),
                    reviewer_question:
                        "Is this decoded JWT used only for non-security-sensitive introspection?"
                            .to_string(),
                },
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
                    artifact,
                    FindingRequest {
                        rule_id: "jwt_missing_expiration".to_string(),
                        category: FindingCategory::LifecycleGap,
                        severity: Severity::Low,
                        evidence_ids: fallback_ids(
                            &attributes.expiration.evidence_ids,
                            &artifact.lifecycle_evidence.expire,
                        ),
                        title: format!("JWT `{name}` issue evidence has no expiration evidence"),
                        description:
                            "JWT issue evidence was detected without a static expiration claim or option."
                                .to_string(),
                        suggested_fix:
                            "Set an explicit expiration claim or library expiration option when issuing JWTs."
                                .to_string(),
                        reviewer_question: "Should this JWT have a bounded lifetime?".to_string(),
                    },
                )),
                JwtAttributeState::Dynamic => findings.push(finding(
                    artifact,
                    FindingRequest {
                        rule_id: "jwt_dynamic_expiration".to_string(),
                        category: FindingCategory::DynamicReviewRequired,
                        severity: Severity::Medium,
                        evidence_ids: fallback_ids(
                            &attributes.expiration.evidence_ids,
                            &artifact.lifecycle_evidence.expire,
                        ),
                        title: format!("JWT `{name}` expiration evidence is dynamic"),
                        description:
                            "JWT expiration appears to depend on unresolved runtime options."
                                .to_string(),
                        suggested_fix:
                            "Confirm the effective production lifetime and make the expiration explicit when possible."
                                .to_string(),
                        reviewer_question:
                            "What effective JWT lifetime is configured in production?".to_string(),
                    },
                )),
                _ => {}
            }
        }

        if !artifact.lifecycle_evidence.validate.is_empty()
            || !artifact.lifecycle_evidence.introspect.is_empty()
        {
            match attributes.expiry_enforcement.state {
                JwtAttributeState::Missing => findings.push(finding(
                    artifact,
                    FindingRequest {
                        rule_id: "jwt_expiry_enforcement_disabled".to_string(),
                        category: FindingCategory::HighConfidenceMisconfiguration,
                        severity: Severity::High,
                        evidence_ids: fallback_ids(
                            &attributes.expiry_enforcement.evidence_ids,
                            &artifact.lifecycle_evidence.validate,
                        ),
                        title: format!("JWT `{name}` expiry enforcement is disabled or absent"),
                        description:
                            "Evidence shows this JWT validation path does not enforce expiration."
                                .to_string(),
                        suggested_fix: "Require expiration enforcement when validating JWTs."
                            .to_string(),
                        reviewer_question: "Can expired tokens be accepted on this path?"
                            .to_string(),
                    },
                )),
                JwtAttributeState::Dynamic => findings.push(finding(
                    artifact,
                    FindingRequest {
                        rule_id: "jwt_dynamic_expiry_enforcement".to_string(),
                        category: FindingCategory::DynamicReviewRequired,
                        severity: Severity::Medium,
                        evidence_ids: fallback_ids(
                            &attributes.expiry_enforcement.evidence_ids,
                            &artifact.lifecycle_evidence.validate,
                        ),
                        title: format!("JWT `{name}` expiry enforcement is dynamic"),
                        description:
                            "JWT expiry enforcement appears to depend on unresolved runtime options."
                                .to_string(),
                        suggested_fix: "Confirm production verification rejects expired JWTs."
                            .to_string(),
                        reviewer_question:
                            "What expiry enforcement settings are active in production?"
                                .to_string(),
                    },
                )),
                JwtAttributeState::FrameworkDefault => findings.push(finding(
                    artifact,
                    FindingRequest {
                        rule_id: "jwt_default_expiry_enforcement".to_string(),
                        category: FindingCategory::FrameworkDefaultAssumed,
                        severity: Severity::Low,
                        evidence_ids: fallback_ids(
                            &attributes.expiry_enforcement.evidence_ids,
                            &artifact.lifecycle_evidence.validate,
                        ),
                        title: format!(
                            "JWT `{name}` expiry enforcement relies on library defaults"
                        ),
                        description:
                            "JWT validation appears to rely on the library default for expiration enforcement."
                                .to_string(),
                        suggested_fix:
                            "Make expiration enforcement explicit or document the library version and default."
                                .to_string(),
                        reviewer_question:
                            "Which JWT library version and settings determine expiration enforcement here?"
                                .to_string(),
                    },
                )),
                _ => {}
            }
        }
    }

    findings
}

fn classify_alg_none(
    report: &ScanReport,
    artifact: &Artifact,
    name: &str,
    attributes: &sessionscope_model::JwtAttributes,
) -> Option<Finding> {
    let algorithm_option = artifact_bound_evidence(report, artifact, "jwt.option.algorithms");
    let has_dynamic_algorithm_option = algorithm_option.iter().any(|evidence| evidence.dynamic);
    let has_literal_none_option = algorithm_option.iter().any(evidence_mentions_none);
    let has_literal_none_attribute = observation_contains_literal(&attributes.algorithm, "none");

    if has_literal_none_option || has_literal_none_attribute {
        let mut evidence_ids = algorithm_option
            .iter()
            .map(|evidence| evidence.id.clone())
            .collect::<Vec<_>>();
        evidence_ids.extend(attributes.algorithm.evidence_ids.clone());
        evidence_ids.sort();
        evidence_ids.dedup();
        return Some(finding(
            artifact,
            FindingRequest {
                rule_id: "jwt_alg_none_accepted".to_string(),
                category: FindingCategory::HighConfidenceMisconfiguration,
                severity: Severity::High,
                evidence_ids: fallback_ids(&evidence_ids, &artifact.lifecycle_evidence.validate),
                title: format!("JWT `{name}` validation accepts the `none` algorithm"),
                description:
                    "JWT verification evidence includes an explicit `none` algorithm allow-list entry."
                        .to_string(),
                suggested_fix:
                    "Remove `none` from accepted algorithms and pin the expected signing algorithm."
                        .to_string(),
                reviewer_question:
                    "Is any validation path intentionally accepting unsigned JWTs?".to_string(),
            },
        ));
    }

    if has_dynamic_algorithm_option || attributes.algorithm.state == JwtAttributeState::Dynamic {
        return None;
    }

    if attributes.algorithm.state == JwtAttributeState::Unknown
        && library_has_default_alg_none_risk(artifact)
    {
        return Some(finding(
            artifact,
            FindingRequest {
                rule_id: "jwt_alg_none_accepted".to_string(),
                category: FindingCategory::FrameworkDefaultAssumed,
                severity: Severity::Medium,
                evidence_ids: artifact.lifecycle_evidence.validate.clone(),
                title: format!("JWT `{name}` validation relies on JWT algorithm defaults"),
                description:
                    "JWT verification evidence does not pin accepted algorithms for a library path with historically configuration-dependent `none` handling."
                        .to_string(),
                suggested_fix:
                    "Pass an explicit safe algorithms allow-list when verifying JWTs."
                        .to_string(),
                reviewer_question:
                    "Which library version and configuration define the accepted JWT algorithms here?"
                        .to_string(),
            },
        ));
    }

    None
}

fn classify_alg_confusion(
    report: &ScanReport,
    artifact: &Artifact,
    name: &str,
    attributes: &sessionscope_model::JwtAttributes,
) -> Option<Finding> {
    let algorithm_option = artifact_bound_evidence(report, artifact, "jwt.option.algorithms");
    let algorithms = accepted_algorithms(&algorithm_option, &attributes.algorithm);
    if algorithms.is_empty() {
        return None;
    }

    let accepts_hmac = algorithms
        .iter()
        .any(|algorithm| is_hmac_algorithm(algorithm));
    let accepts_asymmetric = algorithms
        .iter()
        .any(|algorithm| is_asymmetric_algorithm(algorithm));
    let public_key_reference = public_key_like_reference(&attributes.key_reference);

    if accepts_hmac && accepts_asymmetric {
        return Some(finding(
            artifact,
            FindingRequest {
                rule_id: "jwt_alg_confusion_signal".to_string(),
                category: FindingCategory::HighConfidenceMisconfiguration,
                severity: Severity::High,
                evidence_ids: algorithm_and_key_evidence_ids(&algorithm_option, attributes),
                title: format!(
                    "JWT `{name}` validation accepts both HMAC and asymmetric algorithms"
                ),
                description:
                    "JWT verification evidence allows both symmetric HMAC and asymmetric algorithms on the same validation path."
                        .to_string(),
                suggested_fix:
                    "Pin one expected algorithm family for this key type and separate symmetric and asymmetric validation paths."
                        .to_string(),
                reviewer_question:
                    "Can an attacker influence the token algorithm header on this validation path?"
                        .to_string(),
            },
        ));
    }

    if accepts_hmac && public_key_reference {
        return Some(finding(
            artifact,
            FindingRequest {
                rule_id: "jwt_alg_confusion_signal".to_string(),
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                evidence_ids: algorithm_and_key_evidence_ids(&algorithm_option, attributes),
                title: format!(
                    "JWT `{name}` validation pairs HMAC algorithms with public-key-like material"
                ),
                description:
                    "JWT verification evidence accepts an HMAC algorithm while the key reference appears public-key-like."
                        .to_string(),
                suggested_fix:
                    "Confirm the key material type and pin algorithms that match the expected key family."
                        .to_string(),
                reviewer_question:
                    "Is this key reference a symmetric secret or an asymmetric public key?".to_string(),
            },
        ));
    }

    None
}

fn accepted_algorithms(
    algorithm_option: &[&Evidence],
    observation: &JwtAttributeObservation,
) -> Vec<String> {
    let mut algorithms = Vec::new();
    for evidence in algorithm_option {
        if let Some(excerpt) = &evidence.excerpt {
            algorithms.extend(algorithm_tokens(excerpt.as_str()));
        }
    }
    if let Some(value) = &observation.value {
        algorithms.extend(algorithm_tokens(value));
    }
    algorithms.sort();
    algorithms.dedup();
    algorithms
}

fn algorithm_tokens(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter_map(|part| {
            let upper = part.to_ascii_uppercase();
            (is_hmac_algorithm(&upper) || is_asymmetric_algorithm(&upper) || upper == "NONE")
                .then_some(upper)
        })
        .collect()
}

fn is_hmac_algorithm(algorithm: &str) -> bool {
    matches!(algorithm, "HS256" | "HS384" | "HS512")
}

fn is_asymmetric_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512"
    )
}

fn public_key_like_reference(observation: &JwtAttributeObservation) -> bool {
    let Some(value) = observation.value.as_ref() else {
        return false;
    };
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '.')
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.contains("secret") || normalized.contains("private") {
        return false;
    }
    normalized.contains("publickey")
        || normalized.contains("pubkey")
        || normalized.contains("loadpublickey")
        || normalized.ends_with(".pem")
}

fn algorithm_and_key_evidence_ids(
    algorithm_option: &[&Evidence],
    attributes: &sessionscope_model::JwtAttributes,
) -> Vec<EvidenceId> {
    let mut evidence_ids = algorithm_option
        .iter()
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();
    evidence_ids.extend(attributes.algorithm.evidence_ids.clone());
    evidence_ids.extend(attributes.key_reference.evidence_ids.clone());
    evidence_ids.sort();
    evidence_ids.dedup();
    evidence_ids
}

fn artifact_bound_evidence<'a>(
    report: &'a ScanReport,
    artifact: &Artifact,
    detector_id: &str,
) -> Vec<&'a Evidence> {
    report
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == detector_id)
        .filter(|evidence| artifact.lifecycle_evidence.validate.contains(&evidence.id))
        .collect()
}

fn evidence_mentions_none(evidence: &&Evidence) -> bool {
    evidence.excerpt.as_ref().is_some_and(|excerpt| {
        text_mentions_literal(&excerpt.as_str().to_ascii_lowercase(), "none")
    })
}

fn observation_contains_literal(observation: &JwtAttributeObservation, literal: &str) -> bool {
    observation.value.as_ref().is_some_and(|value| {
        text_mentions_literal(&value.to_ascii_lowercase(), &literal.to_ascii_lowercase())
    })
}

fn text_mentions_literal(text: &str, literal: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| part == literal)
}

fn library_has_default_alg_none_risk(artifact: &Artifact) -> bool {
    artifact
        .framework_hints
        .iter()
        .any(|hint| matches!(hint.as_str(), "jsonwebtoken" | "pyjwt" | "PyJWT" | "jwt"))
}

fn classify_validation_field(
    artifact: &Artifact,
    name: &str,
    field_name: &str,
    observation: &JwtAttributeObservation,
) -> Option<Finding> {
    match observation.state {
        JwtAttributeState::Missing => Some(finding(
            artifact,
            FindingRequest {
                rule_id: format!("jwt_missing_{field_name}"),
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::Medium,
                evidence_ids: fallback_ids(
                    &observation.evidence_ids,
                    &artifact.lifecycle_evidence.validate,
                ),
                title: format!("JWT `{name}` verification has no {field_name} evidence"),
                description: format!(
                    "JWT verification evidence does not include an expected {field_name} check."
                ),
                suggested_fix: format!("Require an expected {field_name} when verifying JWTs."),
                reviewer_question: format!(
                    "Should this service reject tokens with an unexpected {field_name}?"
                ),
            },
        )),
        JwtAttributeState::Dynamic => Some(finding(
            artifact,
            FindingRequest {
                rule_id: format!("jwt_dynamic_{field_name}"),
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                evidence_ids: fallback_ids(
                    &observation.evidence_ids,
                    &artifact.lifecycle_evidence.validate,
                ),
                title: format!("JWT `{name}` {field_name} validation is dynamic"),
                description: format!(
                    "JWT {field_name} validation appears to depend on unresolved runtime options."
                ),
                suggested_fix: format!(
                    "Confirm the effective production {field_name} and make it explicit when possible."
                ),
                reviewer_question: format!("What {field_name} value is accepted in production?"),
            },
        )),
        _ => None,
    }
}

struct FindingRequest {
    rule_id: String,
    category: FindingCategory,
    severity: Severity,
    evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
}

fn finding(artifact: &Artifact, request: FindingRequest) -> Finding {
    let evidence_part = request
        .evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let name_part = artifact.display_name.as_deref().unwrap_or("dynamic");
    let id = stable_finding_id(&[
        request.rule_id.as_str(),
        artifact.id.0.as_str(),
        evidence_part,
        name_part,
    ]);

    Finding {
        id,
        category: request.category,
        severity: request.severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids: request.evidence_ids,
        title: request.title,
        description: request.description,
        suggested_fix: Some(request.suggested_fix),
        reviewer_question: Some(request.reviewer_question),
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
        ArtifactId, ArtifactType, Confidence, JwtAttributes, LifecycleEvidence, LifecycleStage,
        SCHEMA_VERSION, SanitizedExcerpt, ScanSummary, SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact) -> Vec<Finding> {
        classify_report(vec![artifact], Vec::new())
    }

    fn classify_report(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> Vec<Finding> {
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
            token_boundary_attributes: None,
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

    fn option_evidence(id: &str, detector_id: &str, excerpt: &str, dynamic: bool) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: LifecycleStage::Validate,
            location: SourceLocation {
                path: "auth.ts".to_string(),
                line: Some(1),
                column: Some(1),
            },
            detector_id: detector_id.to_string(),
            confidence: if dynamic {
                Confidence::Medium
            } else {
                Confidence::High
            },
            excerpt: Some(SanitizedExcerpt::from_sanitized(excerpt.to_string())),
            dynamic,
            framework_default: false,
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
    fn literal_none_algorithm_is_high_confidence() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Present,
            Some("none"),
            EvidenceId("evidence_algorithm".to_string()),
        );
        let mut artifact = artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![
                    EvidenceId("evidence_verify".to_string()),
                    EvidenceId("evidence_option_algorithms".to_string()),
                ],
                ..LifecycleEvidence::default()
            },
        );
        artifact.framework_hints = vec!["jsonwebtoken".to_string()];
        let findings = classify_report(
            vec![artifact],
            vec![option_evidence(
                "evidence_option_algorithms",
                "jwt.option.algorithms",
                r#"algorithms: ["none"]"#,
                false,
            )],
        );

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("`none` algorithm"))
            .expect("alg none finding");
        assert_eq!(
            finding.category,
            FindingCategory::HighConfidenceMisconfiguration
        );
        assert_eq!(finding.severity, Severity::High);
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_option_algorithms".to_string()))
        );
    }

    #[test]
    fn missing_algorithm_allowlist_on_default_sensitive_library_is_framework_default() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Unknown,
            None,
            EvidenceId("evidence_algorithm".to_string()),
        );
        let mut artifact = artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        artifact.framework_hints = vec!["pyjwt".to_string()];

        let findings = classify_artifact(artifact);

        assert!(findings.iter().any(|finding| {
            finding.title.contains("algorithm defaults")
                && finding.category == FindingCategory::FrameworkDefaultAssumed
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn dynamic_algorithm_options_do_not_emit_alg_none_finding() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Dynamic,
            None,
            EvidenceId("evidence_algorithm".to_string()),
        );
        let artifact = artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![
                    EvidenceId("evidence_verify".to_string()),
                    EvidenceId("evidence_option_algorithms".to_string()),
                ],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_report(
            vec![artifact],
            vec![option_evidence(
                "evidence_option_algorithms",
                "jwt.option.algorithms",
                "JWT algorithms option depends on unresolved JWT options",
                true,
            )],
        );

        assert!(
            findings
                .iter()
                .all(|finding| !finding.title.contains("`none` algorithm"))
        );
    }

    #[test]
    fn mixed_hmac_and_asymmetric_algorithms_signal_confusion() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Present,
            Some("HS256, RS256"),
            EvidenceId("evidence_algorithm".to_string()),
        );
        attributes.key_reference = observation(
            "key",
            JwtAttributeState::Present,
            Some("verificationKey"),
            EvidenceId("evidence_key".to_string()),
        );
        let artifact = artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![
                    EvidenceId("evidence_verify".to_string()),
                    EvidenceId("evidence_option_algorithms".to_string()),
                ],
                ..LifecycleEvidence::default()
            },
        );

        let findings = classify_report(
            vec![artifact],
            vec![option_evidence(
                "evidence_option_algorithms",
                "jwt.option.algorithms",
                r#"algorithms: ["HS256", "RS256"]"#,
                false,
            )],
        );

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("HMAC and asymmetric"))
            .expect("algorithm confusion finding");
        assert_eq!(
            finding.category,
            FindingCategory::HighConfidenceMisconfiguration
        );
        assert_eq!(finding.severity, Severity::High);
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_option_algorithms".to_string()))
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_key".to_string()))
        );
    }

    #[test]
    fn public_key_like_reference_with_hmac_requires_review() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Present,
            Some("HS256"),
            EvidenceId("evidence_algorithm".to_string()),
        );
        attributes.key_reference = observation(
            "key",
            JwtAttributeState::Present,
            Some("publicKey"),
            EvidenceId("evidence_key".to_string()),
        );
        let artifact = artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        );

        let findings = classify_artifact(artifact);

        assert!(findings.iter().any(|finding| {
            finding.title.contains("public-key-like")
                && finding.category == FindingCategory::DynamicReviewRequired
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn matching_key_family_algorithms_do_not_signal_confusion() {
        let hs_secret = classify_artifact(artifact(
            attributes(
                JwtAttributeState::Present,
                JwtAttributeState::Present,
                JwtAttributeState::Present,
                "validate",
            ),
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        let mut rs_attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        rs_attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Present,
            Some("RS256"),
            EvidenceId("evidence_algorithm".to_string()),
        );
        rs_attributes.key_reference = observation(
            "key",
            JwtAttributeState::Present,
            Some("publicKey"),
            EvidenceId("evidence_key".to_string()),
        );
        let rs_public = classify_artifact(artifact(
            rs_attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(hs_secret.iter().chain(rs_public.iter()).all(|finding| {
            !finding.title.contains("HMAC and asymmetric")
                && !finding.title.contains("public-key-like")
        }));
    }

    #[test]
    fn public_secret_name_does_not_signal_public_key_confusion() {
        let mut attributes = attributes(
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            JwtAttributeState::Present,
            "validate",
        );
        attributes.algorithm = observation(
            "algorithm",
            JwtAttributeState::Present,
            Some("HS256"),
            EvidenceId("evidence_algorithm".to_string()),
        );
        attributes.key_reference = observation(
            "key",
            JwtAttributeState::Present,
            Some("publicSecret"),
            EvidenceId("evidence_key".to_string()),
        );
        let findings = classify_artifact(artifact(
            attributes,
            LifecycleEvidence {
                validate: vec![EvidenceId("evidence_verify".to_string())],
                ..LifecycleEvidence::default()
            },
        ));

        assert!(
            findings
                .iter()
                .all(|finding| !finding.title.contains("public-key-like"))
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
