use sessionscope_model::{
    Artifact, ArtifactType, Confidence, CookieAttributeObservation, CookieAttributeState,
    EvidenceId, Finding, FindingCategory, ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for artifact in &report.artifacts {
        let Some(attributes) = &artifact.cookie_attributes else {
            continue;
        };

        let cookie_name = artifact.display_name.as_deref().unwrap_or("unknown cookie");
        let session_like = is_session_like_cookie(artifact);
        let has_static_name = artifact.display_name.is_some();

        if session_like {
            findings.extend(classify_http_only(
                artifact,
                cookie_name,
                &attributes.http_only,
            ));
        }

        if has_static_name {
            findings.extend(classify_secure(artifact, cookie_name, &attributes.secure));
        }

        findings.extend(classify_same_site_none_without_secure(
            artifact,
            cookie_name,
            &attributes.same_site,
            &attributes.secure,
        ));

        if session_like || artifact.artifact_type == ArtifactType::SignedCookie {
            findings.extend(classify_expiry(
                artifact,
                cookie_name,
                &attributes.max_age,
                &attributes.expires,
            ));
        }
    }

    findings
}

fn classify_http_only(
    artifact: &Artifact,
    cookie_name: &str,
    http_only: &CookieAttributeObservation,
) -> Option<Finding> {
    match http_only.state {
        CookieAttributeState::Missing if http_only.confidence == Confidence::High => {
            Some(finding(
                "cookie_missing_httponly",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                http_only.evidence_ids.clone(),
                format!("Session-like cookie `{cookie_name}` does not set HttpOnly"),
                "No HttpOnly attribute evidence was detected for this cookie-setting call."
                    .to_string(),
                "Set HttpOnly on session cookies so client-side scripts cannot read them."
                    .to_string(),
                "Is this cookie intended to be inaccessible to browser JavaScript?".to_string(),
            ))
        }
        CookieAttributeState::FrameworkDefault
            if observation_value_is_false(http_only) && http_only.confidence == Confidence::Low =>
        {
            Some(finding(
                "cookie_default_false_httponly",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                http_only.evidence_ids.clone(),
                format!("Session-like cookie `{cookie_name}` defaults HttpOnly to false"),
                "Framework default evidence indicates HttpOnly is false for this cookie-setting call."
                    .to_string(),
                "Set HttpOnly explicitly on session cookies so client-side scripts cannot read them."
                    .to_string(),
                "Is this cookie intended to be inaccessible to browser JavaScript?".to_string(),
            ))
        }
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_dynamic_httponly",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            http_only.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` has dynamic HttpOnly evidence"),
            "The HttpOnly attribute appears to depend on a non-literal expression."
                .to_string(),
            "Confirm the effective production value and set HttpOnly explicitly when possible."
                .to_string(),
            "Can production guarantee HttpOnly is enabled for this cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_default_httponly",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Low,
            artifact,
            http_only.evidence_ids.clone(),
            format!("Session-like cookie `{cookie_name}` relies on HttpOnly framework default"),
            "The local code does not set HttpOnly directly; behavior appears to depend on a framework default."
                .to_string(),
            "Set HttpOnly explicitly or document the framework version and active default."
                .to_string(),
            "Which framework version and deployment settings determine HttpOnly here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_secure(
    artifact: &Artifact,
    cookie_name: &str,
    secure: &CookieAttributeObservation,
) -> Option<Finding> {
    match secure.state {
        CookieAttributeState::Missing if secure.confidence == Confidence::High => Some(finding(
            "cookie_missing_secure",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` does not set Secure"),
            "No Secure attribute evidence was detected for this cookie-setting call.".to_string(),
            "Set Secure for cookies that should only be sent over HTTPS.".to_string(),
            "Is this cookie ever used in an externally reachable production environment?"
                .to_string(),
        )),
        CookieAttributeState::FrameworkDefault
            if observation_value_is_false(secure) && secure.confidence == Confidence::Low =>
        {
            Some(finding(
                "cookie_default_false_secure",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                artifact,
                secure.evidence_ids.clone(),
                format!("Cookie `{cookie_name}` defaults Secure to false"),
                "Framework default evidence indicates Secure is false for this cookie-setting call."
                    .to_string(),
                "Set Secure for cookies that should only be sent over HTTPS.".to_string(),
                "Is this cookie ever used in an externally reachable production environment?"
                    .to_string(),
            ))
        }
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_dynamic_secure",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` has dynamic Secure evidence"),
            "The Secure attribute appears to depend on a non-literal expression.".to_string(),
            "Confirm the effective production value and set Secure explicitly when possible."
                .to_string(),
            "Can production guarantee Secure is enabled for this cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_default_secure",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Low,
            artifact,
            secure.evidence_ids.clone(),
            format!("Cookie `{cookie_name}` relies on Secure framework default"),
            "The local code does not set Secure directly; behavior appears to depend on a framework default."
                .to_string(),
            "Set Secure explicitly or document the framework version and active default."
                .to_string(),
            "Which framework version and deployment settings determine Secure here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_same_site_none_without_secure(
    artifact: &Artifact,
    cookie_name: &str,
    same_site: &CookieAttributeObservation,
    secure: &CookieAttributeObservation,
) -> Option<Finding> {
    if !same_site_is_none(same_site) {
        return None;
    }

    let evidence_ids = combined_evidence_ids(same_site, secure);
    match secure.state {
        CookieAttributeState::Missing => Some(finding(
            "cookie_samesite_none_without_secure",
            FindingCategory::HighConfidenceMisconfiguration,
            Severity::High,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None without Secure evidence"),
            "SameSite=None was detected, but Secure attribute evidence was not detected for this cookie-setting call."
                .to_string(),
            "Set Secure whenever SameSite=None is used.".to_string(),
            "Is this cookie intentionally available in cross-site requests?".to_string(),
        )),
        CookieAttributeState::Dynamic => Some(finding(
            "cookie_samesite_none_dynamic_secure",
            FindingCategory::DynamicReviewRequired,
            Severity::Medium,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None with dynamic Secure evidence"),
            "SameSite=None was detected, while Secure appears to depend on a non-literal expression."
                .to_string(),
            "Confirm Secure is enabled whenever SameSite=None is active.".to_string(),
            "Can production guarantee Secure is enabled for this SameSite=None cookie?".to_string(),
        )),
        CookieAttributeState::FrameworkDefault => Some(finding(
            "cookie_samesite_none_default_secure",
            FindingCategory::FrameworkDefaultAssumed,
            Severity::Medium,
            artifact,
            evidence_ids,
            format!("Cookie `{cookie_name}` sets SameSite=None and relies on Secure default"),
            "SameSite=None was detected, while Secure appears to depend on a framework default."
                .to_string(),
            "Set Secure explicitly whenever SameSite=None is used.".to_string(),
            "Which framework version and deployment settings determine Secure here?".to_string(),
        )),
        _ => None,
    }
}

fn classify_expiry(
    artifact: &Artifact,
    cookie_name: &str,
    max_age: &CookieAttributeObservation,
    expires: &CookieAttributeObservation,
) -> Option<Finding> {
    if max_age.state == CookieAttributeState::Dynamic
        || expires.state == CookieAttributeState::Dynamic
    {
        return Some(finding(
            "cookie_dynamic_expiry",
            FindingCategory::DynamicReviewRequired,
            Severity::Low,
            artifact,
            combined_evidence_ids(max_age, expires),
            format!("Cookie `{cookie_name}` has dynamic expiry evidence"),
            "Cookie lifetime appears to depend on dynamic Max-Age or Expires evidence.".to_string(),
            "Confirm the effective cookie lifetime and document the production value.".to_string(),
            "What effective lifetime does this cookie have in production?".to_string(),
        ));
    }

    if is_expiry_absent(max_age) && is_expiry_absent(expires) {
        return Some(finding(
            "cookie_missing_expiry",
            FindingCategory::LifecycleGap,
            Severity::Low,
            artifact,
            combined_evidence_ids(max_age, expires),
            format!("Cookie `{cookie_name}` has no explicit expiry evidence"),
            "No Max-Age or Expires evidence was detected for this cookie-setting call."
                .to_string(),
            "Add an explicit Max-Age or Expires value when the cookie should have a bounded lifetime."
                .to_string(),
            "Should this cookie be session-scoped, or should it have an explicit lifetime?"
                .to_string(),
        ));
    }

    None
}

#[allow(clippy::too_many_arguments)]
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
    let artifact_id_part = artifact.id.0.as_str();
    let evidence_part = evidence_ids
        .first()
        .map(|evidence_id| evidence_id.0.as_str())
        .unwrap_or("no_evidence");
    let name_part = artifact.display_name.as_deref().unwrap_or("dynamic");
    let id = stable_finding_id(&[rule_id, artifact_id_part, evidence_part, name_part]);

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

fn is_session_like_cookie(artifact: &Artifact) -> bool {
    if matches!(
        artifact.artifact_type,
        ArtifactType::SessionCookie | ArtifactType::SignedCookie
    ) {
        return true;
    }

    let Some(name) = &artifact.display_name else {
        return false;
    };
    let normalized = name.to_ascii_lowercase();
    matches!(normalized.as_str(), "session" | "sessionid" | "sid") || normalized.contains("session")
}

fn same_site_is_none(observation: &CookieAttributeObservation) -> bool {
    observation
        .value
        .as_deref()
        .map(|value| {
            value
                .trim_matches('"')
                .trim_matches('\'')
                .eq_ignore_ascii_case("none")
        })
        .unwrap_or(false)
}

fn observation_value_is_false(observation: &CookieAttributeObservation) -> bool {
    observation
        .value
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("false"))
}

fn is_expiry_absent(observation: &CookieAttributeObservation) -> bool {
    observation.state == CookieAttributeState::Missing
        || (observation.state == CookieAttributeState::FrameworkDefault
            && observation
                .value
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("none")))
}

fn combined_evidence_ids(
    left: &CookieAttributeObservation,
    right: &CookieAttributeObservation,
) -> Vec<EvidenceId> {
    let mut evidence_ids = left.evidence_ids.clone();
    evidence_ids.extend(right.evidence_ids.clone());
    evidence_ids.sort();
    evidence_ids.dedup();
    evidence_ids
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, CookieAttributes, LifecycleEvidence, SCHEMA_VERSION, ScanSummary,
        SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![artifact],
            evidence: Vec::new(),
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(name: &str, attributes: CookieAttributes) -> Artifact {
        Artifact {
            id: ArtifactId(format!("artifact_{name}")),
            artifact_type: ArtifactType::SessionCookie,
            display_name: Some(name.to_string()),
            locations: vec![SourceLocation {
                path: "app.ts".to_string(),
                line: Some(1),
                column: Some(1),
            }],
            lifecycle_evidence: LifecycleEvidence::default(),
            confidence: Confidence::High,
            framework_hints: vec!["express".to_string()],
            cookie_attributes: Some(attributes),
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn attributes(
        http_only: CookieAttributeObservation,
        secure: CookieAttributeObservation,
        same_site: CookieAttributeObservation,
        max_age: CookieAttributeObservation,
        expires: CookieAttributeObservation,
    ) -> CookieAttributes {
        CookieAttributes {
            http_only,
            secure,
            same_site,
            max_age,
            expires,
            path: present("path", "/"),
            domain: missing("domain"),
        }
    }

    fn present(attribute: &str, value: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Present,
            Some(value),
            Confidence::High,
        )
    }

    fn missing(attribute: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Missing,
            None,
            Confidence::High,
        )
    }

    fn dynamic(attribute: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::Dynamic,
            Some("process.env.NODE_ENV === \"production\""),
            Confidence::Medium,
        )
    }

    fn default(attribute: &str, value: &str) -> CookieAttributeObservation {
        observation(
            attribute,
            CookieAttributeState::FrameworkDefault,
            Some(value),
            Confidence::Low,
        )
    }

    fn observation(
        attribute: &str,
        state: CookieAttributeState,
        value: Option<&str>,
        confidence: Confidence,
    ) -> CookieAttributeObservation {
        CookieAttributeObservation {
            state,
            value: value.map(str::to_string),
            evidence_ids: vec![EvidenceId(format!("evidence_{attribute}"))],
            confidence,
        }
    }

    #[test]
    fn missing_http_only_on_session_cookie_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                missing("http_only"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("HttpOnly")
        }));
    }

    #[test]
    fn missing_secure_on_static_cookie_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                missing("secure"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("Secure")
        }));
    }

    #[test]
    fn same_site_none_without_secure_links_both_evidence_ids() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                missing("secure"),
                present("same_site", "none"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("SameSite=None"))
            .expect("sameSite finding should exist");
        assert_eq!(
            finding.category,
            FindingCategory::HighConfidenceMisconfiguration
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_secure".to_string()))
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_same_site".to_string()))
        );
    }

    #[test]
    fn dynamic_secure_requires_review_not_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                dynamic("secure"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::DynamicReviewRequired
                && finding.title.contains("Secure")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.title.contains("Secure")
        }));
    }

    #[test]
    fn framework_default_false_secure_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                default("secure", "false"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("Secure")
                && finding.title.contains("defaults")
        }));
    }

    #[test]
    fn framework_default_false_httponly_is_high_confidence() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                default("http_only", "false"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::HighConfidenceMisconfiguration
                && finding.severity == Severity::High
                && finding.title.contains("HttpOnly")
                && finding.title.contains("defaults")
        }));
    }

    #[test]
    fn missing_expiry_is_lifecycle_gap_with_question() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                missing("max_age"),
                default("expires", "none"),
            ),
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.category == FindingCategory::LifecycleGap)
            .expect("expiry lifecycle finding should exist");
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn safe_cookie_produces_no_findings() {
        let findings = classify_artifact(artifact(
            "session",
            attributes(
                present("http_only", "true"),
                present("secure", "true"),
                present("same_site", "lax"),
                present("max_age", "900"),
                missing("expires"),
            ),
        ));

        assert!(findings.is_empty());
    }
}
