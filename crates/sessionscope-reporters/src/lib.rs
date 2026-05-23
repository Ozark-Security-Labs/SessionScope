mod diff;
mod explain;
mod github_summary;
mod json;
mod markdown;
mod markdown_escape;
mod sarif;

use std::fmt;

use sessionscope_core::redaction::sanitized_report;
use sessionscope_model::{
    Artifact, CookieAttributeObservation, CookieAttributes, Evidence, EvidenceId,
    JwtAttributeObservation, JwtAttributes, JwtIdentityClaims, LifecycleEvidence, LifecyclePath,
    ScanReport, SourceLocation, TokenBoundaryAttributes, TokenBoundaryObservation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Markdown,
    Sarif,
    GithubSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseReportFormatError {
    value: String,
}

impl fmt::Display for ParseReportFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unsupported report format: {}", self.value)
    }
}

impl std::error::Error for ParseReportFormatError {}

impl ReportFormat {
    pub fn parse(value: &str) -> Result<Self, ParseReportFormatError> {
        match value {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            "github-summary" => Ok(Self::GithubSummary),
            _ => Err(ParseReportFormatError {
                value: value.to_string(),
            }),
        }
    }
}

pub fn render(report: &ScanReport, format: ReportFormat) -> String {
    let mut report = sanitized_report(report);
    canonicalize_report(&mut report);
    let rendered = match format {
        ReportFormat::Json => json::render(&report),
        ReportFormat::Markdown => markdown::render(&report),
        ReportFormat::Sarif => sarif::render(&report),
        ReportFormat::GithubSummary => github_summary::render(&report),
    };
    // Renderers may or may not emit trailing newlines. Normalize here so the
    // CLI can use `println!` uniformly (F-19) without producing blank-line
    // artifacts when piping or writing to a file.
    strip_trailing_newlines(rendered)
}

pub fn render_diff_json(report: &sessionscope_model::DiffReport) -> String {
    strip_trailing_newlines(diff::render_json(report))
}

pub fn render_diff_markdown(report: &sessionscope_model::DiffReport) -> String {
    strip_trailing_newlines(diff::render_markdown(report))
}

pub fn render_explain(report: &ScanReport, finding_id: &str) -> Option<String> {
    let mut report = sanitized_report(report);
    canonicalize_report(&mut report);
    explain::render(&report, finding_id).map(strip_trailing_newlines)
}

fn strip_trailing_newlines(mut value: String) -> String {
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    value
}

fn canonicalize_report(report: &mut ScanReport) {
    report
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    report.summary.diagnostics.sort();

    for file in &mut report.files {
        file.diagnostics.sort();
        sort_artifacts(&mut file.artifacts);
        sort_evidence(&mut file.evidence);
    }

    sort_artifacts(&mut report.artifacts);
    sort_evidence(&mut report.evidence);
    sort_lifecycle_paths(&mut report.lifecycle_paths);
}

fn sort_artifacts(artifacts: &mut [Artifact]) {
    for artifact in artifacts.iter_mut() {
        artifact.locations.sort_by_key(location_key);
        artifact.framework_hints.sort();
        sort_lifecycle_evidence(&mut artifact.lifecycle_evidence);
        if let Some(attributes) = &mut artifact.cookie_attributes {
            sort_cookie_attribute_evidence_ids(attributes);
        }
        if let Some(attributes) = &mut artifact.jwt_attributes {
            sort_jwt_attribute_evidence_ids(attributes);
        }
        if let Some(attributes) = &mut artifact.token_boundary_attributes {
            sort_token_boundary_attribute_evidence_ids(attributes);
        }
    }

    artifacts.sort_by(|left, right| {
        first_location_key(&left.locations)
            .cmp(&first_location_key(&right.locations))
            .then_with(|| left.display_name.cmp(&right.display_name))
            .then_with(|| left.artifact_type.cmp(&right.artifact_type))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn sort_evidence(evidence: &mut [Evidence]) {
    evidence.sort_by(|left, right| {
        location_key(&left.location)
            .cmp(&location_key(&right.location))
            .then_with(|| left.lifecycle_stage.cmp(&right.lifecycle_stage))
            .then_with(|| left.detector_id.cmp(&right.detector_id))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn sort_lifecycle_paths(paths: &mut [LifecyclePath]) {
    for path in paths.iter_mut() {
        path.artifact_ids.sort();
        for step in &mut path.stages {
            sort_evidence_ids(&mut step.evidence_ids);
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

fn first_location_key(locations: &[SourceLocation]) -> (String, usize, usize) {
    locations
        .first()
        .map(location_key)
        .unwrap_or_else(|| (String::new(), usize::MAX, usize::MAX))
}

fn location_key(location: &SourceLocation) -> (String, usize, usize) {
    (
        location.path.replace('\\', "/"),
        location.line.unwrap_or(usize::MAX),
        location.column.unwrap_or(usize::MAX),
    )
}

fn sort_lifecycle_evidence(lifecycle_evidence: &mut LifecycleEvidence) {
    sort_evidence_ids(&mut lifecycle_evidence.issue);
    sort_evidence_ids(&mut lifecycle_evidence.store);
    sort_evidence_ids(&mut lifecycle_evidence.transmit);
    sort_evidence_ids(&mut lifecycle_evidence.validate);
    sort_evidence_ids(&mut lifecycle_evidence.refresh);
    sort_evidence_ids(&mut lifecycle_evidence.revoke);
    sort_evidence_ids(&mut lifecycle_evidence.expire);
    sort_evidence_ids(&mut lifecycle_evidence.introspect);
}

fn sort_cookie_attribute_evidence_ids(attributes: &mut CookieAttributes) {
    sort_observation_evidence_ids(&mut attributes.http_only);
    sort_observation_evidence_ids(&mut attributes.secure);
    sort_observation_evidence_ids(&mut attributes.same_site);
    sort_observation_evidence_ids(&mut attributes.max_age);
    sort_observation_evidence_ids(&mut attributes.expires);
    sort_observation_evidence_ids(&mut attributes.path);
    sort_observation_evidence_ids(&mut attributes.domain);
}

fn sort_observation_evidence_ids(observation: &mut CookieAttributeObservation) {
    sort_evidence_ids(&mut observation.evidence_ids);
}

fn sort_jwt_attribute_evidence_ids(attributes: &mut JwtAttributes) {
    sort_jwt_observation_evidence_ids(&mut attributes.operation);
    sort_jwt_observation_evidence_ids(&mut attributes.algorithm);
    sort_jwt_observation_evidence_ids(&mut attributes.key_reference);
    sort_jwt_observation_evidence_ids(&mut attributes.issuer);
    sort_jwt_observation_evidence_ids(&mut attributes.audience);
    sort_jwt_observation_evidence_ids(&mut attributes.expiration);
    sort_jwt_observation_evidence_ids(&mut attributes.signature_verification);
    sort_jwt_observation_evidence_ids(&mut attributes.expiry_enforcement);
    if let Some(identity_claims) = &mut attributes.identity_claims {
        sort_identity_claim_evidence_ids(identity_claims);
    }
}

fn sort_identity_claim_evidence_ids(identity_claims: &mut JwtIdentityClaims) {
    sort_jwt_observation_evidence_ids(&mut identity_claims.subject);
    sort_jwt_observation_evidence_ids(&mut identity_claims.user_id);
    sort_jwt_observation_evidence_ids(&mut identity_claims.tenant_id);
    sort_jwt_observation_evidence_ids(&mut identity_claims.org_id);
    sort_jwt_observation_evidence_ids(&mut identity_claims.workspace_id);
    sort_jwt_observation_evidence_ids(&mut identity_claims.roles);
    sort_jwt_observation_evidence_ids(&mut identity_claims.scopes);
    sort_jwt_observation_evidence_ids(&mut identity_claims.groups);
    sort_jwt_observation_evidence_ids(&mut identity_claims.email);
    sort_jwt_observation_evidence_ids(&mut identity_claims.email_verified);
    sort_jwt_observation_evidence_ids(&mut identity_claims.auth_method);
    sort_jwt_observation_evidence_ids(&mut identity_claims.auth_class);
}

fn sort_jwt_observation_evidence_ids(observation: &mut JwtAttributeObservation) {
    sort_evidence_ids(&mut observation.evidence_ids);
}

fn sort_token_boundary_attribute_evidence_ids(attributes: &mut TokenBoundaryAttributes) {
    sort_token_boundary_observation_evidence_ids(&mut attributes.issuer);
    sort_token_boundary_observation_evidence_ids(&mut attributes.audience);
    sort_token_boundary_observation_evidence_ids(&mut attributes.service);
    sort_token_boundary_observation_evidence_ids(&mut attributes.environment);
    sort_token_boundary_observation_evidence_ids(&mut attributes.tenant);
    sort_token_boundary_observation_evidence_ids(&mut attributes.provider);
    sort_token_boundary_observation_evidence_ids(&mut attributes.scope);
    sort_token_boundary_observation_evidence_ids(&mut attributes.trust_boundary);
}

fn sort_token_boundary_observation_evidence_ids(observation: &mut TokenBoundaryObservation) {
    sort_evidence_ids(&mut observation.evidence_ids);
}

fn sort_evidence_ids(evidence_ids: &mut [EvidenceId]) {
    evidence_ids.sort();
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeObservation,
        CookieAttributeState, CookieAttributes, Evidence, EvidenceId, Finding, FindingCategory,
        FindingId, LifecycleEvidence, LifecycleStage, SCHEMA_VERSION, SanitizedExcerpt, ScanReport,
        ScanSummary, Severity, SourceLocation,
    };

    use super::{ReportFormat, render};

    const SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789";
    const OAUTH_STATE: &str = "stateabcdefghijklmnopqrstuvwxyzABCDEF0123456789";

    fn unsafe_report() -> ScanReport {
        let evidence_id = EvidenceId("evidence_report_secret".to_string());
        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: vec![format!("diagnostic saw token {SECRET}")],
                worker_panic_count: 0,
                skipped_by_reason: std::collections::BTreeMap::new(),
            },
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_report_secret".to_string()),
                artifact_type: ArtifactType::SessionCookie,
                display_name: Some("session".to_string()),
                locations: Vec::new(),
                lifecycle_evidence: LifecycleEvidence::default(),
                confidence: Confidence::High,
                framework_hints: Vec::new(),
                cookie_attributes: Some(cookie_attributes_with_value(SECRET)),
                jwt_attributes: None,
                token_boundary_attributes: None,
            }],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Validate,
                location: SourceLocation {
                    path: "src/auth.ts".to_string(),
                    line: Some(7),
                    column: Some(3),
                },
                detector_id: "test.detector".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt::from_sanitized(format!(
                    "Authorization: Bearer {SECRET}"
                ))),
                dynamic: false,
                framework_default: false,
            }],
            lifecycle_paths: Vec::new(),
            findings: vec![Finding {
                id: FindingId("finding_report_secret".to_string()),
                category: FindingCategory::HighConfidenceMisconfiguration,
                severity: Severity::High,
                artifact_ids: Vec::new(),
                evidence_ids: vec![evidence_id],
                title: format!("Leaked token {SECRET}"),
                description: format!("Description mentions {SECRET}"),
                suggested_fix: Some(format!("Remove {SECRET}")),
                reviewer_question: Some(format!("Is {SECRET} expected?")),
            }],
        }
    }

    fn cookie_attributes_with_value(value: &str) -> CookieAttributes {
        let missing = CookieAttributeObservation {
            state: CookieAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        CookieAttributes {
            http_only: missing.clone(),
            secure: missing.clone(),
            same_site: missing.clone(),
            max_age: missing.clone(),
            expires: missing.clone(),
            path: missing.clone(),
            domain: CookieAttributeObservation {
                state: CookieAttributeState::Present,
                value: Some(value.to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::High,
            },
        }
    }

    #[test]
    fn render_sanitizes_json_output() {
        let output = render(&unsafe_report(), ReportFormat::Json);

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(SECRET));
    }

    #[test]
    fn renderers_do_not_leak_secret_like_values() {
        for format in [
            ReportFormat::Markdown,
            ReportFormat::Sarif,
            ReportFormat::GithubSummary,
        ] {
            let output = render(&unsafe_report(), format);

            assert!(!output.contains(SECRET), "{format:?} leaked a secret");
        }
    }

    #[test]
    fn github_summary_includes_sanitized_key_findings() {
        let output = render(&unsafe_report(), ReportFormat::GithubSummary);

        assert!(output.contains("### Key findings"));
        assert!(output.contains("`high` `high_confidence_misconfiguration`"));
        assert!(output.contains("\\[REDACTED\\]"));
        assert!(!output.contains(SECRET));
    }

    #[test]
    fn render_sanitizes_oauth_values_in_json_and_markdown() {
        let evidence_id = EvidenceId("evidence_oauth_state".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: Vec::new(),
                worker_panic_count: 0,
                skipped_by_reason: std::collections::BTreeMap::new(),
            },
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_oauth_flow".to_string()),
                artifact_type: ArtifactType::OAuthAuthCodeFlow,
                display_name: Some("oauth_auth_code_flow".to_string()),
                locations: Vec::new(),
                lifecycle_evidence: LifecycleEvidence::default(),
                confidence: Confidence::High,
                framework_hints: vec!["oauth-generic".to_string()],
                cookie_attributes: None,
                jwt_attributes: None,
                token_boundary_attributes: None,
            }],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Issue,
                location: SourceLocation {
                    path: "src/oauth.ts".to_string(),
                    line: Some(12),
                    column: Some(1),
                },
                detector_id: "oauth.state.present".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt::from_sanitized(format!(
                    "authorizationUrl({{ state: '{OAUTH_STATE}', nonce: 'nonceabcdefghijklmnopqrstuvwxyzABCDEF0123456789', code_verifier: 'verifierabcdefghijklmnopqrstuvwxyzABCDEF0123456789' }})"
                ))),
                dynamic: false,
                framework_default: false,
            }],
            lifecycle_paths: Vec::new(),
            findings: vec![Finding {
                id: FindingId("finding_oauth_state".to_string()),
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                artifact_ids: vec![ArtifactId("artifact_oauth_flow".to_string())],
                evidence_ids: vec![evidence_id],
                title: format!("OAuth state {OAUTH_STATE} is static"),
                description: format!("OAuth state value {OAUTH_STATE} must not leak"),
                suggested_fix: None,
                reviewer_question: None,
            }],
        };

        for format in [ReportFormat::Json, ReportFormat::Markdown] {
            let output = render(&report, format);
            assert!(output.contains("REDACTED"), "{format:?} did not redact");
            for secret in [
                OAUTH_STATE,
                "nonceabcdefghijklmnopqrstuvwxyzABCDEF0123456789",
                "verifierabcdefghijklmnopqrstuvwxyzABCDEF0123456789",
            ] {
                assert!(!output.contains(secret), "{format:?} leaked {secret}");
            }
        }
    }

    #[test]
    fn render_sanitizes_browser_storage_token_values() {
        let mut report = unsafe_report();
        report.evidence[0].excerpt = Some(SanitizedExcerpt::from_sanitized(
            "localStorage.setItem('access_token', `raw-token-value`)".to_string(),
        ));

        for format in [ReportFormat::Json, ReportFormat::Markdown] {
            let output = render(&report, format);
            assert!(output.contains("REDACTED"), "{format:?} did not redact");
            assert!(!output.contains("raw-token-value"));
        }
    }
}
