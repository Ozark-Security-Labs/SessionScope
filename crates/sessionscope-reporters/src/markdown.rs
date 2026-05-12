use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeState, Evidence, EvidenceId,
    Finding, FindingCategory, LifecycleEvidence, LifecycleStage, ScanReport, Severity,
    SkippedReason, SourceLocation,
};

pub fn render(report: &ScanReport) -> String {
    let mut output = format!(
        concat!(
            "# SessionScope Report\n\n",
            "## Summary\n\n",
            "- Schema version: `{}`\n",
            "- Files discovered: {}\n",
            "- Files scanned: {}\n",
            "- Files skipped: {}\n",
            "- Artifacts: {}\n",
            "- Evidence records: {}\n",
            "- Findings: {}\n",
            "- Diagnostics: {}\n"
        ),
        report.schema_version,
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.artifacts.len(),
        report.evidence.len(),
        report.findings.len(),
        report.summary.diagnostics.len()
    );

    render_skipped_files(&mut output, report);
    render_findings(&mut output, report);
    render_artifacts(&mut output, report);
    output
}

fn render_skipped_files(output: &mut String, report: &ScanReport) {
    output.push_str("\n## Skipped Files\n\n");
    let skipped_files = report
        .files
        .iter()
        .filter_map(|file| {
            file.skipped_reason
                .as_ref()
                .map(|reason| (&file.path, reason))
        })
        .collect::<Vec<_>>();

    if skipped_files.is_empty() {
        output.push_str("No skipped files.\n");
        return;
    }

    output.push_str("| File | Reason |\n| --- | --- |\n");
    for (path, reason) in skipped_files {
        output.push_str(&format!(
            "| {} | `{}` |\n",
            table_cell(path),
            format_skipped_reason(reason)
        ));
    }
}

fn render_findings(output: &mut String, report: &ScanReport) {
    output.push_str("\n## Findings\n\n");
    if report.findings.is_empty() {
        output.push_str("No findings were detected.\n");
        return;
    }

    for finding in &report.findings {
        render_finding(output, finding, report);
    }
}

fn render_finding(output: &mut String, finding: &Finding, report: &ScanReport) {
    output.push_str(&format!("### {}\n\n", inline_text(finding.title.as_str())));
    output.push_str(&format!(
        "- Severity: `{}`\n- Category: `{}`\n- Finding ID: `{}`\n",
        format_severity(finding.severity),
        format_category(finding.category),
        finding.id.0
    ));
    if !finding.artifact_ids.is_empty() {
        output.push_str(&format!(
            "- Artifacts: {}\n",
            format_artifact_ids(&finding.artifact_ids)
        ));
    }
    if !finding.evidence_ids.is_empty() {
        output.push_str(&format!(
            "- Evidence: {}\n",
            format_evidence_ids(&finding.evidence_ids)
        ));
        output.push_str(&format!(
            "- Source locations: {}\n",
            format_finding_locations(finding, report)
        ));
    }
    output.push_str(&format!("\n{}\n\n", inline_text(&finding.description)));
    if let Some(suggested_fix) = &finding.suggested_fix {
        output.push_str(&format!(
            "**Suggested fix:** {}\n\n",
            inline_text(suggested_fix)
        ));
    }
    if let Some(reviewer_question) = &finding.reviewer_question {
        output.push_str(&format!(
            "**Reviewer question:** {}\n\n",
            inline_text(reviewer_question)
        ));
    }
}

fn render_artifacts(output: &mut String, report: &ScanReport) {
    output.push_str("\n## Artifacts\n\n");
    if report.artifacts.is_empty() {
        output.push_str("No artifacts were detected.\n");
        if report.evidence.is_empty() {
            output.push_str("\nNo lifecycle evidence was detected.\n");
        }
        return;
    }

    let evidence_by_id = evidence_by_id(report);
    let mut grouped: BTreeMap<ArtifactType, Vec<&Artifact>> = BTreeMap::new();
    for artifact in &report.artifacts {
        grouped
            .entry(artifact.artifact_type)
            .or_default()
            .push(artifact);
    }

    for (artifact_type, artifacts) in grouped {
        output.push_str(&format!(
            "### `{}`\n\n",
            format_artifact_type(artifact_type)
        ));
        for artifact in artifacts {
            render_artifact(output, artifact, &evidence_by_id);
        }
    }
}

fn render_artifact(
    output: &mut String,
    artifact: &Artifact,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) {
    let name = artifact.display_name.as_deref().unwrap_or("unknown");
    output.push_str(&format!("#### `{}`\n\n", inline_text(name)));
    output.push_str(&format!("- Artifact ID: `{}`\n", artifact.id.0));
    output.push_str(&format!(
        "- Type: `{}`\n",
        format_artifact_type(artifact.artifact_type)
    ));
    output.push_str(&format!(
        "- Confidence: `{}`\n",
        format_confidence(artifact.confidence)
    ));
    output.push_str(&format!(
        "- Locations: {}\n",
        format_locations(&artifact.locations)
    ));
    output.push_str(&format!(
        "- Framework hints: {}\n\n",
        format_framework_hints(&artifact.framework_hints)
    ));

    render_lifecycle_evidence(output, &artifact.lifecycle_evidence, evidence_by_id);
    if let Some(attributes) = &artifact.cookie_attributes {
        render_cookie_attributes(output, attributes);
    }
}

fn render_lifecycle_evidence(
    output: &mut String,
    lifecycle_evidence: &LifecycleEvidence,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) {
    let rows = lifecycle_rows(lifecycle_evidence);
    if rows.is_empty() {
        output.push_str("No lifecycle evidence linked to this artifact.\n\n");
        return;
    }

    output.push_str("| Stage | Evidence ID | Location | Confidence | Detector | Dynamic | Framework default | Excerpt |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for (stage, evidence_id) in rows {
        let evidence = evidence_by_id.get(evidence_id.0.as_str()).copied();
        output.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {} | {} |\n",
            format_lifecycle_stage(stage),
            evidence_id.0,
            table_cell(
                &evidence
                    .map(|record| format_location(&record.location))
                    .unwrap_or_else(|| "unknown location".to_string())
            ),
            evidence
                .map(|record| format!("`{}`", format_confidence(record.confidence)))
                .unwrap_or_else(|| "-".to_string()),
            table_cell(
                evidence
                    .map(|record| record.detector_id.as_str())
                    .unwrap_or("-")
            ),
            bool_cell(evidence.is_some_and(|record| record.dynamic)),
            bool_cell(evidence.is_some_and(|record| record.framework_default)),
            table_cell(
                evidence
                    .and_then(|record| record.excerpt.as_ref())
                    .map(|excerpt| excerpt.0.as_str())
                    .unwrap_or("-")
            )
        ));
    }
    output.push('\n');
}

fn render_cookie_attributes(
    output: &mut String,
    attributes: &sessionscope_model::CookieAttributes,
) {
    output.push_str("| Attribute | State | Value | Confidence | Evidence |\n");
    output.push_str("| --- | --- | --- | --- | ---: |\n");
    for (label, observation) in [
        ("HttpOnly", &attributes.http_only),
        ("Secure", &attributes.secure),
        ("SameSite", &attributes.same_site),
        ("Max-Age", &attributes.max_age),
        ("Expires", &attributes.expires),
        ("Path", &attributes.path),
        ("Domain", &attributes.domain),
    ] {
        output.push_str(&format!(
            "| {label} | `{}` | {} | `{}` | {} |\n",
            format_state(observation.state),
            table_cell(observation.value.as_deref().unwrap_or("-")),
            format_confidence(observation.confidence),
            observation.evidence_ids.len()
        ));
    }
    output.push('\n');
}

fn lifecycle_rows(lifecycle_evidence: &LifecycleEvidence) -> Vec<(LifecycleStage, &EvidenceId)> {
    let mut rows = Vec::new();
    for (stage, evidence_ids) in [
        (LifecycleStage::Issue, &lifecycle_evidence.issue),
        (LifecycleStage::Store, &lifecycle_evidence.store),
        (LifecycleStage::Transmit, &lifecycle_evidence.transmit),
        (LifecycleStage::Validate, &lifecycle_evidence.validate),
        (LifecycleStage::Refresh, &lifecycle_evidence.refresh),
        (LifecycleStage::Revoke, &lifecycle_evidence.revoke),
        (LifecycleStage::Expire, &lifecycle_evidence.expire),
        (LifecycleStage::Introspect, &lifecycle_evidence.introspect),
    ] {
        rows.extend(evidence_ids.iter().map(|id| (stage, id)));
    }
    rows
}

fn evidence_by_id(report: &ScanReport) -> BTreeMap<&str, &Evidence> {
    report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect()
}

fn format_finding_locations(finding: &Finding, report: &ScanReport) -> String {
    let evidence_by_id = evidence_by_id(report);
    let locations = finding
        .evidence_ids
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()))
        .map(|evidence| format!("`{}`", format_location(&evidence.location)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if locations.is_empty() {
        "unknown".to_string()
    } else {
        locations.join(", ")
    }
}

fn format_locations(locations: &[SourceLocation]) -> String {
    if locations.is_empty() {
        return "unknown".to_string();
    }

    locations
        .iter()
        .map(|location| format!("`{}`", format_location(location)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_artifact_ids(ids: &[ArtifactId]) -> String {
    ids.iter()
        .map(|id| format!("`{}`", id.0))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_evidence_ids(ids: &[EvidenceId]) -> String {
    ids.iter()
        .map(|id| format!("`{}`", id.0))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_framework_hints(hints: &[String]) -> String {
    if hints.is_empty() {
        return "none".to_string();
    }

    hints
        .iter()
        .map(|hint| format!("`{}`", inline_text(hint)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_location(location: &SourceLocation) -> String {
    match (location.line, location.column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", location.path),
        (Some(line), None) => format!("{}:{line}", location.path),
        _ => location.path.clone(),
    }
}

fn format_artifact_type(artifact_type: ArtifactType) -> &'static str {
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

fn format_state(state: CookieAttributeState) -> &'static str {
    match state {
        CookieAttributeState::Present => "present",
        CookieAttributeState::Missing => "missing",
        CookieAttributeState::Dynamic => "dynamic",
        CookieAttributeState::FrameworkDefault => "framework_default",
        CookieAttributeState::Unknown => "unknown",
    }
}

fn format_confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn format_lifecycle_stage(stage: LifecycleStage) -> &'static str {
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

fn format_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

fn format_category(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::HighConfidenceMisconfiguration => "high_confidence_misconfiguration",
        FindingCategory::MissingValidationEvidence => "missing_validation_evidence",
        FindingCategory::LifecycleGap => "lifecycle_gap",
        FindingCategory::DynamicReviewRequired => "dynamic_review_required",
        FindingCategory::FrameworkDefaultAssumed => "framework_default_assumed",
    }
}

fn format_skipped_reason(reason: &SkippedReason) -> &'static str {
    match reason {
        SkippedReason::Binary => "binary",
        SkippedReason::TooLarge => "too_large",
        SkippedReason::Unsupported => "unsupported",
        SkippedReason::Excluded => "excluded",
        SkippedReason::Ignored => "ignored",
        SkippedReason::SensitivePath => "sensitive_path",
        SkippedReason::ReadError(_) => "read_error",
    }
}

fn bool_cell(value: bool) -> &'static str {
    if value { "`yes`" } else { "`no`" }
}

fn table_cell(value: &str) -> String {
    inline_text(value).replace('|', "\\|")
}

fn inline_text(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("<br>")
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeObservation,
        CookieAttributeState, CookieAttributes, Evidence, EvidenceId, FileScanResult, Finding,
        FindingCategory, FindingId, Language, LifecycleEvidence, LifecycleStage, SCHEMA_VERSION,
        SanitizedExcerpt, ScanReport, ScanSummary, Severity, SkippedReason, SourceLocation,
    };

    use super::render;

    #[test]
    fn renders_empty_report_with_useful_states() {
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: Vec::new(),
            findings: Vec::new(),
        };

        let rendered = render(&report);

        assert!(rendered.contains("- Schema version: `0.2.0`"));
        assert!(rendered.contains("No skipped files."));
        assert!(rendered.contains("No findings were detected."));
        assert!(rendered.contains("No artifacts were detected."));
        assert!(rendered.contains("No lifecycle evidence was detected."));
    }

    #[test]
    fn renders_cookie_lifecycle_artifact_and_finding_details() {
        let evidence_id = EvidenceId("evidence_cookie_store".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: Vec::new(),
            },
            files: vec![FileScanResult::skipped(
                "ignored.ts".to_string(),
                Language::TypeScript,
                SkippedReason::Excluded,
            )],
            artifacts: vec![cookie_artifact(evidence_id.clone())],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Store,
                location: location("app.ts", 3, 5),
                detector_id: "cookie.set".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt(
                    "response.cookie(\"session\", [REDACTED])".to_string(),
                )),
                dynamic: false,
                framework_default: false,
            }],
            findings: vec![Finding {
                id: FindingId("finding_cookie".to_string()),
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                artifact_ids: vec![ArtifactId("artifact_cookie".to_string())],
                evidence_ids: vec![evidence_id],
                title: "Cookie has dynamic Secure evidence".to_string(),
                description: "The Secure attribute appears dynamic.".to_string(),
                suggested_fix: Some("Confirm production Secure behavior.".to_string()),
                reviewer_question: Some("Can production guarantee Secure?".to_string()),
            }],
        };

        let rendered = render(&report);

        assert!(rendered.contains("## Findings"));
        assert!(rendered.contains("- Finding ID: `finding_cookie`"));
        assert!(rendered.contains("- Source locations: `app.ts:3:5`"));
        assert!(rendered.contains("**Suggested fix:** Confirm production Secure behavior."));
        assert!(rendered.contains("**Reviewer question:** Can production guarantee Secure?"));
        assert!(rendered.contains("### `session_cookie`"));
        assert!(rendered.contains("#### `session`"));
        assert!(rendered.contains("| `store` | `evidence_cookie_store` | app.ts:3:5 | `high` | cookie.set | `no` | `no` | response.cookie"));
        assert!(rendered.contains(
            "| Secure | `dynamic` | process.env.NODE_ENV === \"production\" | `medium` | 0 |"
        ));
        assert!(rendered.contains("| ignored.ts | `excluded` |"));
    }

    #[test]
    fn renders_synthetic_jwt_finding_with_evidence_location() {
        let artifact_id = ArtifactId("artifact_access_jwt".to_string());
        let evidence_id = EvidenceId("evidence_jwt_verify".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: artifact_id.clone(),
                artifact_type: ArtifactType::AccessJwt,
                display_name: Some("access_jwt".to_string()),
                locations: vec![location("src/auth.ts", 12, 7)],
                lifecycle_evidence: LifecycleEvidence {
                    validate: vec![evidence_id.clone()],
                    ..LifecycleEvidence::default()
                },
                confidence: Confidence::High,
                framework_hints: vec!["jsonwebtoken".to_string()],
                cookie_attributes: None,
            }],
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Validate,
                location: location("src/auth.ts", 23, 10),
                detector_id: "jwt.validation".to_string(),
                confidence: Confidence::Medium,
                excerpt: Some(SanitizedExcerpt("jwt.verify(token, secret)".to_string())),
                dynamic: false,
                framework_default: false,
            }],
            findings: vec![Finding {
                id: FindingId("finding_missing_audience".to_string()),
                category: FindingCategory::MissingValidationEvidence,
                severity: Severity::Medium,
                artifact_ids: vec![artifact_id],
                evidence_ids: vec![evidence_id],
                title: "Audience validation evidence was not found".to_string(),
                description: "JWT verification evidence does not include an audience check."
                    .to_string(),
                suggested_fix: Some(
                    "Require an expected audience during verification.".to_string(),
                ),
                reviewer_question: Some(
                    "Should this service reject tokens for other audiences?".to_string(),
                ),
            }],
        };

        let rendered = render(&report);

        assert!(rendered.contains("### `access_jwt`"));
        assert!(rendered.contains("#### `access_jwt`"));
        assert!(rendered.contains("Category: `missing_validation_evidence`"));
        assert!(rendered.contains("- Source locations: `src/auth.ts:23:10`"));
        assert!(rendered.contains("| `validate` | `evidence_jwt_verify` | src/auth.ts:23:10 | `medium` | jwt.validation | `no` | `no` | jwt.verify(token, secret) |"));
    }

    #[test]
    fn escapes_markdown_table_cells() {
        let evidence_id = EvidenceId("evidence_cookie_store".to_string());
        let mut artifact = cookie_artifact(evidence_id.clone());
        artifact
            .cookie_attributes
            .as_mut()
            .expect("cookie attributes")
            .domain = CookieAttributeObservation {
            state: CookieAttributeState::Present,
            value: Some("one|two\nthree".to_string()),
            evidence_ids: vec![evidence_id.clone()],
            confidence: Confidence::High,
        };
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: vec![artifact],
            evidence: vec![Evidence {
                id: evidence_id,
                lifecycle_stage: LifecycleStage::Store,
                location: location("app.ts", 3, 5),
                detector_id: "cookie.set".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt("first|second\nthird".to_string())),
                dynamic: false,
                framework_default: false,
            }],
            findings: Vec::new(),
        };

        let rendered = render(&report);

        assert!(rendered.contains("first\\|second<br>third"));
        assert!(rendered.contains("one\\|two<br>three"));
    }

    fn cookie_artifact(evidence_id: EvidenceId) -> Artifact {
        Artifact {
            id: ArtifactId("artifact_cookie".to_string()),
            artifact_type: ArtifactType::SessionCookie,
            display_name: Some("session".to_string()),
            locations: vec![location("app.ts", 3, 5)],
            lifecycle_evidence: LifecycleEvidence {
                store: vec![evidence_id],
                ..LifecycleEvidence::default()
            },
            confidence: Confidence::High,
            framework_hints: vec!["express".to_string()],
            cookie_attributes: Some(attributes()),
        }
    }

    fn attributes() -> CookieAttributes {
        let present = CookieAttributeObservation {
            state: CookieAttributeState::Present,
            value: Some("true".to_string()),
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        let missing = CookieAttributeObservation {
            state: CookieAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        CookieAttributes {
            http_only: present.clone(),
            secure: CookieAttributeObservation {
                state: CookieAttributeState::Dynamic,
                value: Some("process.env.NODE_ENV === \"production\"".to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::Medium,
            },
            same_site: present,
            max_age: missing.clone(),
            expires: missing.clone(),
            path: missing.clone(),
            domain: missing,
        }
    }

    fn location(path: &str, line: usize, column: usize) -> SourceLocation {
        SourceLocation {
            path: path.to_string(),
            line: Some(line),
            column: Some(column),
        }
    }
}
