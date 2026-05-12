use sessionscope_model::{
    Artifact, CookieAttributeState, Finding, FindingCategory, ScanReport, Severity, SkippedReason,
    SourceLocation,
};

pub fn render(report: &ScanReport) -> String {
    let mut output = format!(
        concat!(
            "# SessionScope Report\n\n",
            "- Files discovered: {}\n",
            "- Files scanned: {}\n",
            "- Files skipped: {}\n",
            "- Findings: {}\n"
        ),
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.findings.len()
    );

    let skipped_files = report
        .files
        .iter()
        .filter_map(|file| {
            file.skipped_reason
                .as_ref()
                .map(|reason| (&file.path, reason))
        })
        .collect::<Vec<_>>();

    if !skipped_files.is_empty() {
        output.push_str("\n## Skipped Files\n\n");
        for (path, reason) in skipped_files {
            output.push_str(&format!("- `{path}`: {}\n", format_skipped_reason(reason)));
        }
    }

    if !report.findings.is_empty() {
        output.push_str("\n## Findings\n\n");
        for finding in &report.findings {
            render_finding(&mut output, finding);
        }
    }

    let cookie_artifacts = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.cookie_attributes.is_some())
        .collect::<Vec<_>>();
    if !cookie_artifacts.is_empty() {
        output.push_str("\n## Artifacts\n\n");
        for artifact in cookie_artifacts {
            render_cookie_artifact(&mut output, artifact);
        }
    }

    output
}

fn render_finding(output: &mut String, finding: &Finding) {
    output.push_str(&format!(
        "### {}\n\n- Severity: `{}`\n- Category: `{}`\n",
        finding.title,
        format_severity(finding.severity),
        format_category(finding.category)
    ));
    if !finding.evidence_ids.is_empty() {
        let evidence = finding
            .evidence_ids
            .iter()
            .map(|id| format!("`{}`", id.0))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!("- Evidence: {evidence}\n"));
    }
    output.push_str(&format!("\n{}\n\n", finding.description));
    if let Some(suggested_fix) = &finding.suggested_fix {
        output.push_str(&format!("Suggested fix: {suggested_fix}\n\n"));
    }
    if let Some(reviewer_question) = &finding.reviewer_question {
        output.push_str(&format!("Reviewer question: {reviewer_question}\n\n"));
    }
}

fn render_cookie_artifact(output: &mut String, artifact: &Artifact) {
    let name = artifact.display_name.as_deref().unwrap_or("unknown cookie");
    let location = artifact
        .locations
        .first()
        .map(format_location)
        .unwrap_or_else(|| "unknown location".to_string());
    output.push_str(&format!(
        "### `{name}`\n\n- Type: `{:?}`\n- Location: `{location}`\n\n",
        artifact.artifact_type
    ));
    output.push_str(
        "| Attribute | State | Value | Confidence | Evidence |\n| --- | --- | --- | --- | ---: |\n",
    );

    let attributes = artifact
        .cookie_attributes
        .as_ref()
        .expect("cookie artifact should have attributes");
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
            "| {label} | `{}` | {} | `{:?}` | {} |\n",
            format_state(observation.state),
            observation.value.as_deref().unwrap_or("-"),
            observation.confidence,
            observation.evidence_ids.len()
        ));
    }
    output.push('\n');
}

fn format_location(location: &SourceLocation) -> String {
    match (location.line, location.column) {
        (Some(line), Some(column)) => format!("{}:{line}:{column}", location.path),
        (Some(line), None) => format!("{}:{line}", location.path),
        _ => location.path.clone(),
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

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeObservation,
        CookieAttributeState, CookieAttributes, EvidenceId, Finding, FindingCategory, FindingId,
        LifecycleEvidence, SCHEMA_VERSION, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::render;

    #[test]
    fn renders_cookie_attribute_table() {
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: Vec::new(),
            },
            files: Vec::new(),
            artifacts: vec![Artifact {
                id: ArtifactId("artifact_cookie".to_string()),
                artifact_type: ArtifactType::SessionCookie,
                display_name: Some("session".to_string()),
                locations: vec![SourceLocation {
                    path: "app.ts".to_string(),
                    line: Some(3),
                    column: Some(5),
                }],
                lifecycle_evidence: LifecycleEvidence::default(),
                confidence: Confidence::High,
                framework_hints: vec!["express".to_string()],
                cookie_attributes: Some(attributes()),
            }],
            evidence: Vec::new(),
            findings: Vec::new(),
        };

        let rendered = render(&report);

        assert!(rendered.contains("## Artifacts"));
        assert!(rendered.contains("| HttpOnly | `present` | true | `High` | 0 |"));
        assert!(rendered.contains("| Secure | `dynamic` |"));
        assert!(rendered.contains("`app.ts:3:5`"));
    }

    #[test]
    fn renders_findings_with_review_context() {
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: Vec::new(),
            findings: vec![Finding {
                id: FindingId("finding_cookie".to_string()),
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Medium,
                artifact_ids: vec![ArtifactId("artifact_cookie".to_string())],
                evidence_ids: vec![EvidenceId("evidence_cookie".to_string())],
                title: "Cookie has dynamic Secure evidence".to_string(),
                description: "The Secure attribute appears dynamic.".to_string(),
                suggested_fix: Some("Confirm production Secure behavior.".to_string()),
                reviewer_question: Some("Can production guarantee Secure?".to_string()),
            }],
        };

        let rendered = render(&report);

        assert!(rendered.contains("## Findings"));
        assert!(rendered.contains("Severity: `medium`"));
        assert!(rendered.contains("Category: `dynamic_review_required`"));
        assert!(rendered.contains("Suggested fix: Confirm production Secure behavior."));
        assert!(rendered.contains("Reviewer question: Can production guarantee Secure?"));
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
}
