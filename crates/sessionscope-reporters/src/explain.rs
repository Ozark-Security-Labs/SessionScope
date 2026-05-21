use std::collections::{BTreeMap, BTreeSet};

use crate::markdown_escape::{code_span, inline_text, table_cell};
use sessionscope_model::{
    Evidence, Finding, FindingCategory, ScanReport, Severity, SourceLocation,
};

pub fn render(report: &ScanReport, finding_id: &str) -> Option<String> {
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id.0 == finding_id)?;
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();

    Some(render_finding(finding, &evidence_by_id))
}

fn render_finding(finding: &Finding, evidence_by_id: &BTreeMap<&str, &Evidence>) -> String {
    let mut output = format!(
        concat!(
            "# SessionScope Finding Explain\n\n",
            "## Finding\n\n",
            "- Title: {}\n",
            "- Finding ID: {}\n",
            "- Severity: {}\n",
            "- Category: {}\n",
            "- Rationale: {}\n\n",
            "{}\n"
        ),
        inline_text(&finding.title),
        code_span(&finding.id.0),
        code_span(format_severity(finding.severity)),
        code_span(format_category(finding.category)),
        inline_text(rationale(finding.category)),
        inline_text(&finding.description)
    );

    render_relationships(&mut output, finding);
    render_evidence(&mut output, finding, evidence_by_id);
    render_guidance(&mut output, finding);
    render_references(&mut output, finding.category);
    output
}

fn render_relationships(output: &mut String, finding: &Finding) {
    output.push_str("\n## Relationships\n\n");
    if finding.artifact_ids.is_empty() {
        output.push_str("- Artifacts: none linked\n");
    } else {
        output.push_str(&format!(
            "- Artifacts: {}\n",
            finding
                .artifact_ids
                .iter()
                .map(|id| code_span(&id.0))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if finding.evidence_ids.is_empty() {
        output.push_str("- Evidence: none linked\n");
    } else {
        output.push_str(&format!(
            "- Evidence: {}\n",
            finding
                .evidence_ids
                .iter()
                .map(|id| code_span(&id.0))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_evidence(
    output: &mut String,
    finding: &Finding,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) {
    output.push_str("\n## Evidence\n\n");
    let evidence = finding
        .evidence_ids
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()).copied())
        .collect::<Vec<_>>();

    if evidence.is_empty() {
        output.push_str("No linked evidence records were found in the report.\n");
        return;
    }

    output.push_str("| Evidence ID | Stage | Location | Detector | Confidence | Dynamic | Framework default | Excerpt |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for record in evidence {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            code_span(&record.id.0),
            code_span(format_lifecycle_stage(record.lifecycle_stage)),
            table_cell(&format_location(&record.location)),
            table_cell(&record.detector_id),
            code_span(format_confidence(record.confidence)),
            code_span(bool_text(record.dynamic)),
            code_span(bool_text(record.framework_default)),
            record
                .excerpt
                .as_ref()
                .map(|excerpt| table_cell(excerpt.as_str()))
                .unwrap_or_else(|| "-".to_string())
        ));
    }
}

fn render_guidance(output: &mut String, finding: &Finding) {
    output.push_str("\n## Guidance\n\n");
    if let Some(suggested_fix) = &finding.suggested_fix {
        output.push_str(&format!(
            "- Suggested fix: {}\n",
            inline_text(suggested_fix)
        ));
    } else {
        output.push_str("- Suggested fix: no specific remediation was attached to this finding.\n");
    }

    if let Some(question) = &finding.reviewer_question {
        output.push_str(&format!("- Reviewer question: {}\n", inline_text(question)));
    } else {
        output.push_str("- Reviewer question: none attached.\n");
    }
}

fn render_references(output: &mut String, category: FindingCategory) {
    output.push_str("\n## References\n\n");
    let mut references = BTreeSet::from(["docs/SCHEMA.md"]);
    if matches!(
        category,
        FindingCategory::DynamicReviewRequired | FindingCategory::FrameworkDefaultAssumed
    ) {
        references.insert("docs/DESIGN_DECISIONS.md");
    }

    for reference in references {
        output.push_str(&format!("- `{reference}`\n"));
    }
}

fn rationale(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::HighConfidenceMisconfiguration => {
            "The classifier found deterministic source evidence for an unsafe configuration."
        }
        FindingCategory::MissingValidationEvidence => {
            "The classifier did not find matching validation evidence near the related token flow."
        }
        FindingCategory::LifecycleGap => {
            "The classifier found lifecycle evidence that appears incomplete for this artifact."
        }
        FindingCategory::DynamicReviewRequired => {
            "The classifier found dynamic or ambiguous source evidence that needs reviewer confirmation."
        }
        FindingCategory::FrameworkDefaultAssumed => {
            "The finding depends on framework default behavior that should be confirmed for the deployed version."
        }
    }
}

fn format_location(location: &SourceLocation) -> String {
    format!(
        "{}:{}:{}",
        location.path,
        location
            .line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "?".to_string()),
        location
            .column
            .map(|column| column.to_string())
            .unwrap_or_else(|| "?".to_string())
    )
}

fn format_lifecycle_stage(stage: sessionscope_model::LifecycleStage) -> &'static str {
    match stage {
        sessionscope_model::LifecycleStage::Issue => "issue",
        sessionscope_model::LifecycleStage::Store => "store",
        sessionscope_model::LifecycleStage::Transmit => "transmit",
        sessionscope_model::LifecycleStage::Validate => "validate",
        sessionscope_model::LifecycleStage::Refresh => "refresh",
        sessionscope_model::LifecycleStage::Revoke => "revoke",
        sessionscope_model::LifecycleStage::Expire => "expire",
        sessionscope_model::LifecycleStage::Introspect => "introspect",
    }
}

fn format_confidence(confidence: sessionscope_model::Confidence) -> &'static str {
    match confidence {
        sessionscope_model::Confidence::Low => "low",
        sessionscope_model::Confidence::Medium => "medium",
        sessionscope_model::Confidence::High => "high",
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

fn bool_text(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, Evidence, EvidenceId, Finding, FindingCategory, FindingId,
        LifecycleStage, SCHEMA_VERSION, SanitizedExcerpt, ScanReport, ScanSummary, Severity,
        SourceLocation,
    };

    use super::render;

    #[test]
    fn renders_evidence_bound_explain_output() {
        let evidence_id = EvidenceId("evidence_cookie_secure".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Store,
                location: SourceLocation {
                    path: "src/app.ts".to_string(),
                    line: Some(7),
                    column: Some(3),
                },
                detector_id: "cookie.set".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt::from_sanitized(
                    "response.cookie(\"session\", [REDACTED])".to_string(),
                )),
                dynamic: true,
                framework_default: false,
            }],
            lifecycle_paths: Vec::new(),
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

        let output = render(&report, "finding_cookie").expect("finding should render");

        assert!(output.contains("# SessionScope Finding Explain"));
        assert!(output.contains("- Finding ID: `finding_cookie`"));
        assert!(output.contains("- Severity: `medium`"));
        assert!(output.contains("- Category: `dynamic_review_required`"));
        assert!(output.contains("needs reviewer confirmation"));
        assert!(output.contains("| `evidence_cookie_secure` | `store` | src/app.ts:7:3 | cookie.set | `high` | `yes` | `no` | response.cookie"));
        assert!(output.contains("- Suggested fix: Confirm production Secure behavior."));
        assert!(output.contains("- Reviewer question: Can production guarantee Secure?"));
        assert!(output.contains("docs/SCHEMA.md"));
        assert!(output.contains("docs/DESIGN_DECISIONS.md"));
    }

    #[test]
    fn returns_none_for_unknown_finding() {
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: Vec::new(),
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        };

        assert!(render(&report, "missing").is_none());
    }

    #[test]
    fn escapes_markdown_controlled_report_fields() {
        let evidence_id = EvidenceId("evidence_`id`".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Validate,
                location: SourceLocation {
                    path: "src/[auth](x)|file.ts".to_string(),
                    line: Some(3),
                    column: Some(1),
                },
                detector_id: "test.detector".to_string(),
                confidence: Confidence::High,
                excerpt: Some(SanitizedExcerpt::from_sanitized(
                    "![x](y) | `cell`".to_string(),
                )),
                dynamic: false,
                framework_default: false,
            }],
            lifecycle_paths: Vec::new(),
            findings: vec![Finding {
                id: FindingId("finding_`id`".to_string()),
                category: FindingCategory::LifecycleGap,
                severity: Severity::Medium,
                artifact_ids: vec![ArtifactId("artifact".to_string())],
                evidence_ids: vec![evidence_id],
                title: "Injected [link](https://example.test)\n# heading".to_string(),
                description: "Description with | table cell".to_string(),
                suggested_fix: Some("Use `safe` [text](x)".to_string()),
                reviewer_question: Some("Question with ![image](x)".to_string()),
            }],
        };

        let output = render(&report, "finding_`id`").expect("finding should render");

        assert!(output.contains("\\[link\\]\\(https://example.test\\)<br>\\# heading"));
        assert!(output.contains("Description with \\| table cell"));
        assert!(output.contains("Use \\`safe\\` \\[text\\]\\(x\\)"));
        assert!(output.contains("Question with \\!\\[image\\]\\(x\\)"));
        assert!(output.contains("src/\\[auth\\]\\(x\\)\\|file.ts:3:1"));
        assert!(output.contains("\\!\\[x\\]\\(y\\) \\| \\`cell\\`"));
    }
}
