use crate::markdown_escape::{code_span, inline_text};
use sessionscope_model::{
    DiffChangeKind, DiffFindingChange, DiffReport, FindingCategory, Severity, SourceLocation,
};

pub fn render_markdown(report: &DiffReport) -> String {
    let mut output = format!(
        concat!(
            "# SessionScope Diff\n\n",
            "## Summary\n\n",
            "- Schema version: `{}`\n",
            "- Baseline schema version: `{}`\n",
            "- Current report schema version: `{}`\n",
            "- New: {}\n",
            "- Unchanged: {}\n",
            "- Changed: {}\n",
            "- Moved: {}\n",
            "- Resolved: {}\n"
        ),
        report.schema_version,
        report.baseline_schema_version,
        report.current_report_schema_version,
        report.summary.new,
        report.summary.unchanged,
        report.summary.changed,
        report.summary.moved,
        report.summary.resolved
    );

    render_group(&mut output, "New", report, DiffChangeKind::New);
    render_group(&mut output, "Changed", report, DiffChangeKind::Changed);
    render_group(&mut output, "Moved", report, DiffChangeKind::Moved);
    render_group(&mut output, "Resolved", report, DiffChangeKind::Resolved);
    render_group(&mut output, "Unchanged", report, DiffChangeKind::Unchanged);
    output
}

pub fn render_json(report: &DiffReport) -> String {
    serde_json::to_string_pretty(report).expect("DiffReport serialization should not fail")
}

fn render_group(output: &mut String, title: &str, report: &DiffReport, kind: DiffChangeKind) {
    output.push_str(&format!("\n## {title}\n\n"));
    let changes = report
        .changes
        .iter()
        .filter(|change| change.kind == kind)
        .collect::<Vec<_>>();

    if changes.is_empty() {
        output.push_str("No findings.\n");
        return;
    }

    for change in changes {
        render_change(output, change);
    }
}

fn render_change(output: &mut String, change: &DiffFindingChange) {
    let finding = change.current.as_ref().or(change.baseline.as_ref());
    let Some(finding) = finding else {
        return;
    };

    output.push_str(&format!("### {}\n\n", inline_text(&finding.title)));
    output.push_str(&format!(
        "- Finding ID: {}\n- Severity: {}\n- Category: {}\n",
        code_span(&finding.id.0),
        code_span(format_severity(finding.severity)),
        code_span(format_category(finding.category))
    ));

    match (&change.baseline, &change.current) {
        (Some(baseline), Some(current)) if change.kind == DiffChangeKind::Moved => {
            output.push_str(&format!(
                "- Previous locations: {}\n- Current locations: {}\n",
                format_locations(&baseline.source_locations),
                format_locations(&current.source_locations)
            ));
        }
        (Some(baseline), Some(current)) if change.kind == DiffChangeKind::Changed => {
            output.push_str(&format!(
                "- Baseline fingerprint: {}\n- Current fingerprint: {}\n- Current locations: {}\n",
                code_span(&baseline.semantic_fingerprint),
                code_span(&current.semantic_fingerprint),
                format_locations(&current.source_locations)
            ));
        }
        (_, Some(current)) => {
            output.push_str(&format!(
                "- Source locations: {}\n",
                format_locations(&current.source_locations)
            ));
        }
        (Some(baseline), None) => {
            output.push_str(&format!(
                "- Previous locations: {}\n",
                format_locations(&baseline.source_locations)
            ));
        }
        _ => {}
    }

    output.push('\n');
}

fn format_locations(locations: &[SourceLocation]) -> String {
    if locations.is_empty() {
        return "unknown".to_string();
    }

    locations
        .iter()
        .map(format_location)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_location(location: &SourceLocation) -> String {
    let line = location
        .line
        .map(|line| line.to_string())
        .unwrap_or_else(|| "?".to_string());
    let column = location
        .column
        .map(|column| column.to_string())
        .unwrap_or_else(|| "?".to_string());
    code_span(format!("{}:{line}:{column}", location.path))
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

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        BaselineFinding, DiffChangeKind, DiffFindingChange, DiffReport, DiffSummary,
        FindingCategory, FindingId, Severity, SourceLocation,
    };

    use super::render_markdown;

    #[test]
    fn markdown_escapes_report_controlled_fields() {
        let report = DiffReport {
            schema_version: "0.1.0".to_string(),
            baseline_schema_version: "0.1.0".to_string(),
            current_report_schema_version: "0.5.0".to_string(),
            summary: DiffSummary {
                new: 1,
                ..DiffSummary::default()
            },
            changes: vec![DiffFindingChange {
                kind: DiffChangeKind::New,
                baseline: None,
                current: Some(BaselineFinding {
                    id: FindingId("finding_`id`".to_string()),
                    category: FindingCategory::LifecycleGap,
                    severity: Severity::Medium,
                    title: "Injected [link](https://example.test)\n# heading | cell".to_string(),
                    semantic_fingerprint: "fingerprint_`semantic`".to_string(),
                    evidence_fingerprint: "fingerprint_evidence".to_string(),
                    artifact_ids: Vec::new(),
                    evidence_ids: Vec::new(),
                    source_locations: vec![SourceLocation {
                        path: "src/`auth`|file.ts\n![x](y)".to_string(),
                        line: Some(7),
                        column: Some(1),
                    }],
                }),
            }],
        };

        let rendered = render_markdown(&report);

        assert!(rendered.contains("\\[link\\]\\(https://example.test\\)"));
        assert!(rendered.contains("<br>\\# heading \\| cell"));
        assert!(rendered.contains("`` finding_`id` ``"));
        assert!(rendered.contains("``src/`auth`|file.ts<br>![x](y):7:1``"));
    }
}
