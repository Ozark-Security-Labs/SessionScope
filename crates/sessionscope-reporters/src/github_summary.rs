use sessionscope_model::{FindingCategory, ScanReport, Severity};

pub fn render(report: &ScanReport) -> String {
    let mut output = format!(
        concat!(
            "## SessionScope\n\n",
            "| Metric | Count |\n",
            "| --- | ---: |\n",
            "| Files discovered | {} |\n",
            "| Files scanned | {} |\n",
            "| Files skipped | {} |\n",
            "| Lifecycle paths | {} |\n",
            "| Findings | {} |\n"
        ),
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.lifecycle_paths.len(),
        report.findings.len()
    );

    output.push('\n');
    if report.findings.is_empty() {
        output.push_str("No findings were detected.\n");
        return output;
    }

    output.push_str("### Key findings\n\n");
    for finding in report.findings.iter().take(5) {
        output.push_str(&format!(
            "- `{}` `{}` {}\n",
            format_severity(finding.severity),
            format_category(finding.category),
            inline_text(&finding.title)
        ));
    }
    if report.findings.len() > 5 {
        output.push_str(&format!(
            "- ...and {} more findings.\n",
            report.findings.len() - 5
        ));
    }

    output
}

fn inline_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
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
