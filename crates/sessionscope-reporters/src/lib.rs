pub mod github_summary;
pub mod json;
pub mod markdown;
pub mod sarif;

use std::fmt;

use sessionscope_core::redaction::sanitized_report;
use sessionscope_model::ScanReport;

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
    let report = sanitized_report(report);
    match format {
        ReportFormat::Json => json::render(&report),
        ReportFormat::Markdown => markdown::render(&report),
        ReportFormat::Sarif => sarif::render(&report),
        ReportFormat::GithubSummary => github_summary::render(&report),
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Confidence, Evidence, EvidenceId, Finding, FindingCategory, FindingId, LifecycleStage,
        SCHEMA_VERSION, SanitizedExcerpt, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::{ReportFormat, render};

    const SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789";

    fn unsafe_report() -> ScanReport {
        let evidence_id = EvidenceId("evidence_report_secret".to_string());
        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: vec![format!("diagnostic saw token {SECRET}")],
            },
            files: Vec::new(),
            artifacts: Vec::new(),
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
                excerpt: Some(SanitizedExcerpt(format!("Authorization: Bearer {SECRET}"))),
                dynamic: false,
                framework_default: false,
            }],
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
}
