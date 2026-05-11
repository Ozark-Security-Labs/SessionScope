pub mod github_summary;
pub mod json;
pub mod markdown;
pub mod sarif;

use std::fmt;

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
    match format {
        ReportFormat::Json => json::render(report),
        ReportFormat::Markdown => markdown::render(report),
        ReportFormat::Sarif => sarif::render(report),
        ReportFormat::GithubSummary => github_summary::render(report),
    }
}
