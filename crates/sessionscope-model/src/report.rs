use crate::{Artifact, Evidence, Finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Json,
    Yaml,
    Toml,
    Text,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkippedReason {
    Binary,
    TooLarge,
    Unsupported,
    ReadError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileScanResult {
    pub path: String,
    pub language: Language,
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub diagnostics: Vec<String>,
    pub skipped_reason: Option<SkippedReason>,
}

impl FileScanResult {
    pub fn scanned(path: String, language: Language) -> Self {
        Self {
            path,
            language,
            artifacts: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            skipped_reason: None,
        }
    }

    pub fn skipped(path: String, language: Language, skipped_reason: SkippedReason) -> Self {
        Self {
            path,
            language,
            artifacts: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            skipped_reason: Some(skipped_reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanSummary {
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub schema_version: &'static str,
    pub summary: ScanSummary,
    pub files: Vec<FileScanResult>,
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub findings: Vec<Finding>,
}
