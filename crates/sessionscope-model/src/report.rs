use crate::{Artifact, Evidence, Finding, LifecyclePath};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkippedReason {
    Binary,
    TooLarge,
    Unsupported,
    Excluded,
    Ignored,
    SensitivePath,
    ReadError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub diagnostics: Vec<String>,
    /// Number of worker-thread panics caught during scanning. Each panic is
    /// reported as a `SkippedReason::ReadError("detector panic")` entry in
    /// `files`; this counter aggregates them for quick triage.
    #[serde(default)]
    pub worker_panic_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub summary: ScanSummary,
    pub files: Vec<FileScanResult>,
    pub artifacts: Vec<Artifact>,
    pub evidence: Vec<Evidence>,
    pub lifecycle_paths: Vec<LifecyclePath>,
    pub findings: Vec<Finding>,
}
