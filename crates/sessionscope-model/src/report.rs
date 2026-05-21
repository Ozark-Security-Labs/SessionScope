use crate::{Artifact, Evidence, Finding, LifecyclePath};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// The discovered file is a symbolic link. Symlinks are refused
    /// during discovery (F-03) so that a hostile target repository
    /// cannot point an in-tree link at `/etc/passwd` or any path
    /// outside the scan root and trick the scanner into reading it.
    Symlink,
    ReadError(String),
    /// File scanning exceeded the per-file CPU budget. See F-10 in the
    /// pre-release remediation plan.
    Timeout,
}

impl SkippedReason {
    pub fn kind(&self) -> SkippedReasonKind {
        match self {
            Self::Binary => SkippedReasonKind::Binary,
            Self::TooLarge => SkippedReasonKind::TooLarge,
            Self::Unsupported => SkippedReasonKind::Unsupported,
            Self::Excluded => SkippedReasonKind::Excluded,
            Self::Ignored => SkippedReasonKind::Ignored,
            Self::SensitivePath => SkippedReasonKind::SensitivePath,
            Self::Symlink => SkippedReasonKind::Symlink,
            Self::ReadError(_) => SkippedReasonKind::ReadError,
            Self::Timeout => SkippedReasonKind::Timeout,
        }
    }
}

/// Variant tag of `SkippedReason` without its payload. Used as a key when
/// counting per-reason skips in `ScanSummary::skipped_by_reason`. See F-13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkippedReasonKind {
    Binary,
    TooLarge,
    Unsupported,
    Excluded,
    Ignored,
    SensitivePath,
    Symlink,
    ReadError,
    Timeout,
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
    /// `files`; this counter aggregates them for quick triage. See F-02.
    #[serde(default)]
    pub worker_panic_count: u32,
    /// Counts of skipped files grouped by SkippedReasonKind. Empty when no
    /// files were skipped. Serialized as a snake_case map (`{"too_large": 3}`)
    /// so reporters and downstream tools can summarise dropped coverage
    /// without re-walking `files`. See F-13.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub skipped_by_reason: BTreeMap<SkippedReasonKind, u32>,
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

impl ScanReport {
    /// Returns true when permission errors dominate the scan's skipped
    /// files. Used by CI integrations to surface a "scan was crippled" signal
    /// even when no findings were produced. See F-13.
    pub fn has_critical_failures(&self) -> bool {
        let total_skipped: u32 = self.summary.skipped_by_reason.values().sum();
        if total_skipped == 0 {
            return false;
        }

        let permission_denied_label = std::io::ErrorKind::PermissionDenied.to_string();
        let permission_errors = self
            .files
            .iter()
            .filter(|file| {
                matches!(
                    file.skipped_reason.as_ref(),
                    Some(SkippedReason::ReadError(message)) if message == &permission_denied_label
                )
            })
            .count() as u32;

        permission_errors * 2 > total_skipped
    }
}
