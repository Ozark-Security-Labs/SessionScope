use crate::{ArtifactId, EvidenceId, FindingCategory, FindingId, Severity, SourceLocation};
use serde::{Deserialize, Serialize};

pub const BASELINE_SCHEMA_VERSION: &str = "0.1.0";
pub const DIFF_SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub schema_version: String,
    pub report_schema_version: String,
    pub created_by: String,
    pub findings: Vec<BaselineFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub id: FindingId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub semantic_fingerprint: String,
    pub evidence_fingerprint: String,
    pub artifact_ids: Vec<ArtifactId>,
    pub evidence_ids: Vec<EvidenceId>,
    pub source_locations: Vec<SourceLocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffChangeKind {
    New,
    Unchanged,
    Changed,
    Moved,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    pub new: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub moved: usize,
    pub resolved: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema_version: String,
    pub baseline_schema_version: String,
    pub current_report_schema_version: String,
    pub summary: DiffSummary,
    pub changes: Vec<DiffFindingChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFindingChange {
    pub kind: DiffChangeKind,
    pub baseline: Option<BaselineFinding>,
    pub current: Option<BaselineFinding>,
}
