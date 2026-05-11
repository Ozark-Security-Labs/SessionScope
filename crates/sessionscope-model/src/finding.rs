use crate::{ArtifactId, EvidenceId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    HighConfidenceMisconfiguration,
    MissingValidationEvidence,
    LifecycleGap,
    DynamicReviewRequired,
    FrameworkDefaultAssumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub category: FindingCategory,
    pub severity: Severity,
    pub artifact_ids: Vec<ArtifactId>,
    pub evidence_ids: Vec<EvidenceId>,
    pub title: String,
    pub description: String,
    pub suggested_fix: Option<String>,
    pub reviewer_question: Option<String>,
}
