use crate::{ArtifactId, EvidenceId};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingCategory {
    HighConfidenceMisconfiguration,
    MissingValidationEvidence,
    LifecycleGap,
    DynamicReviewRequired,
    FrameworkDefaultAssumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
