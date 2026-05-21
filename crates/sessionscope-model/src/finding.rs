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

impl FindingCategory {
    /// Return the stable snake_case wire name matching the serde
    /// representation.
    ///
    /// This is the canonical string used in SARIF `ruleId`, baseline
    /// fingerprints, and any other persistence layer. Per F-07, callers
    /// must use this instead of `format!("{:?}", category)` because
    /// `Debug` is not part of the wire contract and changes if variants
    /// are renamed.
    pub fn stable_name(self) -> &'static str {
        match self {
            FindingCategory::HighConfidenceMisconfiguration => "high_confidence_misconfiguration",
            FindingCategory::MissingValidationEvidence => "missing_validation_evidence",
            FindingCategory::LifecycleGap => "lifecycle_gap",
            FindingCategory::DynamicReviewRequired => "dynamic_review_required",
            FindingCategory::FrameworkDefaultAssumed => "framework_default_assumed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Return the stable snake_case wire name matching the serde
    /// representation. See `FindingCategory::stable_name` for the
    /// motivation (F-07).
    pub fn stable_name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
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
