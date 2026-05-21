use crate::{ArtifactId, Confidence, EvidenceId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecyclePathId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    Issue,
    Store,
    Transmit,
    Validate,
    Refresh,
    Revoke,
    Expire,
    Introspect,
}

impl LifecycleStage {
    pub const ORDERED: [Self; 8] = [
        Self::Issue,
        Self::Store,
        Self::Transmit,
        Self::Validate,
        Self::Refresh,
        Self::Revoke,
        Self::Expire,
        Self::Introspect,
    ];

    /// Return the stable snake_case wire name matching the serde
    /// representation. See `FindingCategory::stable_name` for the
    /// motivation (F-07).
    pub fn stable_name(self) -> &'static str {
        match self {
            LifecycleStage::Issue => "issue",
            LifecycleStage::Store => "store",
            LifecycleStage::Transmit => "transmit",
            LifecycleStage::Validate => "validate",
            LifecycleStage::Refresh => "refresh",
            LifecycleStage::Revoke => "revoke",
            LifecycleStage::Expire => "expire",
            LifecycleStage::Introspect => "introspect",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LifecyclePathStep {
    pub stage: LifecycleStage,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecyclePath {
    pub id: LifecyclePathId,
    pub artifact_ids: Vec<ArtifactId>,
    pub stages: Vec<LifecyclePathStep>,
    pub confidence: Confidence,
    pub dynamic: bool,
    pub reviewer_question: Option<String>,
}
