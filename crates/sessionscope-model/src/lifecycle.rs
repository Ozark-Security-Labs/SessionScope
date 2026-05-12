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
