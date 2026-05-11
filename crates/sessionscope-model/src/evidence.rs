use crate::LifecycleStage;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

/// Sanitized source context suitable for reports and persisted inventory.
///
/// Values must be redacted before construction and must not contain token
/// values, private keys, bearer strings, cookie values, or runtime secrets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SanitizedExcerpt(pub String);

impl From<String> for SanitizedExcerpt {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SanitizedExcerpt {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub lifecycle_stage: LifecycleStage,
    pub location: SourceLocation,
    pub detector_id: String,
    pub confidence: Confidence,
    pub excerpt: Option<SanitizedExcerpt>,
    pub dynamic: bool,
    pub framework_default: bool,
}
