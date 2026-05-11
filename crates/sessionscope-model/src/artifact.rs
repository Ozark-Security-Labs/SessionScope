use crate::{Confidence, EvidenceId, SourceLocation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    SessionCookie,
    SignedCookie,
    AccessJwt,
    RefreshJwt,
    OpaqueBearerToken,
    ApiKey,
    PasswordResetToken,
    EmailVerificationToken,
    SessionRecord,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LifecycleEvidence {
    pub issue: Vec<EvidenceId>,
    pub store: Vec<EvidenceId>,
    pub transmit: Vec<EvidenceId>,
    pub validate: Vec<EvidenceId>,
    pub refresh: Vec<EvidenceId>,
    pub revoke: Vec<EvidenceId>,
    pub expire: Vec<EvidenceId>,
    pub introspect: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub artifact_type: ArtifactType,
    pub display_name: Option<String>,
    pub locations: Vec<SourceLocation>,
    pub lifecycle_evidence: LifecycleEvidence,
    pub confidence: Confidence,
    pub framework_hints: Vec<String>,
}
