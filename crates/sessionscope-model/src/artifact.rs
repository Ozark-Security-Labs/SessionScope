use crate::{Confidence, EvidenceId, SourceLocation};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub id: ArtifactId,
    pub artifact_type: ArtifactType,
    pub display_name: Option<String>,
    pub locations: Vec<SourceLocation>,
    pub evidence_ids: Vec<EvidenceId>,
    pub confidence: Confidence,
    pub framework_hints: Vec<String>,
}
