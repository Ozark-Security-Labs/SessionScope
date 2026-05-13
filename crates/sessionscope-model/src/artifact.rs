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
    ServiceToken,
    UnknownToken,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieAttributeState {
    Present,
    Missing,
    Dynamic,
    FrameworkDefault,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieAttributeObservation {
    pub state: CookieAttributeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub evidence_ids: Vec<EvidenceId>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieAttributes {
    pub http_only: CookieAttributeObservation,
    pub secure: CookieAttributeObservation,
    pub same_site: CookieAttributeObservation,
    pub max_age: CookieAttributeObservation,
    pub expires: CookieAttributeObservation,
    pub path: CookieAttributeObservation,
    pub domain: CookieAttributeObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtAttributeState {
    Present,
    Missing,
    Dynamic,
    FrameworkDefault,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAttributeObservation {
    pub state: JwtAttributeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub evidence_ids: Vec<EvidenceId>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtIdentityClaims {
    pub subject: JwtAttributeObservation,
    pub user_id: JwtAttributeObservation,
    pub tenant_id: JwtAttributeObservation,
    pub org_id: JwtAttributeObservation,
    pub workspace_id: JwtAttributeObservation,
    pub roles: JwtAttributeObservation,
    pub scopes: JwtAttributeObservation,
    pub groups: JwtAttributeObservation,
    pub email: JwtAttributeObservation,
    pub email_verified: JwtAttributeObservation,
    pub auth_method: JwtAttributeObservation,
    pub auth_class: JwtAttributeObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAttributes {
    pub operation: JwtAttributeObservation,
    pub algorithm: JwtAttributeObservation,
    pub key_reference: JwtAttributeObservation,
    pub issuer: JwtAttributeObservation,
    pub audience: JwtAttributeObservation,
    pub expiration: JwtAttributeObservation,
    pub signature_verification: JwtAttributeObservation,
    pub expiry_enforcement: JwtAttributeObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claims: Option<JwtIdentityClaims>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenBoundaryAttributeState {
    Present,
    Missing,
    Dynamic,
    FrameworkDefault,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBoundaryObservation {
    pub state: TokenBoundaryAttributeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub evidence_ids: Vec<EvidenceId>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBoundaryAttributes {
    pub issuer: TokenBoundaryObservation,
    pub audience: TokenBoundaryObservation,
    pub service: TokenBoundaryObservation,
    pub environment: TokenBoundaryObservation,
    pub tenant: TokenBoundaryObservation,
    pub provider: TokenBoundaryObservation,
    pub scope: TokenBoundaryObservation,
    pub trust_boundary: TokenBoundaryObservation,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_attributes: Option<CookieAttributes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_attributes: Option<JwtAttributes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_boundary_attributes: Option<TokenBoundaryAttributes>,
}
