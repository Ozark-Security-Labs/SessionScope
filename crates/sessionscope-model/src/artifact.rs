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
    /// Source-visible OAuth/OIDC authorization-code flow construction.
    ///
    /// Added by the P3.1 artifact audit because existing session, bearer,
    /// cookie, and JWT artifacts do not accurately model an authorization
    /// request plus callback verification lifecycle.
    OAuthAuthCodeFlow,
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

impl Default for JwtAttributeObservation {
    fn default() -> Self {
        Self {
            state: JwtAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtIdentityClaims {
    #[serde(default)]
    pub subject: JwtAttributeObservation,
    #[serde(default)]
    pub user_id: JwtAttributeObservation,
    #[serde(default)]
    pub tenant_id: JwtAttributeObservation,
    #[serde(default)]
    pub org_id: JwtAttributeObservation,
    #[serde(default)]
    pub workspace_id: JwtAttributeObservation,
    #[serde(default)]
    pub roles: JwtAttributeObservation,
    #[serde(default)]
    pub scopes: JwtAttributeObservation,
    #[serde(default)]
    pub groups: JwtAttributeObservation,
    #[serde(default)]
    pub email: JwtAttributeObservation,
    #[serde(default)]
    pub email_verified: JwtAttributeObservation,
    #[serde(default)]
    pub auth_method: JwtAttributeObservation,
    #[serde(default)]
    pub auth_class: JwtAttributeObservation,
}

impl Default for JwtIdentityClaims {
    fn default() -> Self {
        let unknown = JwtAttributeObservation::default();
        Self {
            subject: unknown.clone(),
            user_id: unknown.clone(),
            tenant_id: unknown.clone(),
            org_id: unknown.clone(),
            workspace_id: unknown.clone(),
            roles: unknown.clone(),
            scopes: unknown.clone(),
            groups: unknown.clone(),
            email: unknown.clone(),
            email_verified: unknown.clone(),
            auth_method: unknown.clone(),
            auth_class: unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAttributes {
    #[serde(default)]
    pub operation: JwtAttributeObservation,
    #[serde(default)]
    pub algorithm: JwtAttributeObservation,
    #[serde(default)]
    pub key_reference: JwtAttributeObservation,
    #[serde(default)]
    pub issuer: JwtAttributeObservation,
    #[serde(default)]
    pub audience: JwtAttributeObservation,
    #[serde(default)]
    pub expiration: JwtAttributeObservation,
    #[serde(default)]
    pub signature_verification: JwtAttributeObservation,
    #[serde(default)]
    pub expiry_enforcement: JwtAttributeObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_claims: Option<JwtIdentityClaims>,
}

impl Default for JwtAttributes {
    fn default() -> Self {
        let unknown = JwtAttributeObservation::default();
        Self {
            operation: unknown.clone(),
            algorithm: unknown.clone(),
            key_reference: unknown.clone(),
            issuer: unknown.clone(),
            audience: unknown.clone(),
            expiration: unknown.clone(),
            signature_verification: unknown.clone(),
            expiry_enforcement: unknown,
            identity_claims: None,
        }
    }
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
    #[serde(default = "TokenBoundaryObservation::default_state")]
    pub state: TokenBoundaryAttributeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<EvidenceId>,
    #[serde(default = "TokenBoundaryObservation::default_confidence")]
    pub confidence: Confidence,
}

impl TokenBoundaryObservation {
    fn default_state() -> TokenBoundaryAttributeState {
        TokenBoundaryAttributeState::Unknown
    }

    fn default_confidence() -> Confidence {
        Confidence::Low
    }

    pub fn is_unknown(&self) -> bool {
        self.state == TokenBoundaryAttributeState::Unknown
            && self.value.is_none()
            && self.evidence_ids.is_empty()
            && self.confidence == Confidence::Low
    }
}

impl Default for TokenBoundaryObservation {
    fn default() -> Self {
        Self {
            state: TokenBoundaryAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBoundaryAttributes {
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub issuer: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub audience: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub service: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub environment: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub tenant: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub provider: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub scope: TokenBoundaryObservation,
    #[serde(default, skip_serializing_if = "TokenBoundaryObservation::is_unknown")]
    pub trust_boundary: TokenBoundaryObservation,
}

impl TokenBoundaryAttributes {
    pub fn is_all_unknown(&self) -> bool {
        self.issuer.is_unknown()
            && self.audience.is_unknown()
            && self.service.is_unknown()
            && self.environment.is_unknown()
            && self.tenant.is_unknown()
            && self.provider.is_unknown()
            && self.scope.is_unknown()
            && self.trust_boundary.is_unknown()
    }
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
    #[serde(default, skip_serializing_if = "token_boundary_attributes_absent")]
    pub token_boundary_attributes: Option<TokenBoundaryAttributes>,
}

fn token_boundary_attributes_absent(attributes: &Option<TokenBoundaryAttributes>) -> bool {
    attributes
        .as_ref()
        .is_none_or(TokenBoundaryAttributes::is_all_unknown)
}
