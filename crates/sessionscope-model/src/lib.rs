pub mod artifact;
pub mod evidence;
pub mod finding;
pub mod lifecycle;
pub mod report;
pub mod schema;

pub use artifact::{
    Artifact, ArtifactId, ArtifactType, CookieAttributeObservation, CookieAttributeState,
    CookieAttributes, JwtAttributeObservation, JwtAttributeState, JwtAttributes, JwtIdentityClaims,
    LifecycleEvidence,
};
pub use evidence::{Confidence, Evidence, EvidenceId, SanitizedExcerpt, SourceLocation};
pub use finding::{Finding, FindingCategory, FindingId, Severity};
pub use lifecycle::LifecycleStage;
pub use report::{FileScanResult, Language, ScanReport, ScanSummary, SkippedReason};
pub use schema::{SCHEMA_VERSION, stable_artifact_id, stable_evidence_id, stable_finding_id};

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        Artifact, ArtifactId, ArtifactType, Confidence, CookieAttributeObservation,
        CookieAttributeState, CookieAttributes, Evidence, EvidenceId, Finding, FindingCategory,
        FindingId, JwtAttributeObservation, JwtAttributeState, JwtAttributes, JwtIdentityClaims,
        LifecycleEvidence, LifecycleStage, SCHEMA_VERSION, SanitizedExcerpt, Severity,
        SourceLocation, stable_artifact_id, stable_evidence_id, stable_finding_id,
    };

    fn source_location() -> SourceLocation {
        SourceLocation {
            path: "src/auth/session.ts".to_string(),
            line: Some(42),
            column: Some(9),
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            id: EvidenceId("evidence_cookie_store".to_string()),
            lifecycle_stage: LifecycleStage::Store,
            location: source_location(),
            detector_id: "detector.cookie.set".to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt("[REDACTED] cookie attributes".to_string())),
            dynamic: false,
            framework_default: false,
        }
    }

    #[test]
    fn round_trips_artifact_with_lifecycle_evidence() {
        let artifact = Artifact {
            id: ArtifactId("artifact_session_cookie".to_string()),
            artifact_type: ArtifactType::SessionCookie,
            display_name: Some("session".to_string()),
            locations: vec![source_location()],
            lifecycle_evidence: LifecycleEvidence {
                store: vec![EvidenceId("evidence_cookie_store".to_string())],
                expire: vec![EvidenceId("evidence_cookie_expire".to_string())],
                ..LifecycleEvidence::default()
            },
            confidence: Confidence::High,
            framework_hints: vec!["express".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
        };

        let serialized =
            serde_json::to_string(&artifact).expect("artifact should serialize to JSON");
        let deserialized: Artifact =
            serde_json::from_str(&serialized).expect("artifact should deserialize from JSON");

        assert_eq!(deserialized, artifact);
        assert!(serialized.contains("\"artifact_type\":\"session_cookie\""));
        assert!(serialized.contains("\"lifecycle_evidence\""));
    }

    #[test]
    fn round_trips_evidence_bound_finding() {
        let finding = Finding {
            id: FindingId("finding_missing_audience".to_string()),
            category: FindingCategory::MissingValidationEvidence,
            severity: Severity::Medium,
            artifact_ids: vec![ArtifactId("artifact_access_jwt".to_string())],
            evidence_ids: vec![EvidenceId("evidence_jwt_verify".to_string())],
            title: "Audience validation evidence was not found".to_string(),
            description: "JWT verification evidence does not include an audience check."
                .to_string(),
            suggested_fix: Some("Require an expected audience during verification.".to_string()),
            reviewer_question: Some(
                "Should this service reject tokens for other audiences?".to_string(),
            ),
        };

        let serialized = serde_json::to_string(&finding).expect("finding should serialize to JSON");
        let deserialized: Finding =
            serde_json::from_str(&serialized).expect("finding should deserialize from JSON");

        assert_eq!(deserialized, finding);
        assert!(serialized.contains("\"category\":\"missing_validation_evidence\""));
        assert!(serialized.contains("\"reviewer_question\""));
    }

    #[test]
    fn enum_wire_values_are_snake_case() {
        assert_eq!(SCHEMA_VERSION, "0.3.0");
        assert_eq!(
            serde_json::to_value(FindingCategory::HighConfidenceMisconfiguration)
                .expect("category should serialize"),
            json!("high_confidence_misconfiguration")
        );
        assert_eq!(
            serde_json::to_value(FindingCategory::FrameworkDefaultAssumed)
                .expect("category should serialize"),
            json!("framework_default_assumed")
        );
        assert_eq!(
            serde_json::to_value(LifecycleStage::Introspect).expect("stage should serialize"),
            json!("introspect")
        );
        assert_eq!(
            serde_json::to_value(ArtifactType::PasswordResetToken)
                .expect("artifact type should serialize"),
            json!("password_reset_token")
        );
        assert_eq!(
            serde_json::to_value(CookieAttributeState::FrameworkDefault)
                .expect("cookie attribute state should serialize"),
            json!("framework_default")
        );
    }

    #[test]
    fn round_trips_cookie_attribute_inventory() {
        let evidence_id = EvidenceId("evidence_cookie_secure".to_string());
        let observed = CookieAttributeObservation {
            state: CookieAttributeState::Present,
            value: Some("true".to_string()),
            evidence_ids: vec![evidence_id.clone()],
            confidence: Confidence::High,
        };
        let missing = CookieAttributeObservation {
            state: CookieAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        let attributes = CookieAttributes {
            http_only: observed.clone(),
            secure: observed,
            same_site: CookieAttributeObservation {
                state: CookieAttributeState::FrameworkDefault,
                value: Some("lax".to_string()),
                evidence_ids: vec![evidence_id],
                confidence: Confidence::Low,
            },
            max_age: missing.clone(),
            expires: missing.clone(),
            path: missing.clone(),
            domain: missing,
        };

        let serialized =
            serde_json::to_string(&attributes).expect("cookie attributes should serialize");
        let deserialized: CookieAttributes =
            serde_json::from_str(&serialized).expect("cookie attributes should deserialize");

        assert_eq!(deserialized, attributes);
        assert!(serialized.contains("\"http_only\""));
        assert!(serialized.contains("\"same_site\""));
    }

    #[test]
    fn round_trips_jwt_attribute_inventory() {
        let evidence_id = EvidenceId("evidence_jwt_issuer".to_string());
        let observed = JwtAttributeObservation {
            state: JwtAttributeState::Present,
            value: Some("ISSUER".to_string()),
            evidence_ids: vec![evidence_id],
            confidence: Confidence::High,
        };
        let missing = JwtAttributeObservation {
            state: JwtAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        let attributes = JwtAttributes {
            operation: JwtAttributeObservation {
                state: JwtAttributeState::Present,
                value: Some("validate".to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::High,
            },
            algorithm: missing.clone(),
            key_reference: missing.clone(),
            issuer: observed,
            audience: missing.clone(),
            expiration: missing.clone(),
            signature_verification: JwtAttributeObservation {
                state: JwtAttributeState::Present,
                value: Some("verified".to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::High,
            },
            expiry_enforcement: JwtAttributeObservation {
                state: JwtAttributeState::FrameworkDefault,
                value: Some("library_default".to_string()),
                evidence_ids: Vec::new(),
                confidence: Confidence::Low,
            },
            identity_claims: Some(JwtIdentityClaims {
                subject: JwtAttributeObservation {
                    state: JwtAttributeState::Present,
                    value: Some("userId".to_string()),
                    evidence_ids: Vec::new(),
                    confidence: Confidence::High,
                },
                user_id: missing.clone(),
                tenant_id: missing.clone(),
                org_id: missing.clone(),
                workspace_id: missing.clone(),
                roles: missing.clone(),
                scopes: missing.clone(),
                groups: missing.clone(),
                email: missing.clone(),
                email_verified: missing.clone(),
                auth_method: missing.clone(),
                auth_class: missing,
            }),
        };

        let serialized = serde_json::to_string(&attributes).expect("jwt attributes serialize");
        let deserialized: JwtAttributes =
            serde_json::from_str(&serialized).expect("jwt attributes deserialize");

        assert_eq!(deserialized, attributes);
        assert!(serialized.contains("\"issuer\""));
        assert!(serialized.contains("\"key_reference\""));
        assert!(serialized.contains("\"signature_verification\""));
        assert!(serialized.contains("\"expiry_enforcement\""));
        assert!(serialized.contains("\"identity_claims\""));
        assert!(serialized.contains("\"subject\""));

        let mut attributes_without_claims = attributes;
        attributes_without_claims.identity_claims = None;
        let serialized_without_claims =
            serde_json::to_string(&attributes_without_claims).expect("jwt attributes serialize");
        assert!(!serialized_without_claims.contains("\"identity_claims\""));
    }

    #[test]
    fn ids_are_transparent_strings_and_stable() {
        let id = ArtifactId("artifact_abc123".to_string());
        assert_eq!(
            serde_json::to_value(&id).expect("artifact ID should serialize"),
            json!("artifact_abc123")
        );

        let parts = [
            "detector.cookie.set",
            "session_cookie",
            "src\\auth.ts",
            "42",
        ];
        assert_eq!(stable_artifact_id(&parts), stable_artifact_id(&parts));
        assert!(stable_artifact_id(&parts).0.starts_with("artifact_"));
        assert!(stable_evidence_id(&parts).0.starts_with("evidence_"));
        assert!(stable_finding_id(&parts).0.starts_with("finding_"));
        assert_eq!(
            stable_artifact_id(&[" src\\auth.ts "]),
            stable_artifact_id(&["src/auth.ts"])
        );
    }

    #[test]
    fn evidence_serialization_uses_sanitized_excerpts() {
        let token_secret = "aaa.bbb.cccccccccccccccccccccc";
        let serialized = serde_json::to_string(&evidence()).expect("evidence should serialize");

        assert!(serialized.contains("[REDACTED]"));
        assert!(!serialized.contains(token_secret));
    }
}
