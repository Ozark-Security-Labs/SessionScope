use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use sessionscope_model::{
    Artifact, ArtifactType, Confidence, Evidence, JwtAttributeObservation, JwtAttributeState,
    JwtAttributes, JwtIdentityClaims, Language, LifecycleEvidence, LifecycleStage,
    SanitizedExcerpt, SourceLocation, TokenBoundaryAttributeState, TokenBoundaryAttributes,
    TokenBoundaryObservation, stable_artifact_id, stable_evidence_id,
};
use tree_sitter::{Node, Parser, Tree};

use crate::{DetectionOutput, Detector, DetectorInput};

const DETECTOR_ID: &str = "jwt.validation";
const REDACTION: &str = "[REDACTED]";

static PLACEHOLDER_SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bPLACEHOLDER[A-Z0-9_]*(?:TOKEN|SECRET|JWT)[A-Z0-9_]*\b")
        .expect("placeholder secret regex should compile")
});
static JWT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{6,}\b")
        .expect("JWT regex should compile")
});
static LONG_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(secret|private[_-]?key|signing[_-]?key|token|jwt)\s*[:=]\s*["'][^"']*["']"#)
        .expect("sensitive literal regex should compile")
});
static JWT_API_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?sx)\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?(?:sign|verify|decode|encode|jwtVerify|decodeJwt)\s*\((?:[^()]|\([^)]*\)){0,600}\)"#,
    )
    .expect("JWT API call regex should compile")
});
static QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#)
        .expect("quoted literal regex should compile")
});
static SENSITIVE_CLAIM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?(?:sub|email|email_verified|emailVerified|phone|address|sid|jti|user_id|userId|uid|tenant|tenant_id|tenantId|org|org_id|organization_id|organizationId|workspace|workspace_id|workspaceId|role|roles|scope|scopes|groups|amr|acr|auth_method|authMethod|auth_class|authClass)["']?\s*:\s*["'])([^"']+)(["'])"#,
    )
    .expect("sensitive claim regex should compile")
});
static SENSITIVE_CLAIM_COLLECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)(["']?(?:role|roles|scope|scopes|groups|amr|acr|auth_method|authMethod|auth_class|authClass)["']?\s*:\s*)(\[[^\]]*\]|\{[^}]*\})"#,
    )
    .expect("sensitive claim collection regex should compile")
});
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .expect("email regex should compile")
});

#[derive(Debug, Clone, Copy, Default)]
pub struct JwtDetector;

impl Detector for JwtDetector {
    fn id(&self) -> &'static str {
        DETECTOR_ID
    }

    fn detect(&self, input: &DetectorInput<'_>) -> DetectionOutput {
        match input.language {
            Language::JavaScript | Language::TypeScript => detect_javascript_like(input, self.id()),
            Language::Python => detect_python(input, self.id()),
            _ => DetectionOutput::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JwtOperation {
    Issue,
    Validate,
    DecodeWithoutVerify,
}

impl JwtOperation {
    fn lifecycle_stage(self) -> LifecycleStage {
        match self {
            Self::Issue => LifecycleStage::Issue,
            Self::Validate => LifecycleStage::Validate,
            Self::DecodeWithoutVerify => LifecycleStage::Introspect,
        }
    }

    fn value(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Validate => "validate",
            Self::DecodeWithoutVerify => "decode_without_verify",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JwtField {
    Operation,
    Algorithm,
    KeyReference,
    Issuer,
    Audience,
    Expiration,
    SignatureVerification,
    ExpiryEnforcement,
    Subject,
    UserId,
    TenantId,
    OrgId,
    WorkspaceId,
    Roles,
    Scopes,
    Groups,
    Email,
    EmailVerified,
    AuthMethod,
    AuthClass,
    OptionAlgorithms,
    OptionAudience,
    OptionIssuer,
    OptionSubject,
    OptionNonce,
    OptionClockTolerance,
    OptionClockTimestamp,
    OptionComplete,
    OptionIgnoreNotBefore,
    OptionIgnoreExpiration,
    HeaderJku,
    HeaderX5u,
    HeaderJwk,
    HeaderKid,
}

impl JwtField {
    const ALL: [Self; 20] = [
        Self::Operation,
        Self::Algorithm,
        Self::KeyReference,
        Self::Issuer,
        Self::Audience,
        Self::Expiration,
        Self::SignatureVerification,
        Self::ExpiryEnforcement,
        Self::Subject,
        Self::UserId,
        Self::TenantId,
        Self::OrgId,
        Self::WorkspaceId,
        Self::Roles,
        Self::Scopes,
        Self::Groups,
        Self::Email,
        Self::EmailVerified,
        Self::AuthMethod,
        Self::AuthClass,
    ];

    const IDENTITY_CLAIMS: [Self; 12] = [
        Self::Subject,
        Self::UserId,
        Self::TenantId,
        Self::OrgId,
        Self::WorkspaceId,
        Self::Roles,
        Self::Scopes,
        Self::Groups,
        Self::Email,
        Self::EmailVerified,
        Self::AuthMethod,
        Self::AuthClass,
    ];

    fn wire_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Algorithm => "algorithm",
            Self::KeyReference => "key_reference",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expiration => "expiration",
            Self::SignatureVerification => "signature_verification",
            Self::ExpiryEnforcement => "expiry_enforcement",
            Self::Subject => "subject",
            Self::UserId => "user_id",
            Self::TenantId => "tenant_id",
            Self::OrgId => "org_id",
            Self::WorkspaceId => "workspace_id",
            Self::Roles => "roles",
            Self::Scopes => "scopes",
            Self::Groups => "groups",
            Self::Email => "email",
            Self::EmailVerified => "email_verified",
            Self::AuthMethod => "auth_method",
            Self::AuthClass => "auth_class",
            Self::OptionAlgorithms => "algorithms",
            Self::OptionAudience => "audience",
            Self::OptionIssuer => "issuer",
            Self::OptionSubject => "subject",
            Self::OptionNonce => "nonce",
            Self::OptionClockTolerance => "clock_tolerance",
            Self::OptionClockTimestamp => "clock_timestamp",
            Self::OptionComplete => "complete",
            Self::OptionIgnoreNotBefore => "ignore_not_before",
            Self::OptionIgnoreExpiration => "ignore_expiration",
            Self::HeaderJku => "jku",
            Self::HeaderX5u => "x5u",
            Self::HeaderJwk => "jwk",
            Self::HeaderKid => "kid",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Algorithm => "algorithm",
            Self::KeyReference => "key reference",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expiration => "expiration",
            Self::SignatureVerification => "signature verification",
            Self::ExpiryEnforcement => "expiry enforcement",
            Self::Subject => "subject claim",
            Self::UserId => "user ID claim",
            Self::TenantId => "tenant ID claim",
            Self::OrgId => "organization ID claim",
            Self::WorkspaceId => "workspace ID claim",
            Self::Roles => "roles claim",
            Self::Scopes => "scopes claim",
            Self::Groups => "groups claim",
            Self::Email => "email claim",
            Self::EmailVerified => "email verified claim",
            Self::AuthMethod => "auth method claim",
            Self::AuthClass => "auth class claim",
            Self::OptionAlgorithms => "JWT algorithms option",
            Self::OptionAudience => "JWT audience option",
            Self::OptionIssuer => "JWT issuer option",
            Self::OptionSubject => "JWT subject option",
            Self::OptionNonce => "JWT nonce option",
            Self::OptionClockTolerance => "JWT clock tolerance option",
            Self::OptionClockTimestamp => "JWT clock timestamp option",
            Self::OptionComplete => "JWT complete option",
            Self::OptionIgnoreNotBefore => "JWT ignore-not-before option",
            Self::OptionIgnoreExpiration => "JWT ignore-expiration option",
            Self::HeaderJku => "JWT jku header",
            Self::HeaderX5u => "JWT x5u header",
            Self::HeaderJwk => "JWT embedded JWK header",
            Self::HeaderKid => "JWT kid header",
        }
    }

    fn is_option(self) -> bool {
        matches!(
            self,
            Self::OptionAlgorithms
                | Self::OptionAudience
                | Self::OptionIssuer
                | Self::OptionSubject
                | Self::OptionNonce
                | Self::OptionClockTolerance
                | Self::OptionClockTimestamp
                | Self::OptionComplete
                | Self::OptionIgnoreNotBefore
                | Self::OptionIgnoreExpiration
        )
    }

    fn is_header(self) -> bool {
        matches!(
            self,
            Self::HeaderJku | Self::HeaderX5u | Self::HeaderJwk | Self::HeaderKid
        )
    }

    fn lifecycle_stage(self, operation: JwtOperation) -> LifecycleStage {
        match self {
            Self::Expiration => LifecycleStage::Expire,
            Self::OptionAlgorithms
            | Self::OptionAudience
            | Self::OptionIssuer
            | Self::OptionSubject
            | Self::OptionNonce
            | Self::OptionClockTolerance
            | Self::OptionClockTimestamp
            | Self::OptionComplete
            | Self::OptionIgnoreNotBefore
            | Self::OptionIgnoreExpiration
            | Self::HeaderJku
            | Self::HeaderX5u
            | Self::HeaderJwk
            | Self::HeaderKid => LifecycleStage::Validate,
            Self::ExpiryEnforcement | Self::SignatureVerification => LifecycleStage::Validate,
            _ => operation.lifecycle_stage(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtFieldEvidence {
    state: JwtAttributeState,
    value: Option<String>,
    confidence: Confidence,
    line: usize,
    column: usize,
    excerpt: SanitizedExcerpt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtCall {
    operation: JwtOperation,
    api_name: &'static str,
    framework_hint: &'static str,
    line: usize,
    column: usize,
    excerpt: SanitizedExcerpt,
    display_name: Option<String>,
    artifact_type: ArtifactType,
    fields: BTreeMap<JwtField, JwtFieldEvidence>,
}

#[derive(Debug, Clone, Default)]
struct JsImports {
    jsonwebtoken_namespaces: BTreeSet<String>,
    jsonwebtoken_functions: BTreeMap<String, &'static str>,
    jose_functions: BTreeMap<String, &'static str>,
}

#[derive(Debug, Clone, Default)]
struct PyImports {
    jwt_modules: BTreeSet<String>,
    jwt_functions: BTreeMap<String, &'static str>,
}

#[derive(Debug, Clone, Default)]
struct FieldSet {
    fields: BTreeMap<JwtField, JwtFieldEvidence>,
    dynamic: bool,
}

#[derive(Debug, Clone, Copy)]
struct JwtSourceContext<'a> {
    source: &'a str,
    scope_source: &'a str,
}

#[derive(Debug, Clone)]
struct ScopedFieldSet {
    fields: BTreeMap<JwtField, JwtFieldEvidence>,
    dynamic: bool,
    declaration_end_byte: usize,
    scope_start_byte: usize,
    scope_end_byte: usize,
}

type AliasMap = BTreeMap<String, Vec<ScopedFieldSet>>;

fn detect_javascript_like(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_javascript_like(input, input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let imports = collect_js_imports(input.source);
    let option_aliases = collect_js_option_aliases(root, input.source);
    let mut calls = Vec::new();
    collect_js_calls(
        root,
        input.source,
        &imports,
        &option_aliases,
        None,
        &mut calls,
    );

    calls_to_output(input, detector_id, calls)
}

fn detect_python(input: &DetectorInput<'_>, detector_id: &str) -> DetectionOutput {
    let Some(tree) = parse_python(input.source) else {
        return DetectionOutput::default();
    };

    let root = tree.root_node();
    let imports = collect_python_imports(input.source);
    let option_aliases = collect_python_option_aliases(root, input.source);
    let mut calls = Vec::new();
    collect_python_calls(
        root,
        input.source,
        &imports,
        &option_aliases,
        None,
        &mut calls,
    );

    calls_to_output(input, detector_id, calls)
}

fn calls_to_output(
    input: &DetectorInput<'_>,
    detector_id: &str,
    calls: Vec<JwtCall>,
) -> DetectionOutput {
    let mut groups: BTreeMap<String, Vec<JwtCall>> = BTreeMap::new();
    for call in calls {
        let key = format!(
            "{}:{}:{}",
            artifact_type_part(call.artifact_type),
            call.display_name.as_deref().unwrap_or("dynamic"),
            if call.display_name.is_none() {
                call.line
            } else {
                0
            }
        );
        groups.entry(key).or_default().push(call);
    }

    let mut output = DetectionOutput::default();

    for (_, calls) in groups {
        let first = calls.first().expect("group should contain a call");
        let display_name = first.display_name.clone();
        let artifact_type = first.artifact_type;
        let confidence = if display_name.is_some() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        let name_part = display_name.as_deref().unwrap_or("dynamic");
        let id_parts = [
            detector_id,
            artifact_type_part(artifact_type),
            input.path,
            name_part,
        ];
        let artifact_id = stable_artifact_id(&id_parts);
        let mut lifecycle_evidence = LifecycleEvidence::default();
        let mut locations = Vec::new();
        let mut framework_hints = BTreeSet::new();
        let mut field_observations: BTreeMap<JwtField, Vec<JwtFieldEvidence>> = BTreeMap::new();
        let mut field_evidence_ids: BTreeMap<JwtField, Vec<sessionscope_model::EvidenceId>> =
            BTreeMap::new();
        let mut operation_evidence_ids = Vec::new();

        for call in &calls {
            let location = SourceLocation {
                path: input.path.to_string(),
                line: Some(call.line),
                column: Some(call.column),
            };
            locations.push(location.clone());
            framework_hints.insert(call.framework_hint.to_string());

            let line_part = call.line.to_string();
            let column_part = call.column.to_string();
            let evidence_id = stable_evidence_id(&[
                detector_id,
                call.operation.value(),
                input.path,
                &line_part,
                &column_part,
                call.api_name,
                name_part,
            ]);
            push_lifecycle_id(
                &mut lifecycle_evidence,
                call.operation.lifecycle_stage(),
                evidence_id.clone(),
            );
            operation_evidence_ids.push(evidence_id.clone());
            output.evidence.push(Evidence {
                id: evidence_id,
                lifecycle_stage: call.operation.lifecycle_stage(),
                location,
                detector_id: format!("jwt.{}", call.operation.value()),
                confidence,
                excerpt: Some(call.excerpt.clone()),
                dynamic: false,
                framework_default: false,
            });

            let operation_field = JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some(call.operation.value().to_string()),
                confidence,
                line: call.line,
                column: call.column,
                excerpt: call.excerpt.clone(),
            };
            field_observations
                .entry(JwtField::Operation)
                .or_default()
                .push(operation_field);

            for (field, observation) in &call.fields {
                let line_part = observation.line.to_string();
                let column_part = observation.column.to_string();
                let state_part = jwt_state_part(observation.state);
                let evidence_kind = if field.is_option() {
                    "jwt_option"
                } else if field.is_header() {
                    "jwt_header"
                } else {
                    "jwt_attribute"
                };
                let evidence_id = stable_evidence_id(&[
                    detector_id,
                    evidence_kind,
                    field.wire_name(),
                    state_part,
                    input.path,
                    &line_part,
                    &column_part,
                    call.api_name,
                    name_part,
                ]);
                push_lifecycle_id(
                    &mut lifecycle_evidence,
                    field.lifecycle_stage(call.operation),
                    evidence_id.clone(),
                );
                output.evidence.push(Evidence {
                    id: evidence_id.clone(),
                    lifecycle_stage: field.lifecycle_stage(call.operation),
                    location: SourceLocation {
                        path: input.path.to_string(),
                        line: Some(observation.line),
                        column: Some(observation.column),
                    },
                    detector_id: if field.is_option() {
                        format!("jwt.option.{}", field.wire_name())
                    } else if field.is_header() {
                        format!("jwt.header.{}", field.wire_name())
                    } else {
                        format!("jwt.attribute.{}", field.wire_name())
                    },
                    confidence: observation.confidence,
                    excerpt: Some(observation.excerpt.clone()),
                    dynamic: observation.state == JwtAttributeState::Dynamic,
                    framework_default: observation.state == JwtAttributeState::FrameworkDefault,
                });
                field_evidence_ids
                    .entry(*field)
                    .or_default()
                    .push(evidence_id);
                field_observations
                    .entry(*field)
                    .or_default()
                    .push(JwtFieldEvidence {
                        state: observation.state,
                        value: observation.value.clone(),
                        confidence: observation.confidence,
                        line: observation.line,
                        column: observation.column,
                        excerpt: observation.excerpt.clone(),
                    });
            }
        }

        locations.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.column.cmp(&right.column))
        });
        locations.dedup();

        let mut jwt_attributes = aggregate_jwt_attributes(field_observations);
        jwt_attributes.operation.evidence_ids = operation_evidence_ids;
        apply_field_evidence_ids(&mut jwt_attributes, field_evidence_ids);

        output.artifacts.push(Artifact {
            id: artifact_id,
            artifact_type,
            display_name,
            locations,
            lifecycle_evidence,
            confidence,
            framework_hints: framework_hints.into_iter().collect(),
            cookie_attributes: None,
            token_boundary_attributes: Some(boundary_attributes_from_jwt(&jwt_attributes)),
            jwt_attributes: Some(jwt_attributes),
        });
    }

    output
}

fn apply_field_evidence_ids(
    attributes: &mut JwtAttributes,
    mut evidence_ids: BTreeMap<JwtField, Vec<sessionscope_model::EvidenceId>>,
) {
    attributes.algorithm.evidence_ids = evidence_ids
        .remove(&JwtField::Algorithm)
        .unwrap_or_default();
    attributes.key_reference.evidence_ids = evidence_ids
        .remove(&JwtField::KeyReference)
        .unwrap_or_default();
    attributes.issuer.evidence_ids = evidence_ids.remove(&JwtField::Issuer).unwrap_or_default();
    attributes.audience.evidence_ids = evidence_ids.remove(&JwtField::Audience).unwrap_or_default();
    attributes.expiration.evidence_ids = evidence_ids
        .remove(&JwtField::Expiration)
        .unwrap_or_default();
    attributes.signature_verification.evidence_ids = evidence_ids
        .remove(&JwtField::SignatureVerification)
        .unwrap_or_default();
    attributes.expiry_enforcement.evidence_ids = evidence_ids
        .remove(&JwtField::ExpiryEnforcement)
        .unwrap_or_default();
    if let Some(identity_claims) = &mut attributes.identity_claims {
        identity_claims.subject.evidence_ids =
            evidence_ids.remove(&JwtField::Subject).unwrap_or_default();
        identity_claims.user_id.evidence_ids =
            evidence_ids.remove(&JwtField::UserId).unwrap_or_default();
        identity_claims.tenant_id.evidence_ids =
            evidence_ids.remove(&JwtField::TenantId).unwrap_or_default();
        identity_claims.org_id.evidence_ids =
            evidence_ids.remove(&JwtField::OrgId).unwrap_or_default();
        identity_claims.workspace_id.evidence_ids = evidence_ids
            .remove(&JwtField::WorkspaceId)
            .unwrap_or_default();
        identity_claims.roles.evidence_ids =
            evidence_ids.remove(&JwtField::Roles).unwrap_or_default();
        identity_claims.scopes.evidence_ids =
            evidence_ids.remove(&JwtField::Scopes).unwrap_or_default();
        identity_claims.groups.evidence_ids =
            evidence_ids.remove(&JwtField::Groups).unwrap_or_default();
        identity_claims.email.evidence_ids =
            evidence_ids.remove(&JwtField::Email).unwrap_or_default();
        identity_claims.email_verified.evidence_ids = evidence_ids
            .remove(&JwtField::EmailVerified)
            .unwrap_or_default();
        identity_claims.auth_method.evidence_ids = evidence_ids
            .remove(&JwtField::AuthMethod)
            .unwrap_or_default();
        identity_claims.auth_class.evidence_ids = evidence_ids
            .remove(&JwtField::AuthClass)
            .unwrap_or_default();
    }
}

fn boundary_attributes_from_jwt(attributes: &JwtAttributes) -> TokenBoundaryAttributes {
    let identity_claims = attributes.identity_claims.as_ref();
    let unknown = TokenBoundaryObservation {
        state: TokenBoundaryAttributeState::Unknown,
        value: None,
        evidence_ids: Vec::new(),
        confidence: Confidence::Low,
    };
    TokenBoundaryAttributes {
        issuer: boundary_observation_from_jwt(&attributes.issuer),
        audience: boundary_observation_from_jwt(&attributes.audience),
        service: identity_claims
            .map(|claims| boundary_observation_from_jwt(&claims.workspace_id))
            .unwrap_or_else(|| unknown.clone()),
        environment: unknown.clone(),
        tenant: identity_claims
            .map(|claims| {
                merge_boundary_observations(
                    boundary_observation_from_jwt(&claims.tenant_id),
                    boundary_observation_from_jwt(&claims.org_id),
                )
            })
            .unwrap_or_else(|| unknown.clone()),
        provider: provider_observation_from_issuer(&attributes.issuer),
        scope: identity_claims
            .map(|claims| boundary_observation_from_jwt(&claims.scopes))
            .unwrap_or_else(|| unknown.clone()),
        trust_boundary: if attributes.audience.state == JwtAttributeState::Present {
            boundary_observation_from_jwt(&attributes.audience)
        } else {
            unknown
        },
    }
}

fn boundary_observation_from_jwt(
    observation: &JwtAttributeObservation,
) -> TokenBoundaryObservation {
    TokenBoundaryObservation {
        state: match observation.state {
            JwtAttributeState::Present => TokenBoundaryAttributeState::Present,
            JwtAttributeState::Missing => TokenBoundaryAttributeState::Missing,
            JwtAttributeState::Dynamic => TokenBoundaryAttributeState::Dynamic,
            JwtAttributeState::FrameworkDefault => TokenBoundaryAttributeState::FrameworkDefault,
            JwtAttributeState::Unknown => TokenBoundaryAttributeState::Unknown,
        },
        value: observation.value.clone(),
        evidence_ids: observation.evidence_ids.clone(),
        confidence: observation.confidence,
    }
}

fn provider_observation_from_issuer(
    observation: &JwtAttributeObservation,
) -> TokenBoundaryObservation {
    let mut provider = boundary_observation_from_jwt(observation);
    if provider.state == TokenBoundaryAttributeState::Present {
        let normalized = provider.value.as_deref().unwrap_or("").to_ascii_lowercase();
        provider.value = if normalized.contains("auth0") {
            Some("auth0".to_string())
        } else if normalized.contains("okta") {
            Some("okta".to_string())
        } else if normalized.contains("oauth") {
            Some("oauth".to_string())
        } else {
            None
        };
        if provider.value.is_none() {
            provider.state = TokenBoundaryAttributeState::Unknown;
            provider.evidence_ids.clear();
            provider.confidence = Confidence::Low;
        }
    }
    provider
}

fn merge_boundary_observations(
    left: TokenBoundaryObservation,
    right: TokenBoundaryObservation,
) -> TokenBoundaryObservation {
    if left.state == TokenBoundaryAttributeState::Present {
        left
    } else {
        right
    }
}

fn aggregate_jwt_attributes(
    observations: BTreeMap<JwtField, Vec<JwtFieldEvidence>>,
) -> JwtAttributes {
    let mut fields = BTreeMap::new();
    for field in JwtField::ALL {
        fields.insert(field, aggregate_field(field, observations.get(&field)));
    }
    let has_identity_claims = JwtField::IDENTITY_CLAIMS
        .iter()
        .any(|field| observations.contains_key(field));
    let identity_claims = has_identity_claims.then(|| JwtIdentityClaims {
        subject: fields.remove(&JwtField::Subject).expect("subject exists"),
        user_id: fields.remove(&JwtField::UserId).expect("user ID exists"),
        tenant_id: fields
            .remove(&JwtField::TenantId)
            .expect("tenant ID exists"),
        org_id: fields.remove(&JwtField::OrgId).expect("org ID exists"),
        workspace_id: fields
            .remove(&JwtField::WorkspaceId)
            .expect("workspace ID exists"),
        roles: fields.remove(&JwtField::Roles).expect("roles exists"),
        scopes: fields.remove(&JwtField::Scopes).expect("scopes exists"),
        groups: fields.remove(&JwtField::Groups).expect("groups exists"),
        email: fields.remove(&JwtField::Email).expect("email exists"),
        email_verified: fields
            .remove(&JwtField::EmailVerified)
            .expect("email verified exists"),
        auth_method: fields
            .remove(&JwtField::AuthMethod)
            .expect("auth method exists"),
        auth_class: fields
            .remove(&JwtField::AuthClass)
            .expect("auth class exists"),
    });

    JwtAttributes {
        operation: fields
            .remove(&JwtField::Operation)
            .expect("operation exists"),
        algorithm: fields
            .remove(&JwtField::Algorithm)
            .expect("algorithm exists"),
        key_reference: fields
            .remove(&JwtField::KeyReference)
            .expect("key reference exists"),
        issuer: fields.remove(&JwtField::Issuer).expect("issuer exists"),
        audience: fields.remove(&JwtField::Audience).expect("audience exists"),
        expiration: fields
            .remove(&JwtField::Expiration)
            .expect("expiration exists"),
        signature_verification: fields
            .remove(&JwtField::SignatureVerification)
            .expect("signature verification exists"),
        expiry_enforcement: fields
            .remove(&JwtField::ExpiryEnforcement)
            .expect("expiry enforcement exists"),
        identity_claims,
    }
}

fn aggregate_field(
    field: JwtField,
    observations: Option<&Vec<JwtFieldEvidence>>,
) -> JwtAttributeObservation {
    let Some(observations) = observations else {
        return JwtAttributeObservation {
            state: JwtAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        };
    };

    let state = if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Missing)
    {
        JwtAttributeState::Missing
    } else if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Dynamic)
    {
        JwtAttributeState::Dynamic
    } else if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::FrameworkDefault)
    {
        JwtAttributeState::FrameworkDefault
    } else if observations
        .iter()
        .any(|observation| observation.state == JwtAttributeState::Present)
    {
        JwtAttributeState::Present
    } else {
        JwtAttributeState::Unknown
    };
    let confidence = observations
        .iter()
        .map(|observation| observation.confidence)
        .max()
        .unwrap_or(Confidence::Low);
    let mut values = observations
        .iter()
        .filter_map(|observation| observation.value.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if values.len() > 3 {
        values.truncate(3);
        values.push("...".to_string());
    }

    JwtAttributeObservation {
        state,
        value: if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        },
        evidence_ids: Vec::new(),
        confidence: if field == JwtField::Operation {
            Confidence::High
        } else {
            confidence
        },
    }
}

fn parse_javascript_like(input: &DetectorInput<'_>, source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = match input.language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if input.path.ends_with(".tsx") => {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => return None,
    };
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

fn parse_python(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

fn collect_js_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &JsImports,
    option_aliases: &AliasMap,
    function_name: Option<&str>,
    calls: &mut Vec<JwtCall>,
) {
    let local_function_name = js_function_name(node, source);
    let active_function_name = local_function_name.as_deref().or(function_name);

    if node.kind() == "call_expression"
        && let Some(call) = js_jwt_call(node, source, imports, option_aliases, active_function_name)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_js_calls(
            child,
            source,
            imports,
            option_aliases,
            active_function_name,
            calls,
        );
    }
}

fn js_jwt_call<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &JsImports,
    option_aliases: &AliasMap,
    function_name: Option<&str>,
) -> Option<JwtCall> {
    let function = node.child_by_field_name("function")?;
    let call_text = node_text(node, source);

    if is_jose_sign_chain(&call_text, imports) {
        return Some(js_jose_sign_call(node, source, function_name));
    }

    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let mut api_name = None;
    let mut framework_hint = None;
    let mut operation = None;

    if is_member_expression(function) {
        let property = function.child_by_field_name("property")?;
        let property_name = node_text(property, source);
        let object_name = function
            .child_by_field_name("object")
            .map(|object| node_text(object, source))
            .unwrap_or_default();
        if imports.jsonwebtoken_namespaces.contains(&object_name)
            && matches!(property_name.as_str(), "sign" | "verify" | "decode")
        {
            api_name = Some(match property_name.as_str() {
                "sign" => "jsonwebtoken.sign",
                "verify" => "jsonwebtoken.verify",
                "decode" => "jsonwebtoken.decode",
                _ => unreachable!(),
            });
            framework_hint = Some("jsonwebtoken");
            operation = Some(match property_name.as_str() {
                "sign" => JwtOperation::Issue,
                "verify" => JwtOperation::Validate,
                "decode" => JwtOperation::DecodeWithoutVerify,
                _ => unreachable!(),
            });
        }
    } else if function.kind() == "identifier" {
        let local_name = node_text(function, source);
        if let Some(original) = imports.jsonwebtoken_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "sign" => "jsonwebtoken.sign",
                "verify" => "jsonwebtoken.verify",
                "decode" => "jsonwebtoken.decode",
                _ => return None,
            });
            framework_hint = Some("jsonwebtoken");
            operation = Some(match *original {
                "sign" => JwtOperation::Issue,
                "verify" => JwtOperation::Validate,
                "decode" => JwtOperation::DecodeWithoutVerify,
                _ => return None,
            });
        } else if let Some(original) = imports.jose_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "jwtVerify" => "jose.jwtVerify",
                "decodeJwt" => "jose.decodeJwt",
                _ => return None,
            });
            framework_hint = Some("jose");
            operation = Some(match *original {
                "jwtVerify" => JwtOperation::Validate,
                "decodeJwt" => JwtOperation::DecodeWithoutVerify,
                _ => return None,
            });
        }
    }

    let api_name = api_name?;
    let framework_hint = framework_hint?;
    let operation = operation?;
    let (line, column) = node_line_column(node);
    let mut fields = BTreeMap::new();

    match api_name {
        "jsonwebtoken.sign" => add_js_sign_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
        ),
        "jsonwebtoken.verify" | "jose.jwtVerify" => add_js_verify_fields(
            &mut fields,
            JwtSourceContext {
                source,
                scope_source: &scope_text(node, source),
            },
            &argument_nodes,
            option_aliases,
            line,
            column,
            api_name == "jose.jwtVerify",
        ),
        "jsonwebtoken.decode" | "jose.decodeJwt" => {
            add_decode_without_verify_fields(&mut fields, line, column, api_name);
        }
        _ => {}
    }

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    Some(JwtCall {
        operation,
        api_name,
        framework_hint,
        line,
        column,
        excerpt: jwt_call_excerpt(api_name, operation),
        display_name,
        artifact_type,
        fields,
    })
}

fn js_jose_sign_call<'tree>(
    node: Node<'tree>,
    source: &str,
    function_name: Option<&str>,
) -> JwtCall {
    let (line, column) = node_line_column(node);
    let text = node_text(node, source);
    let mut fields = BTreeMap::new();

    add_regex_chain_field(
        &mut fields,
        JwtField::Algorithm,
        &text,
        r#"\.setProtectedHeader\s*\(\s*\{[^}]*\balg\s*:\s*([^,}]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Issuer,
        &text,
        r#"\.setIssuer\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Audience,
        &text,
        r#"\.setAudience\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::Expiration,
        &text,
        r#"\.setExpirationTime\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_regex_chain_field(
        &mut fields,
        JwtField::KeyReference,
        &text,
        r#"\.sign\s*\(\s*([^)]+)"#,
        line,
        column,
    );
    add_identity_claim_fields_from_text(&mut fields, &text, line, column);
    add_missing_for_issue_fields(&mut fields, line, column);

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    JwtCall {
        operation: JwtOperation::Issue,
        api_name: "jose.SignJWT.sign",
        framework_hint: "jose",
        line,
        column,
        excerpt: jwt_call_excerpt("jose.SignJWT.sign", JwtOperation::Issue),
        display_name,
        artifact_type,
        fields,
    }
}

fn add_js_sign_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    if let Some(payload) = argument_nodes.first().copied() {
        add_object_field(
            fields,
            JwtField::Issuer,
            payload,
            source,
            &["iss"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Audience,
            payload,
            source,
            &["aud"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Expiration,
            payload,
            source,
            &["exp"],
            line,
            column,
        );
        add_identity_claim_fields(fields, payload, source, option_aliases);
    }
    if let Some(options) = argument_nodes.get(2).copied() {
        add_js_options_fields(
            fields,
            source,
            options,
            option_aliases,
            &[
                (JwtField::Algorithm, &["algorithm", "algorithms"][..]),
                (JwtField::Issuer, &["issuer"][..]),
                (JwtField::Audience, &["audience"][..]),
                (JwtField::Expiration, &["expiresIn", "expires"][..]),
            ],
            line,
            column,
        );
    }
    add_missing_for_issue_fields(fields, line, column);
}

fn add_js_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    context: JwtSourceContext<'_>,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
    line: usize,
    column: usize,
    jose: bool,
) {
    let source = context.source;
    add_key_reference(fields, source, argument_nodes.get(1).copied(), line, column);
    add_present_value(
        fields,
        JwtField::SignatureVerification,
        "verified",
        line,
        column,
        format!(
            "{api_name} verifies JWT signatures",
            api_name = if jose {
                "jose.jwtVerify"
            } else {
                "jsonwebtoken.verify"
            }
        ),
    );
    if let Some(options) = argument_nodes.get(2).copied() {
        add_js_options_fields(
            fields,
            source,
            options,
            option_aliases,
            &[
                (JwtField::Algorithm, &["algorithms", "algorithm"][..]),
                (JwtField::Issuer, &["issuer"][..]),
                (JwtField::Audience, &["audience"][..]),
                (
                    JwtField::ExpiryEnforcement,
                    if jose {
                        &["maxTokenAge"][..]
                    } else {
                        &["maxAge"][..]
                    },
                ),
            ],
            line,
            column,
        );
        add_js_options_fields(
            fields,
            source,
            options,
            option_aliases,
            js_verify_option_fields(jose),
            line,
            column,
        );
        add_js_expiry_enforcement(fields, source, options, option_aliases, line, column, jose);
    } else {
        add_framework_default(
            fields,
            JwtField::ExpiryEnforcement,
            if jose {
                "jose.jwtVerify default"
            } else {
                "jsonwebtoken.verify default"
            },
            line,
            column,
            if jose {
                "jose.jwtVerify enforces exp by library default"
            } else {
                "jsonwebtoken.verify enforces exp by library default"
            },
        );
    }
    if jose && argument_nodes.get(2).is_none() {
        add_missing(fields, JwtField::Issuer, line, column);
        add_missing(fields, JwtField::Audience, line, column);
    } else {
        add_missing_for_verify_fields(fields, line, column);
    }
    add_header_trust_fields(fields, context.scope_source, line, column);
}

fn add_header_trust_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    line: usize,
    column: usize,
) {
    for (field, header_name) in [
        (JwtField::HeaderJku, "jku"),
        (JwtField::HeaderX5u, "x5u"),
        (JwtField::HeaderJwk, "jwk"),
        (JwtField::HeaderKid, "kid"),
    ] {
        if header_name_is_read(source, header_name) {
            add_present_value(
                fields,
                field,
                header_name,
                line,
                column,
                format!("JWT header `{header_name}` is read near verification logic"),
            );
        }
    }
}

fn header_name_is_read(source: &str, header_name: &str) -> bool {
    let dot = format!(".{header_name}");
    let single = format!("['{header_name}']");
    let double = format!("[\"{header_name}\"]");
    source.contains(&dot) || source.contains(&single) || source.contains(&double)
}

fn js_verify_option_fields(jose: bool) -> &'static [(JwtField, &'static [&'static str])] {
    if jose {
        &[
            (JwtField::OptionAlgorithms, &["algorithms", "algorithm"]),
            (JwtField::OptionIssuer, &["issuer"]),
            (JwtField::OptionAudience, &["audience"]),
            (JwtField::OptionSubject, &["subject"]),
            (JwtField::OptionNonce, &["nonce"]),
            (JwtField::OptionClockTolerance, &["clockTolerance"]),
            (
                JwtField::OptionClockTimestamp,
                &["currentDate", "clockTimestamp"],
            ),
            (JwtField::OptionComplete, &["complete"]),
            (JwtField::OptionIgnoreNotBefore, &["ignoreNotBefore"]),
        ]
    } else {
        &[
            (JwtField::OptionAlgorithms, &["algorithms", "algorithm"]),
            (JwtField::OptionIssuer, &["issuer"]),
            (JwtField::OptionAudience, &["audience"]),
            (JwtField::OptionSubject, &["subject"]),
            (JwtField::OptionNonce, &["nonce"]),
            (JwtField::OptionClockTolerance, &["clockTolerance"]),
            (JwtField::OptionClockTimestamp, &["clockTimestamp"]),
            (JwtField::OptionComplete, &["complete"]),
            (JwtField::OptionIgnoreNotBefore, &["ignoreNotBefore"]),
            (JwtField::OptionIgnoreExpiration, &["ignoreExpiration"]),
        ]
    }
}

fn add_decode_without_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    line: usize,
    column: usize,
    api_name: &str,
) {
    add_missing_value(
        fields,
        JwtField::SignatureVerification,
        "decode_without_verify",
        line,
        column,
        format!("{api_name} decodes JWTs without signature verification"),
    );
    add_missing_value(
        fields,
        JwtField::ExpiryEnforcement,
        "decode_without_verify",
        line,
        column,
        format!("{api_name} does not enforce JWT expiration"),
    );
}

fn add_js_expiry_enforcement(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    options: Node<'_>,
    aliases: &AliasMap,
    line: usize,
    column: usize,
    jose: bool,
) {
    if is_object_literal(options) {
        if object_property_value(options, source, "ignoreExpiration")
            .is_some_and(|value| is_true_literal(value, source))
        {
            add_missing_value(
                fields,
                JwtField::ExpiryEnforcement,
                "ignoreExpiration: true",
                line,
                column,
                "JWT expiry enforcement is disabled with ignoreExpiration: true",
            );
            return;
        }
        let max_age_name = if jose { "maxTokenAge" } else { "maxAge" };
        if let Some(max_age) = object_property_value(options, source, max_age_name) {
            add_present_node(fields, JwtField::ExpiryEnforcement, max_age, source);
            return;
        }
        if object_has_dynamic_spread(options, source) {
            fields
                .entry(JwtField::ExpiryEnforcement)
                .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
            return;
        }
    } else if options.kind() == "identifier" {
        let alias_name = node_text(options, source);
        if let Some(alias) = lookup_alias(aliases, &alias_name, options) {
            if let Some(observation) = alias.fields.get(&JwtField::ExpiryEnforcement) {
                fields
                    .entry(JwtField::ExpiryEnforcement)
                    .or_insert_with(|| observation.clone());
                return;
            }
            if alias.dynamic {
                fields
                    .entry(JwtField::ExpiryEnforcement)
                    .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
                return;
            }
        } else {
            fields
                .entry(JwtField::ExpiryEnforcement)
                .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
            return;
        }
    } else {
        fields
            .entry(JwtField::ExpiryEnforcement)
            .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
        return;
    }

    add_framework_default(
        fields,
        JwtField::ExpiryEnforcement,
        if jose {
            "jose.jwtVerify default"
        } else {
            "jsonwebtoken.verify default"
        },
        line,
        column,
        if jose {
            "jose.jwtVerify enforces exp by library default"
        } else {
            "jsonwebtoken.verify enforces exp by library default"
        },
    );
}

fn add_js_options_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Node<'_>,
    aliases: &AliasMap,
    wanted: &[(JwtField, &[&str])],
    line: usize,
    column: usize,
) {
    if is_object_literal(node) {
        for (field, names) in wanted {
            add_object_field(fields, *field, node, source, names, line, column);
        }
        if object_has_dynamic_spread(node, source) {
            for (field, _) in wanted {
                fields
                    .entry(*field)
                    .or_insert_with(|| dynamic_field(*field, line, column));
            }
        }
    } else if node.kind() == "identifier" {
        let alias_name = node_text(node, source);
        if let Some(alias) = lookup_alias(aliases, &alias_name, node) {
            for (field, _) in wanted {
                if let Some(value) = alias.fields.get(field) {
                    fields.entry(*field).or_insert_with(|| value.clone());
                } else if alias.dynamic {
                    fields
                        .entry(*field)
                        .or_insert_with(|| dynamic_field(*field, line, column));
                }
            }
        } else {
            for (field, _) in wanted {
                fields
                    .entry(*field)
                    .or_insert_with(|| dynamic_field(*field, line, column));
            }
        }
    } else {
        for (field, _) in wanted {
            fields
                .entry(*field)
                .or_insert_with(|| dynamic_field(*field, line, column));
        }
    }
}

fn collect_python_calls<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &PyImports,
    option_aliases: &AliasMap,
    function_name: Option<&str>,
    calls: &mut Vec<JwtCall>,
) {
    let local_function_name = python_function_name(node, source);
    let active_function_name = local_function_name.as_deref().or(function_name);

    if node.kind() == "call"
        && let Some(call) =
            python_jwt_call(node, source, imports, option_aliases, active_function_name)
    {
        calls.push(call);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_python_calls(
            child,
            source,
            imports,
            option_aliases,
            active_function_name,
            calls,
        );
    }
}

fn python_jwt_call<'tree>(
    node: Node<'tree>,
    source: &str,
    imports: &PyImports,
    option_aliases: &AliasMap,
    function_name: Option<&str>,
) -> Option<JwtCall> {
    let function = node.child_by_field_name("function")?;
    let mut api_name = None;
    let mut operation_name = None;

    if function.kind() == "attribute" {
        let attribute = function.child_by_field_name("attribute")?;
        let attribute_name = node_text(attribute, source);
        let object_name = function
            .child_by_field_name("object")
            .map(|object| node_text(object, source))
            .unwrap_or_default();
        if imports.jwt_modules.contains(&object_name)
            && matches!(attribute_name.as_str(), "encode" | "decode")
        {
            api_name = Some(match attribute_name.as_str() {
                "encode" => "pyjwt.encode",
                "decode" => "pyjwt.decode",
                _ => unreachable!(),
            });
            operation_name = Some(attribute_name);
        }
    } else if function.kind() == "identifier" {
        let local_name = node_text(function, source);
        if let Some(original) = imports.jwt_functions.get(local_name.as_str()) {
            api_name = Some(match *original {
                "encode" => "pyjwt.encode",
                "decode" => "pyjwt.decode",
                _ => return None,
            });
            operation_name = Some((*original).to_string());
        }
    }

    let api_name = api_name?;
    let operation_name = operation_name?;
    let arguments = node.child_by_field_name("arguments")?;
    let argument_nodes = named_children(arguments);
    let (line, column) = node_line_column(node);
    let mut fields = BTreeMap::new();

    let operation = if operation_name == "encode" {
        add_python_encode_fields(
            &mut fields,
            source,
            &argument_nodes,
            option_aliases,
            line,
            column,
        );
        JwtOperation::Issue
    } else if python_decode_disables_verification(source, &argument_nodes, option_aliases) {
        add_python_decode_without_verify_fields(
            &mut fields,
            source,
            &scope_text(node, source),
            &argument_nodes,
            option_aliases,
            line,
            column,
        );
        JwtOperation::DecodeWithoutVerify
    } else {
        add_python_decode_fields(
            &mut fields,
            source,
            &scope_text(node, source),
            &argument_nodes,
            option_aliases,
            line,
            column,
        );
        JwtOperation::Validate
    };

    let display_name = infer_jwt_display_name(function_name, node, source);
    let artifact_type = artifact_type_for_name(display_name.as_deref());
    Some(JwtCall {
        operation,
        api_name,
        framework_hint: "pyjwt",
        line,
        column,
        excerpt: jwt_call_excerpt(api_name, operation),
        display_name,
        artifact_type,
        fields,
    })
}

fn add_python_encode_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    let positional_arguments = positional_argument_nodes(argument_nodes);
    let key = positional_arguments
        .get(1)
        .copied()
        .or_else(|| python_keyword_value(argument_nodes, source, "key"));
    add_key_reference(fields, source, key, line, column);
    if let Some(payload) = positional_arguments
        .first()
        .copied()
        .or_else(|| python_keyword_value(argument_nodes, source, "payload"))
    {
        add_object_field(
            fields,
            JwtField::Issuer,
            payload,
            source,
            &["iss"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Audience,
            payload,
            source,
            &["aud"],
            line,
            column,
        );
        add_object_field(
            fields,
            JwtField::Expiration,
            payload,
            source,
            &["exp"],
            line,
            column,
        );
        add_identity_claim_fields(fields, payload, source, option_aliases);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "algorithm") {
        add_present_node(fields, JwtField::Algorithm, value, source);
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "headers") {
        add_object_field(
            fields,
            JwtField::Algorithm,
            options,
            source,
            &["alg"],
            line,
            column,
        );
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "options") {
        add_python_options_fields(fields, source, options, option_aliases, line, column);
    }
    add_missing_for_issue_fields(fields, line, column);
}

fn add_python_decode_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    scope_source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    let positional_arguments = positional_argument_nodes(argument_nodes);
    let key = positional_arguments
        .get(1)
        .copied()
        .or_else(|| python_keyword_value(argument_nodes, source, "key"));
    add_key_reference(fields, source, key, line, column);
    if key.is_some() {
        add_present_value(
            fields,
            JwtField::SignatureVerification,
            "verified",
            line,
            column,
            "PyJWT decode verifies signatures when a key is supplied",
        );
    } else {
        add_missing_value(
            fields,
            JwtField::SignatureVerification,
            "missing_key",
            line,
            column,
            "PyJWT decode has no static verification key evidence",
        );
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "algorithms") {
        add_present_node(fields, JwtField::Algorithm, value, source);
        add_present_node(fields, JwtField::OptionAlgorithms, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "issuer") {
        add_present_node(fields, JwtField::Issuer, value, source);
        add_present_node(fields, JwtField::OptionIssuer, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "audience") {
        add_present_node(fields, JwtField::Audience, value, source);
        add_present_node(fields, JwtField::OptionAudience, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "subject") {
        add_present_node(fields, JwtField::OptionSubject, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "nonce") {
        add_present_node(fields, JwtField::OptionNonce, value, source);
    }
    if let Some(value) = python_keyword_value(argument_nodes, source, "leeway") {
        add_present_node(fields, JwtField::OptionClockTolerance, value, source);
    }
    if let Some(options) = python_keyword_value(argument_nodes, source, "options") {
        add_python_options_fields(fields, source, options, option_aliases, line, column);
    }
    add_python_expiry_enforcement(fields, source, argument_nodes, option_aliases, line, column);
    add_missing_for_verify_fields(fields, line, column);
    add_header_trust_fields(fields, scope_source, line, column);
}

fn add_python_decode_without_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    scope_source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    add_missing_value(
        fields,
        JwtField::SignatureVerification,
        "verify_signature: false",
        line,
        column,
        "PyJWT decode disables signature verification",
    );
    add_missing_value(
        fields,
        JwtField::ExpiryEnforcement,
        "verify_signature: false",
        line,
        column,
        "PyJWT decode without signature verification should not be treated as expiration enforcement",
    );
    add_python_decode_fields(
        fields,
        source,
        scope_source,
        argument_nodes,
        option_aliases,
        line,
        column,
    );
    add_missing_value(
        fields,
        JwtField::SignatureVerification,
        "verify_signature: false",
        line,
        column,
        "PyJWT decode disables signature verification",
    );
    add_missing_value(
        fields,
        JwtField::ExpiryEnforcement,
        "verify_signature: false",
        line,
        column,
        "PyJWT decode without signature verification should not be treated as expiration enforcement",
    );
}

fn add_python_options_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Node<'_>,
    aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    let option_fields = [
        JwtField::Issuer,
        JwtField::Audience,
        JwtField::Algorithm,
        JwtField::OptionIssuer,
        JwtField::OptionAudience,
        JwtField::OptionAlgorithms,
        JwtField::OptionSubject,
        JwtField::OptionNonce,
        JwtField::OptionClockTolerance,
        JwtField::OptionClockTimestamp,
        JwtField::OptionComplete,
        JwtField::OptionIgnoreNotBefore,
        JwtField::OptionIgnoreExpiration,
    ];
    if is_dictionary(node) {
        for (field, names) in [
            (
                JwtField::OptionAlgorithms,
                &["algorithms", "algorithm"] as &[_],
            ),
            (JwtField::OptionIssuer, &["issuer", "iss"]),
            (JwtField::OptionAudience, &["audience", "aud"]),
            (JwtField::OptionSubject, &["subject", "sub"]),
            (JwtField::OptionNonce, &["nonce"]),
            (
                JwtField::OptionClockTolerance,
                &["leeway", "clockTolerance"],
            ),
            (JwtField::OptionClockTimestamp, &["clockTimestamp"]),
            (JwtField::OptionComplete, &["complete"]),
            (JwtField::OptionIgnoreNotBefore, &["verify_nbf"]),
            (JwtField::OptionIgnoreExpiration, &["verify_exp"]),
        ] {
            add_object_field(fields, field, node, source, names, line, column);
        }
        if object_has_dynamic_spread(node, source) {
            for field in option_fields {
                fields
                    .entry(field)
                    .or_insert_with(|| dynamic_field(field, line, column));
            }
        }
    } else if node.kind() == "identifier" {
        let alias_name = node_text(node, source);
        if let Some(alias) = lookup_alias(aliases, &alias_name, node) {
            for field in option_fields {
                if let Some(value) = alias.fields.get(&field) {
                    fields.entry(field).or_insert_with(|| value.clone());
                } else if alias.dynamic {
                    fields
                        .entry(field)
                        .or_insert_with(|| dynamic_field(field, line, column));
                }
            }
        } else {
            for field in option_fields {
                fields
                    .entry(field)
                    .or_insert_with(|| dynamic_field(field, line, column));
            }
        }
    }
}

fn add_python_expiry_enforcement(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    argument_nodes: &[Node<'_>],
    aliases: &AliasMap,
    line: usize,
    column: usize,
) {
    let Some(options) = python_keyword_value(argument_nodes, source, "options") else {
        add_framework_default(
            fields,
            JwtField::ExpiryEnforcement,
            "PyJWT decode default",
            line,
            column,
            "PyJWT decode enforces exp by library default",
        );
        return;
    };

    if is_dictionary(options) {
        if object_property_value(options, source, "verify_exp")
            .is_some_and(|value| is_false_literal(value, source))
        {
            add_missing_value(
                fields,
                JwtField::ExpiryEnforcement,
                "verify_exp: false",
                line,
                column,
                "PyJWT expiry enforcement is disabled with verify_exp: false",
            );
            return;
        }
        if python_options_require_exp(options, source) {
            add_present_value(
                fields,
                JwtField::ExpiryEnforcement,
                "require: exp",
                line,
                column,
                "PyJWT options require exp",
            );
            return;
        }
        if object_has_dynamic_spread(options, source) {
            fields
                .entry(JwtField::ExpiryEnforcement)
                .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
            return;
        }
    } else if options.kind() == "identifier" {
        let alias_name = node_text(options, source);
        if let Some(alias) = lookup_alias(aliases, &alias_name, options) {
            if let Some(observation) = alias.fields.get(&JwtField::ExpiryEnforcement) {
                fields
                    .entry(JwtField::ExpiryEnforcement)
                    .or_insert_with(|| observation.clone());
                return;
            }
            if alias.dynamic {
                fields
                    .entry(JwtField::ExpiryEnforcement)
                    .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
                return;
            }
        } else {
            fields
                .entry(JwtField::ExpiryEnforcement)
                .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
            return;
        }
    } else {
        fields
            .entry(JwtField::ExpiryEnforcement)
            .or_insert_with(|| dynamic_field(JwtField::ExpiryEnforcement, line, column));
        return;
    }

    add_framework_default(
        fields,
        JwtField::ExpiryEnforcement,
        "PyJWT decode default",
        line,
        column,
        "PyJWT decode enforces exp by library default",
    );
}

fn python_decode_disables_verification(
    source: &str,
    argument_nodes: &[Node<'_>],
    option_aliases: &AliasMap,
) -> bool {
    let Some(options) = python_keyword_value(argument_nodes, source, "options") else {
        return false;
    };
    if is_dictionary(options) {
        return object_property_value(options, source, "verify_signature")
            .is_some_and(|value| is_false_literal(value, source));
    }
    if options.kind() == "identifier" {
        let alias_name = node_text(options, source);
        return lookup_alias(option_aliases, &alias_name, options)
            .is_some_and(|alias| alias.fields.contains_key(&JwtField::Operation));
    }
    false
}

fn collect_js_imports(source: &str) -> JsImports {
    let mut imports = JsImports::default();
    imports.jsonwebtoken_namespaces.insert("jwt".to_string());

    for pattern in [
        r#"import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+["']jsonwebtoken["']"#,
        r#"import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+["']jsonwebtoken["']"#,
        r#"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*["']jsonwebtoken["']\s*\)"#,
    ] {
        let regex = Regex::new(pattern).expect("import regex should compile");
        for capture in regex.captures_iter(source) {
            imports
                .jsonwebtoken_namespaces
                .insert(capture[1].to_string());
        }
    }

    collect_js_named_imports(
        source,
        "jsonwebtoken",
        &mut imports.jsonwebtoken_functions,
        &["sign", "verify", "decode"],
    );
    collect_js_named_imports(
        source,
        "jose",
        &mut imports.jose_functions,
        &["jwtVerify", "decodeJwt", "SignJWT"],
    );
    imports
}

fn collect_js_named_imports(
    source: &str,
    package: &str,
    output: &mut BTreeMap<String, &'static str>,
    allowed: &[&'static str],
) {
    let import_regex = Regex::new(&format!(
        r#"import\s*\{{([^}}]+)\}}\s*from\s*["']{}["']"#,
        regex::escape(package)
    ))
    .expect("named import regex should compile");
    let require_regex = Regex::new(&format!(
        r#"(?:const|let|var)\s*\{{([^}}]+)\}}\s*=\s*require\s*\(\s*["']{}["']\s*\)"#,
        regex::escape(package)
    ))
    .expect("named require regex should compile");

    for capture in import_regex
        .captures_iter(source)
        .chain(require_regex.captures_iter(source))
    {
        for item in capture[1].split(',') {
            let item = item.trim();
            let mut pieces = item.split_whitespace().collect::<Vec<_>>();
            if pieces.len() == 3 && pieces[1] == "as" {
                let original = pieces.remove(0);
                let local = pieces.pop().expect("alias should exist");
                if let Some(allowed_original) = allowed.iter().find(|name| **name == original) {
                    output.insert(local.to_string(), *allowed_original);
                }
            } else if pieces.len() == 1 {
                let original = pieces[0];
                if let Some(allowed_original) = allowed.iter().find(|name| **name == original) {
                    output.insert(original.to_string(), *allowed_original);
                }
            }
        }
    }
}

fn collect_python_imports(source: &str) -> PyImports {
    let mut imports = PyImports::default();
    imports.jwt_modules.insert("jwt".to_string());

    let module_regex = Regex::new(r#"(?m)^\s*import\s+jwt(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?"#)
        .expect("python jwt import regex should compile");
    for capture in module_regex.captures_iter(source) {
        imports.jwt_modules.insert(
            capture
                .get(1)
                .map_or("jwt", |alias| alias.as_str())
                .to_string(),
        );
    }

    let fn_regex = Regex::new(r#"(?m)^\s*from\s+jwt\s+import\s+([A-Za-z0-9_,\sas]+)"#)
        .expect("python jwt function import regex should compile");
    for capture in fn_regex.captures_iter(source) {
        for item in capture[1].split(',') {
            let pieces = item.split_whitespace().collect::<Vec<_>>();
            if pieces.len() == 1 && matches!(pieces[0], "encode" | "decode") {
                let original: &'static str = if pieces[0] == "encode" {
                    "encode"
                } else {
                    "decode"
                };
                imports
                    .jwt_functions
                    .insert(pieces[0].to_string(), original);
            } else if pieces.len() == 3
                && pieces[1] == "as"
                && matches!(pieces[0], "encode" | "decode")
            {
                let original: &'static str = if pieces[0] == "encode" {
                    "encode"
                } else {
                    "decode"
                };
                imports
                    .jwt_functions
                    .insert(pieces[2].to_string(), original);
            }
        }
    }
    imports
}

fn collect_js_option_aliases(root: Node<'_>, source: &str) -> AliasMap {
    let mut aliases = BTreeMap::new();
    collect_option_aliases(
        root,
        source,
        &mut aliases,
        true,
        root.start_byte(),
        root.end_byte(),
    );
    aliases
}

fn collect_python_option_aliases(root: Node<'_>, source: &str) -> AliasMap {
    let mut aliases = BTreeMap::new();
    collect_option_aliases(
        root,
        source,
        &mut aliases,
        false,
        root.start_byte(),
        root.end_byte(),
    );
    aliases
}

fn collect_option_aliases(
    node: Node<'_>,
    source: &str,
    aliases: &mut AliasMap,
    javascript: bool,
    scope_start_byte: usize,
    scope_end_byte: usize,
) {
    let (scope_start_byte, scope_end_byte) = if is_scope_node(node) {
        (node.start_byte(), node.end_byte())
    } else {
        (scope_start_byte, scope_end_byte)
    };

    if javascript && node.kind() == "variable_declarator" {
        if let (Some(name), Some(value)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) && is_object_literal(value)
        {
            aliases
                .entry(node_text(name, source))
                .or_default()
                .push(scoped_field_set(
                    field_set_from_object(value, source),
                    node,
                    scope_start_byte,
                    scope_end_byte,
                ));
        }
    } else if !javascript
        && node.kind() == "assignment"
        && let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
        && left.kind() == "identifier"
        && is_dictionary(right)
    {
        aliases
            .entry(node_text(left, source))
            .or_default()
            .push(scoped_field_set(
                field_set_from_object(right, source),
                node,
                scope_start_byte,
                scope_end_byte,
            ));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_option_aliases(
            child,
            source,
            aliases,
            javascript,
            scope_start_byte,
            scope_end_byte,
        );
    }
}

fn scoped_field_set(
    field_set: FieldSet,
    declaration: Node<'_>,
    scope_start_byte: usize,
    scope_end_byte: usize,
) -> ScopedFieldSet {
    ScopedFieldSet {
        fields: field_set.fields,
        dynamic: field_set.dynamic,
        declaration_end_byte: declaration.end_byte(),
        scope_start_byte,
        scope_end_byte,
    }
}

fn lookup_alias<'a>(
    aliases: &'a AliasMap,
    name: &str,
    use_node: Node<'_>,
) -> Option<&'a ScopedFieldSet> {
    aliases.get(name).and_then(|bindings| {
        bindings
            .iter()
            .filter(|binding| {
                binding.declaration_end_byte <= use_node.start_byte()
                    && use_node.start_byte() >= binding.scope_start_byte
                    && use_node.end_byte() <= binding.scope_end_byte
            })
            .max_by_key(|binding| binding.declaration_end_byte)
    })
}

fn field_set_from_object(node: Node<'_>, source: &str) -> FieldSet {
    let mut fields = BTreeMap::new();
    for (field, names) in [
        (JwtField::Algorithm, &["algorithm", "algorithms", "alg"][..]),
        (JwtField::Issuer, &["issuer", "iss"][..]),
        (JwtField::Audience, &["audience", "aud"][..]),
        (JwtField::Expiration, &["expiresIn", "expires", "exp"][..]),
        (JwtField::ExpiryEnforcement, &["maxAge", "maxTokenAge"][..]),
        (
            JwtField::OptionAlgorithms,
            &["algorithm", "algorithms", "alg"][..],
        ),
        (JwtField::OptionIssuer, &["issuer", "iss"][..]),
        (JwtField::OptionAudience, &["audience", "aud"][..]),
        (JwtField::OptionSubject, &["subject", "sub"][..]),
        (JwtField::OptionNonce, &["nonce"][..]),
        (
            JwtField::OptionClockTolerance,
            &["clockTolerance", "leeway"][..],
        ),
        (
            JwtField::OptionClockTimestamp,
            &["clockTimestamp", "currentDate"][..],
        ),
        (JwtField::OptionComplete, &["complete"][..]),
        (
            JwtField::OptionIgnoreNotBefore,
            &["ignoreNotBefore", "verify_nbf"][..],
        ),
        (
            JwtField::OptionIgnoreExpiration,
            &["ignoreExpiration", "verify_exp"][..],
        ),
    ] {
        add_object_field(&mut fields, field, node, source, names, 1, 1);
    }
    if object_property_value(node, source, "ignoreExpiration")
        .is_some_and(|value| is_true_literal(value, source))
    {
        fields.insert(
            JwtField::ExpiryEnforcement,
            JwtFieldEvidence {
                state: JwtAttributeState::Missing,
                value: Some("ignoreExpiration: true".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: jwt_excerpt(
                    "JWT expiry enforcement is disabled with ignoreExpiration: true",
                ),
            },
        );
    }
    if object_property_value(node, source, "verify_exp")
        .is_some_and(|value| is_false_literal(value, source))
    {
        fields.insert(
            JwtField::ExpiryEnforcement,
            JwtFieldEvidence {
                state: JwtAttributeState::Missing,
                value: Some("verify_exp: false".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: jwt_excerpt("PyJWT expiry enforcement is disabled with verify_exp: false"),
            },
        );
    } else if python_options_require_exp(node, source) {
        fields.insert(
            JwtField::ExpiryEnforcement,
            JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some("require: exp".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: jwt_excerpt("PyJWT options require exp"),
            },
        );
    }
    if object_property_value(node, source, "verify_signature")
        .is_some_and(|value| is_false_literal(value, source))
    {
        fields.insert(
            JwtField::Operation,
            JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some("decode_without_verify".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: jwt_excerpt("verify_signature is false"),
            },
        );
        fields.insert(
            JwtField::SignatureVerification,
            JwtFieldEvidence {
                state: JwtAttributeState::Missing,
                value: Some("verify_signature: false".to_string()),
                confidence: Confidence::High,
                line: node_line_column(node).0,
                column: node_line_column(node).1,
                excerpt: jwt_excerpt("PyJWT decode disables signature verification"),
            },
        );
    }
    add_identity_claim_fields_from_object(&mut fields, node, source);
    FieldSet {
        fields,
        dynamic: object_has_dynamic_spread(node, source),
    }
}

fn add_object_field(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    object: Node<'_>,
    source: &str,
    names: &[&str],
    default_line: usize,
    default_column: usize,
) {
    for name in names {
        if let Some(value) = object_property_value(object, source, name) {
            add_present_node(fields, field, value, source);
            return;
        }
    }
    let (line, column) = if is_object_literal(object) || is_dictionary(object) {
        node_line_column(object)
    } else {
        (default_line, default_column)
    };
    if object_has_dynamic_spread(object, source) {
        fields
            .entry(field)
            .or_insert_with(|| dynamic_field(field, line, column));
    }
}

fn add_identity_claim_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    payload: Node<'_>,
    source: &str,
    aliases: &AliasMap,
) {
    if is_object_literal(payload) || is_dictionary(payload) {
        add_identity_claim_fields_from_object(fields, payload, source);
    } else if payload.kind() == "identifier" {
        let alias_name = node_text(payload, source);
        if let Some(alias) = lookup_alias(aliases, &alias_name, payload) {
            for field in JwtField::IDENTITY_CLAIMS {
                if let Some(value) = alias.fields.get(&field) {
                    fields.entry(field).or_insert_with(|| value.clone());
                }
            }
        }
    }
}

fn add_identity_claim_fields_from_object(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    object: Node<'_>,
    source: &str,
) {
    for (field, names) in identity_claim_mappings() {
        for name in names {
            if let Some(value) = object_property_value(object, source, name) {
                add_present_identity_node(fields, field, value, source);
                break;
            }
        }
    }
}

fn add_identity_claim_fields_from_text(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    text: &str,
    line: usize,
    column: usize,
) {
    for (field, names) in identity_claim_mappings() {
        for name in names {
            let pattern = format!(
                r#"(?s)(?:^|[{{,])\s*["']?{}["']?\s*:\s*([^,}}\n]+)"#,
                regex::escape(name)
            );
            let regex = Regex::new(&pattern).expect("claim regex should compile");
            if let Some(capture) = regex.captures(text) {
                fields.entry(field).or_insert_with(|| JwtFieldEvidence {
                    state: JwtAttributeState::Present,
                    value: Some(safe_identity_value(field, capture[1].trim())),
                    confidence: Confidence::High,
                    line,
                    column,
                    excerpt: jwt_excerpt(format!("{} is present", field.display_name())),
                });
                break;
            }
        }
    }
}

fn identity_claim_mappings() -> [(JwtField, &'static [&'static str]); 12] {
    [
        (JwtField::Subject, &["sub"]),
        (JwtField::UserId, &["user_id", "userId", "uid"]),
        (JwtField::TenantId, &["tenant", "tenant_id", "tenantId"]),
        (
            JwtField::OrgId,
            &["org", "org_id", "organization_id", "organizationId"],
        ),
        (
            JwtField::WorkspaceId,
            &["workspace", "workspace_id", "workspaceId"],
        ),
        (JwtField::Roles, &["role", "roles"]),
        (JwtField::Scopes, &["scope", "scopes"]),
        (JwtField::Groups, &["groups"]),
        (JwtField::Email, &["email"]),
        (
            JwtField::EmailVerified,
            &["email_verified", "emailVerified"],
        ),
        (JwtField::AuthMethod, &["amr", "auth_method", "authMethod"]),
        (JwtField::AuthClass, &["acr", "auth_class", "authClass"]),
    ]
}

fn add_present_identity_node(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    node: Node<'_>,
    source: &str,
) {
    let (line, column) = node_line_column(node);
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Present,
            value: Some(safe_identity_value(field, &node_text(node, source))),
            confidence: Confidence::High,
            line,
            column,
            excerpt: jwt_excerpt(format!("{} is present", field.display_name())),
        },
    );
}

fn add_present_node(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    node: Node<'_>,
    source: &str,
) {
    let (line, column) = node_line_column(node);
    let (value, excerpt) = if field.is_option() {
        option_value_and_excerpt(field, node, source)
    } else {
        (
            Some(safe_node_value(node, source)),
            excerpt_for_node(source, node),
        )
    };
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Present,
            value,
            confidence: Confidence::High,
            line,
            column,
            excerpt,
        },
    );
}

fn option_value_and_excerpt(
    field: JwtField,
    node: Node<'_>,
    source: &str,
) -> (Option<String>, SanitizedExcerpt) {
    let value = match field {
        JwtField::OptionAlgorithms
        | JwtField::OptionClockTolerance
        | JwtField::OptionClockTimestamp
        | JwtField::OptionComplete
        | JwtField::OptionIgnoreNotBefore
        | JwtField::OptionIgnoreExpiration => Some(safe_node_value(node, source)),
        _ => Some("[option]".to_string()),
    };
    let excerpt = match field {
        JwtField::OptionAlgorithms
        | JwtField::OptionClockTolerance
        | JwtField::OptionClockTimestamp
        | JwtField::OptionComplete
        | JwtField::OptionIgnoreNotBefore
        | JwtField::OptionIgnoreExpiration => excerpt_for_node(source, node),
        _ => jwt_excerpt(format!("{} is present", field.display_name())),
    };
    (value, excerpt)
}

fn add_present_synthetic(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    node: Node<'_>,
    source: &str,
    excerpt: impl Into<String>,
) {
    let (line, column) = node_line_column(node);
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Present,
            value: Some(if field == JwtField::KeyReference {
                safe_key_reference_value(node, source)
            } else {
                safe_node_value(node, source)
            }),
            confidence: Confidence::High,
            line,
            column,
            excerpt: jwt_excerpt(excerpt),
        },
    );
}

/// Wrap a trusted descriptive string in `SanitizedExcerpt`.
///
/// Detector excerpts that describe the analysis itself (e.g.,
/// "JWT key reference is present") are author-controlled English strings
/// that contain no source-derived secrets. They still flow through
/// `redact_excerpt` so that any inadvertently-templated source values
/// are masked, and are wrapped via the gated `from_sanitized`
/// constructor so the F-06 boundary is preserved.
fn jwt_excerpt(text: impl Into<String>) -> SanitizedExcerpt {
    SanitizedExcerpt::from_sanitized(redact_excerpt(&text.into()))
}

fn add_key_reference(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    source: &str,
    node: Option<Node<'_>>,
    line: usize,
    column: usize,
) {
    match node {
        Some(node) => add_present_synthetic(
            fields,
            JwtField::KeyReference,
            node,
            source,
            "JWT key reference is present",
        ),
        None => add_missing(fields, JwtField::KeyReference, line, column),
    }
}

fn add_missing_for_issue_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    line: usize,
    column: usize,
) {
    for field in [JwtField::Expiration] {
        if !fields.contains_key(&field) {
            add_missing(fields, field, line, column);
        }
    }
}

fn add_missing_for_verify_fields(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    line: usize,
    column: usize,
) {
    for field in [JwtField::Issuer, JwtField::Audience] {
        if !fields.contains_key(&field) {
            add_missing(fields, field, line, column);
        }
    }
}

fn add_missing(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    line: usize,
    column: usize,
) {
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Missing,
            value: None,
            confidence: Confidence::High,
            line,
            column,
            excerpt: jwt_excerpt(format!("{} is omitted", field.display_name())),
        },
    );
}

fn add_present_value(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    value: &str,
    line: usize,
    column: usize,
    excerpt: impl Into<String>,
) {
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Present,
            value: Some(value.to_string()),
            confidence: Confidence::High,
            line,
            column,
            excerpt: jwt_excerpt(excerpt),
        },
    );
}

fn add_missing_value(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    value: &str,
    line: usize,
    column: usize,
    excerpt: impl Into<String>,
) {
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::Missing,
            value: Some(value.to_string()),
            confidence: Confidence::High,
            line,
            column,
            excerpt: jwt_excerpt(excerpt),
        },
    );
}

fn add_framework_default(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    value: &str,
    line: usize,
    column: usize,
    excerpt: impl Into<String>,
) {
    fields.insert(
        field,
        JwtFieldEvidence {
            state: JwtAttributeState::FrameworkDefault,
            value: Some(value.to_string()),
            confidence: Confidence::Low,
            line,
            column,
            excerpt: jwt_excerpt(excerpt),
        },
    );
}

fn dynamic_field(field: JwtField, line: usize, column: usize) -> JwtFieldEvidence {
    JwtFieldEvidence {
        state: JwtAttributeState::Dynamic,
        value: None,
        confidence: Confidence::Medium,
        line,
        column,
        excerpt: jwt_excerpt(format!(
            "{} depends on unresolved JWT options",
            field.display_name()
        )),
    }
}

fn add_regex_chain_field(
    fields: &mut BTreeMap<JwtField, JwtFieldEvidence>,
    field: JwtField,
    text: &str,
    pattern: &str,
    line: usize,
    column: usize,
) {
    let regex = Regex::new(pattern).expect("chain regex should compile");
    if let Some(capture) = regex.captures(text) {
        let excerpt = if field == JwtField::KeyReference {
            "JWT key reference is present".to_string()
        } else {
            redact_excerpt(capture[0].trim())
        };
        fields.insert(
            field,
            JwtFieldEvidence {
                state: JwtAttributeState::Present,
                value: Some(safe_text_value(capture[1].trim())),
                confidence: Confidence::High,
                line,
                column,
                excerpt: SanitizedExcerpt::from_sanitized(excerpt),
            },
        );
    }
}

fn is_jose_sign_chain(text: &str, imports: &JsImports) -> bool {
    imports.jose_functions.iter().any(|(local, original)| {
        *original == "SignJWT" && text.contains(&format!("new {local}")) && text.contains(".sign")
    })
}

fn infer_jwt_display_name(
    function_name: Option<&str>,
    call: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut candidates = Vec::new();
    if let Some(function_name) = function_name {
        candidates.push(function_name.to_string());
    }
    if let Some(name) = assignment_name_for_call(call, source) {
        candidates.push(name);
    }
    candidates.push(node_text(call, source));

    let joined = candidates.join(" ").to_ascii_lowercase();
    if joined.contains("refresh") {
        Some("refresh_jwt".to_string())
    } else if joined.contains("legacy") {
        Some("legacy_access_jwt".to_string())
    } else if [
        "access",
        "session",
        "auth",
        "current_user",
        "currentuser",
        "bearer",
    ]
    .iter()
    .any(|needle| joined.contains(needle))
    {
        Some("access_jwt".to_string())
    } else {
        None
    }
}

fn artifact_type_for_name(name: Option<&str>) -> ArtifactType {
    match name.unwrap_or_default() {
        "access_jwt" | "legacy_access_jwt" => ArtifactType::AccessJwt,
        "refresh_jwt" => ArtifactType::RefreshJwt,
        _ => ArtifactType::Unknown,
    }
}

fn artifact_type_part(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::SessionCookie => "session_cookie",
        ArtifactType::SignedCookie => "signed_cookie",
        ArtifactType::AccessJwt => "access_jwt",
        ArtifactType::RefreshJwt => "refresh_jwt",
        ArtifactType::OpaqueBearerToken => "opaque_bearer_token",
        ArtifactType::ApiKey => "api_key",
        ArtifactType::ServiceToken => "service_token",
        ArtifactType::UnknownToken => "unknown_token",
        ArtifactType::PasswordResetToken => "password_reset_token",
        ArtifactType::EmailVerificationToken => "email_verification_token",
        ArtifactType::SessionRecord => "session_record",
        ArtifactType::Unknown => "unknown",
    }
}

fn push_lifecycle_id(
    lifecycle_evidence: &mut LifecycleEvidence,
    stage: LifecycleStage,
    evidence_id: sessionscope_model::EvidenceId,
) {
    match stage {
        LifecycleStage::Issue => lifecycle_evidence.issue.push(evidence_id),
        LifecycleStage::Store => lifecycle_evidence.store.push(evidence_id),
        LifecycleStage::Transmit => lifecycle_evidence.transmit.push(evidence_id),
        LifecycleStage::Validate => lifecycle_evidence.validate.push(evidence_id),
        LifecycleStage::Refresh => lifecycle_evidence.refresh.push(evidence_id),
        LifecycleStage::Revoke => lifecycle_evidence.revoke.push(evidence_id),
        LifecycleStage::Expire => lifecycle_evidence.expire.push(evidence_id),
        LifecycleStage::Introspect => lifecycle_evidence.introspect.push(evidence_id),
    }
}

fn jwt_call_excerpt(api_name: &str, operation: JwtOperation) -> SanitizedExcerpt {
    SanitizedExcerpt::from_sanitized(format!(
        "{api_name} {} call detected with token and key arguments redacted",
        operation.value()
    ))
}

fn jwt_state_part(state: JwtAttributeState) -> &'static str {
    match state {
        JwtAttributeState::Present => "present",
        JwtAttributeState::Missing => "missing",
        JwtAttributeState::Dynamic => "dynamic",
        JwtAttributeState::FrameworkDefault => "framework_default",
        JwtAttributeState::Unknown => "unknown",
    }
}

fn object_property_value<'tree>(
    node: Node<'tree>,
    source: &str,
    property_name: &str,
) -> Option<Node<'tree>> {
    if !is_object_literal(node) && !is_dictionary(node) {
        return None;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((key, value)) = object_pair(child)
            && property_key_text(key, source).as_deref() == Some(property_name)
        {
            return Some(value);
        }
    }
    None
}

fn object_pair(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    match node.kind() {
        "pair" => Some((
            node.child_by_field_name("key")?,
            node.child_by_field_name("value")?,
        )),
        "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
            Some((node, node))
        }
        _ => None,
    }
}

fn property_key_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" | "identifier" => Some(node_text(node, source)),
        "string" => parse_string_text(&node_text(node, source)),
        _ => Some(node_text(node, source)),
    }
}

fn object_has_dynamic_spread(node: Node<'_>, source: &str) -> bool {
    let text = node_text(node, source);
    text.contains("...") || text.contains("**")
}

fn is_object_literal(node: Node<'_>) -> bool {
    matches!(node.kind(), "object" | "object_pattern")
}

fn is_dictionary(node: Node<'_>) -> bool {
    matches!(node.kind(), "dictionary" | "dictionary_pattern")
}

fn is_member_expression(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "member_expression" | "optional_chain" | "subscript_expression"
    )
}

fn is_scope_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "program"
            | "function_declaration"
            | "function"
            | "arrow_function"
            | "method_definition"
            | "function_definition"
    )
}

fn python_keyword_value<'tree>(
    argument_nodes: &[Node<'tree>],
    source: &str,
    keyword: &str,
) -> Option<Node<'tree>> {
    for argument in argument_nodes {
        if argument.kind() == "keyword_argument"
            && let Some(name) = argument.child_by_field_name("name")
            && node_text(name, source) == keyword
        {
            return argument.child_by_field_name("value").or_else(|| {
                argument
                    .named_child_count()
                    .checked_sub(1)
                    .and_then(|index| argument.named_child(index as u32))
            });
        }
    }
    None
}

fn positional_argument_nodes<'tree>(argument_nodes: &[Node<'tree>]) -> Vec<Node<'tree>> {
    argument_nodes
        .iter()
        .copied()
        .filter(|node| node.kind() != "keyword_argument")
        .collect()
}

fn is_false_literal(node: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(node, source).to_ascii_lowercase().as_str(),
        "false" | "False"
    )
}

fn is_true_literal(node: Node<'_>, source: &str) -> bool {
    matches!(
        node_text(node, source).to_ascii_lowercase().as_str(),
        "true" | "True"
    )
}

fn python_options_require_exp(node: Node<'_>, source: &str) -> bool {
    object_property_value(node, source, "require").is_some_and(|value| {
        node_text(value, source)
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '_' || character == '-')
            })
            .any(|part| part == "exp")
    })
}

fn safe_node_value(node: Node<'_>, source: &str) -> String {
    safe_text_value(&node_text(node, source))
}

fn safe_key_reference_value(node: Node<'_>, source: &str) -> String {
    let text = node_text(node, source);
    let trimmed = text.trim();
    if trimmed.contains(['"', '\'', '`']) {
        return "[key_reference]".to_string();
    }
    match node.kind() {
        "identifier" | "property_identifier" => safe_text_value(trimmed),
        "member_expression" | "attribute" => safe_text_value(trimmed),
        _ if trimmed.to_ascii_lowercase().contains("publickey")
            || trimmed.to_ascii_lowercase().contains("pubkey")
            || trimmed.to_ascii_lowercase().contains("loadpublickey")
            || trimmed.ends_with(".pem") =>
        {
            safe_text_value(trimmed)
        }
        _ => "[key_reference]".to_string(),
    }
}

fn safe_identity_value(field: JwtField, text: &str) -> String {
    let trimmed = text.trim();
    if field == JwtField::EmailVerified
        && matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "true" | "false" | "True" | "False"
        )
    {
        return trimmed.to_ascii_lowercase();
    }
    if parse_string_text(trimmed).is_some()
        || trimmed.starts_with('[')
        || trimmed.starts_with('{')
        || trimmed.chars().all(|character| character.is_ascii_digit())
    {
        "[literal]".to_string()
    } else {
        safe_text_value(trimmed)
    }
}

fn safe_text_value(text: &str) -> String {
    let trimmed = text.trim();
    if parse_string_text(trimmed).is_some() || trimmed.starts_with('[') || trimmed.starts_with('{')
    {
        "[literal]".to_string()
    } else {
        trimmed
            .chars()
            .take(80)
            .collect::<String>()
            .replace(['\n', '\r', '\t'], " ")
    }
}

fn js_function_name(node: Node<'_>, source: &str) -> Option<String> {
    if matches!(
        node.kind(),
        "function_declaration" | "function" | "method_definition"
    ) {
        return node
            .child_by_field_name("name")
            .map(|name| node_text(name, source));
    }
    None
}

fn python_function_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "function_definition" {
        return node
            .child_by_field_name("name")
            .map(|name| node_text(name, source));
    }
    None
}

fn assignment_name_for_call(call: Node<'_>, source: &str) -> Option<String> {
    let mut current = call.parent();
    while let Some(node) = current {
        if node.kind() == "variable_declarator" || node.kind() == "assignment" {
            return node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("left"))
                .map(|name| node_text(name, source));
        }
        if matches!(
            node.kind(),
            "function_declaration" | "function_definition" | "statement_block" | "block"
        ) {
            break;
        }
        current = node.parent();
    }
    None
}

fn node_line_column(node: Node<'_>) -> (usize, usize) {
    let position = node.start_position();
    (position.row + 1, position.column + 1)
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn excerpt_for_node(source: &str, node: Node<'_>) -> SanitizedExcerpt {
    let text = node_text(node, source);
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let excerpt = if collapsed.len() > 240 {
        format!("{}...", &collapsed[..240])
    } else {
        collapsed
    };
    SanitizedExcerpt::from_sanitized(redact_excerpt(&excerpt))
}

fn redact_excerpt(text: &str) -> String {
    let mut output = PLACEHOLDER_SECRET_RE
        .replace_all(text, REDACTION)
        .to_string();
    output = redact_jwt_api_calls(&output);
    output = JWT_RE.replace_all(&output, REDACTION).to_string();
    output = LONG_LITERAL_RE
        .replace_all(&output, |captures: &regex::Captures<'_>| {
            let left = captures
                .get(0)
                .map(|matched| matched.as_str())
                .unwrap_or_default()
                .split(['"', '\''])
                .next()
                .unwrap_or_default();
            format!("{left}\"{REDACTION}\"")
        })
        .to_string();
    output = SENSITIVE_CLAIM_RE
        .replace_all(&output, format!("${{1}}{REDACTION}${{3}}"))
        .to_string();
    output = SENSITIVE_CLAIM_COLLECTION_RE
        .replace_all(&output, format!("${{1}}{REDACTION}"))
        .to_string();
    output = EMAIL_RE.replace_all(&output, REDACTION).to_string();
    output
}

fn redact_jwt_api_calls(input: &str) -> String {
    JWT_API_CALL_RE
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let call = captures.get(0).expect("full capture should exist").as_str();
            QUOTED_LITERAL_RE
                .replace_all(call, |literal: &regex::Captures<'_>| {
                    let value = literal
                        .get(0)
                        .expect("literal capture should exist")
                        .as_str();
                    let quote = &value[..1];
                    format!("{quote}{REDACTION}{quote}")
                })
                .to_string()
        })
        .to_string()
}

fn parse_string_text(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let quote = chars.next()?;
    if !matches!(quote, '"' | '\'' | '`') || !text.ends_with(quote) || text.len() < 2 {
        return None;
    }
    Some(text[quote.len_utf8()..text.len() - quote.len_utf8()].to_string())
}

fn node_text(node: Node<'_>, source: &str) -> String {
    node.utf8_text(source.as_bytes())
        .expect("tree-sitter node should be valid UTF-8")
        .to_string()
}

fn scope_text(node: Node<'_>, source: &str) -> String {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if is_scope_node(candidate) && candidate.kind() != "program" {
            return node_text(candidate, source);
        }
        current = candidate.parent();
    }
    node_text(node, source)
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{ArtifactType, Language};

    use super::*;

    fn detect(language: Language, source: &str) -> DetectionOutput {
        JwtDetector.detect(&DetectorInput {
            path: match language {
                Language::Python => "auth.py",
                _ => "auth.ts",
            },
            language,
            source,
        })
    }

    #[test]
    fn detects_jsonwebtoken_sign_and_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
const ISSUER = "issuer";
const AUDIENCE = "aud";
export function issueAccessJwt(userId: string) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE, expiresIn: "15m" });
}
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE });
}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT artifact should exist");
        assert_eq!(artifact.artifact_type, ArtifactType::AccessJwt);
        assert!(!artifact.lifecycle_evidence.issue.is_empty());
        assert!(!artifact.lifecycle_evidence.validate.is_empty());
        assert!(!artifact.lifecycle_evidence.expire.is_empty());
        let attributes = artifact.jwt_attributes.as_ref().expect("jwt attributes");
        assert_eq!(attributes.issuer.state, JwtAttributeState::Present);
        assert_eq!(attributes.audience.state, JwtAttributeState::Present);
        assert_eq!(attributes.expiration.state, JwtAttributeState::Present);
        assert_eq!(
            attributes.signature_verification.state,
            JwtAttributeState::Present
        );
        assert_eq!(
            attributes.expiry_enforcement.state,
            JwtAttributeState::FrameworkDefault
        );
        assert!(!detected_text(&output).contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    }

    #[test]
    fn detects_jsonwebtoken_decode_without_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import { decode } from "jsonwebtoken";
export function inspectAccessJwt(token: string) {
  return decode(token);
}
"#,
        );

        let artifact = &output.artifacts[0];
        assert!(!artifact.lifecycle_evidence.introspect.is_empty());
        assert_eq!(
            artifact
                .jwt_attributes
                .as_ref()
                .expect("jwt attributes")
                .operation
                .value
                .as_deref(),
            Some("decode_without_verify")
        );
        let attributes = artifact.jwt_attributes.as_ref().expect("jwt attributes");
        assert_eq!(
            attributes.signature_verification.state,
            JwtAttributeState::Missing
        );
        assert_eq!(
            attributes.expiry_enforcement.state,
            JwtAttributeState::Missing
        );
    }

    #[test]
    fn detects_jsonwebtoken_expiry_enforcement_options() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE, maxAge: "15m" });
}
export function verifyLegacyJwt(token: string) {
  return jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
}
"#,
        );

        let access = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        assert_eq!(
            access
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::Present
        );

        let legacy = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("legacy_access_jwt"))
            .expect("legacy JWT should exist");
        assert_eq!(
            legacy
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::Missing
        );
    }

    #[test]
    fn emits_jsonwebtoken_verify_option_evidence() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, publicKey, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: SUBJECT,
    nonce: expectedNonce,
    clockTolerance: 120,
    clockTimestamp: now,
    complete: true,
    ignoreNotBefore: true,
    ignoreExpiration: false,
  });
}
"#,
        );

        for detector_id in [
            "jwt.option.algorithms",
            "jwt.option.issuer",
            "jwt.option.audience",
            "jwt.option.subject",
            "jwt.option.nonce",
            "jwt.option.clock_tolerance",
            "jwt.option.clock_timestamp",
            "jwt.option.complete",
            "jwt.option.ignore_not_before",
            "jwt.option.ignore_expiration",
        ] {
            assert!(
                output
                    .evidence
                    .iter()
                    .any(|evidence| evidence.detector_id == detector_id),
                "missing {detector_id} in {:?}",
                output
                    .evidence
                    .iter()
                    .map(|evidence| evidence.detector_id.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn emits_jose_verify_option_evidence() {
        let output = detect(
            Language::TypeScript,
            r#"
import { jwtVerify } from "jose";
export async function verifyAccessJwt(token: string) {
  return jwtVerify(token, publicKey, {
    algorithms: ["RS256"],
    issuer,
    audience,
    subject,
    nonce,
    clockTolerance: "30s",
    currentDate: now,
  });
}
"#,
        );

        for detector_id in [
            "jwt.option.algorithms",
            "jwt.option.issuer",
            "jwt.option.audience",
            "jwt.option.subject",
            "jwt.option.nonce",
            "jwt.option.clock_tolerance",
            "jwt.option.clock_timestamp",
        ] {
            assert!(
                output
                    .evidence
                    .iter()
                    .any(|evidence| evidence.detector_id == detector_id),
                "missing {detector_id}"
            );
        }
    }

    #[test]
    fn emits_pyjwt_verify_option_evidence() {
        let output = detect(
            Language::Python,
            r#"
import jwt

def verify_access_jwt(token):
    return jwt.decode(
        token,
        key=PUBLIC_KEY,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        nonce=NONCE,
        leeway=120,
        options={"verify_nbf": False, "verify_exp": True, "complete": True},
    )
"#,
        );

        for detector_id in [
            "jwt.option.algorithms",
            "jwt.option.issuer",
            "jwt.option.audience",
            "jwt.option.subject",
            "jwt.option.nonce",
            "jwt.option.clock_tolerance",
            "jwt.option.complete",
            "jwt.option.ignore_not_before",
            "jwt.option.ignore_expiration",
        ] {
            assert!(
                output
                    .evidence
                    .iter()
                    .any(|evidence| evidence.detector_id == detector_id),
                "missing {detector_id}"
            );
        }
    }

    #[test]
    fn emits_jwt_header_read_evidence_near_verification() {
        let ts_output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
export function verifyAccessJwt(token: string) {
  const decoded = jwt.verify(token, getKey, { complete: true, algorithms: ["RS256"] });
  return resolveKey(decoded.header.jku, decoded.header.x5u, decoded.header.jwk, decoded.header.kid);
}
"#,
        );
        let py_output = detect(
            Language::Python,
            r#"
import jwt

def verify_access_jwt(token):
    decoded = jwt.decode(token, key=PUBLIC_KEY, algorithms=["RS256"], options={"complete": True})
    return resolve_key(decoded["header"]["jku"], decoded["header"]["x5u"], decoded["header"]["jwk"])
"#,
        );

        let detector_ids = ts_output
            .evidence
            .iter()
            .chain(py_output.evidence.iter())
            .map(|evidence| evidence.detector_id.as_str())
            .collect::<Vec<_>>();
        for detector_id in [
            "jwt.header.jku",
            "jwt.header.x5u",
            "jwt.header.jwk",
            "jwt.header.kid",
        ] {
            assert!(
                detector_ids.contains(&detector_id),
                "missing {detector_id} in {detector_ids:?}"
            );
        }
    }

    #[test]
    fn does_not_attach_unrelated_header_reads_to_verify_call() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer, audience, complete: true });
}
export function unrelated(decoded: any) {
  return decoded.header.jku;
}
"#,
        );

        assert!(
            output
                .evidence
                .iter()
                .all(|evidence| evidence.detector_id != "jwt.header.jku")
        );
    }

    #[test]
    fn option_and_key_reference_values_do_not_leak_sensitive_literals() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
export function verifyAccessJwt(token: string) {
  return jwt.verify(token, createSecretKey("raw-secret-value"), {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
    subject: "sensitive-subject-value",
    nonce: "abcDEF12345678901234",
    ignoreNotBefore: false,
  });
}
"#,
        );

        let detected = detected_text(&output);
        for leaked in [
            "raw-secret-value",
            "sensitive-subject-value",
            "abcDEF12345678901234",
        ] {
            assert!(!detected.contains(leaked), "{leaked} leaked in {detected}");
        }
    }

    #[test]
    fn detects_jsonwebtoken_identity_claims_from_payload_alias() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
export function issueAccessJwt(userId: string, tenantId: string, authMethod: string) {
  const claims = {
    sub: userId,
    tenant_id: tenantId,
    roles: ["admin"],
    email: "person@example.com",
    emailVerified: true,
    amr: authMethod,
  };
  return jwt.sign(claims, JWT_SECRET, { expiresIn: "15m" });
}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT artifact should exist");
        let identity_claims = artifact
            .jwt_attributes
            .as_ref()
            .expect("jwt attributes")
            .identity_claims
            .as_ref()
            .expect("identity claims");
        assert_eq!(identity_claims.subject.state, JwtAttributeState::Present);
        assert_eq!(identity_claims.subject.value.as_deref(), Some("userId"));
        assert_eq!(identity_claims.tenant_id.state, JwtAttributeState::Present);
        assert_eq!(identity_claims.tenant_id.value.as_deref(), Some("tenantId"));
        assert_eq!(identity_claims.roles.value.as_deref(), Some("[literal]"));
        assert_eq!(identity_claims.email.value.as_deref(), Some("[literal]"));
        assert_eq!(
            identity_claims.email_verified.value.as_deref(),
            Some("true")
        );
        assert_eq!(
            identity_claims.auth_method.value.as_deref(),
            Some("authMethod")
        );
        let detected = detected_text(&output);
        assert!(!detected.contains("person@example.com"));
        assert!(!detected.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
    }

    #[test]
    fn detects_jose_sign_and_verify() {
        let output = detect(
            Language::TypeScript,
            r#"
import { jwtVerify, SignJWT } from "jose";
const secret = new TextEncoder().encode("PLACEHOLDER_SECRET_DO_NOT_USE");
export async function issueAccessJwt(userId: string, orgId: string) {
  return await new SignJWT({ sub: userId, org_id: orgId, scopes: ["read:users"] })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("15m")
    .sign(secret);
}
export async function verifyAccessJwt(token: string) {
  return jwtVerify(token, secret, { issuer, audience });
}
"#,
        );

        let artifact = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT artifact should exist");
        assert!(artifact.framework_hints.contains(&"jose".to_string()));
        assert!(!artifact.lifecycle_evidence.issue.is_empty());
        assert!(!artifact.lifecycle_evidence.validate.is_empty());
        assert_eq!(
            artifact
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::FrameworkDefault
        );
        let identity_claims = artifact
            .jwt_attributes
            .as_ref()
            .expect("attributes")
            .identity_claims
            .as_ref()
            .expect("identity claims");
        assert_eq!(identity_claims.subject.value.as_deref(), Some("userId"));
        assert_eq!(identity_claims.org_id.value.as_deref(), Some("orgId"));
        assert_eq!(identity_claims.scopes.value.as_deref(), Some("[literal]"));
        assert!(!detected_text(&output).contains("read:users"));
    }

    #[test]
    fn detects_pyjwt_encode_decode_and_decode_without_verify() {
        let output = detect(
            Language::Python,
            r#"
import jwt as pyjwt
JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"

def issue_access_jwt(user_id):
    claims = {
        "sub": user_id,
        "workspace_id": workspace_id,
        "groups": ["admins"],
        "email": "person@example.com",
        "email_verified": True,
        "acr": "urn:mfa",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": expires_at,
    }
    return pyjwt.encode(claims, JWT_SECRET, algorithm="HS256")

def verify_legacy_jwt(token):
    return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def inspect_access_jwt(token):
    return pyjwt.decode(token, options={"verify_signature": False})
"#,
        );

        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("access_jwt")
                && !artifact.lifecycle_evidence.issue.is_empty()
        }));
        assert!(output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("legacy_access_jwt")
                && artifact
                    .jwt_attributes
                    .as_ref()
                    .is_some_and(|attributes| attributes.issuer.state == JwtAttributeState::Missing)
        }));
        assert!(
            output
                .artifacts
                .iter()
                .any(|artifact| !artifact.lifecycle_evidence.introspect.is_empty())
        );
        let access = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        let identity_claims = access
            .jwt_attributes
            .as_ref()
            .expect("attributes")
            .identity_claims
            .as_ref()
            .expect("identity claims");
        assert_eq!(identity_claims.subject.value.as_deref(), Some("user_id"));
        assert_eq!(
            identity_claims.workspace_id.value.as_deref(),
            Some("workspace_id")
        );
        assert_eq!(identity_claims.groups.value.as_deref(), Some("[literal]"));
        assert_eq!(identity_claims.email.value.as_deref(), Some("[literal]"));
        assert_eq!(
            identity_claims.email_verified.value.as_deref(),
            Some("true")
        );
        assert_eq!(
            identity_claims.auth_class.value.as_deref(),
            Some("[literal]")
        );
        let detected = detected_text(&output);
        assert!(!detected.contains("PLACEHOLDER_SECRET_DO_NOT_USE"));
        assert!(!detected.contains("person@example.com"));
        assert!(!detected.contains("admins"));
        assert!(!detected.contains("urn:mfa"));
    }

    #[test]
    fn detects_pyjwt_expiry_enforcement_options() {
        let output = detect(
            Language::Python,
            r#"
import jwt
JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE"

def verify_access_jwt(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE, options={"require": ["exp"]})

def verify_legacy_jwt(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
"#,
        );

        let access = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        assert_eq!(
            access
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::Present
        );

        let legacy = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("legacy_access_jwt"))
            .expect("legacy JWT should exist");
        assert_eq!(
            legacy
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::Missing
        );
    }

    #[test]
    fn redacts_short_literal_jwt_tokens_and_keys_from_evidence() {
        let ts_output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
export function issueAccessJwt() {
  return jwt.sign({ sub: "user-123" }, "dev-secret", { expiresIn: "15m" });
}
export function verifyAccessJwt() {
  return jwt.verify("opaque-token", "secret", { issuer: ISSUER, audience: AUDIENCE });
}
export function inspectAccessJwt() {
  return jwt.decode("short-token");
}
"#,
        );
        let py_output = detect(
            Language::Python,
            r#"
import jwt
def verify_access_jwt(token):
    return jwt.decode(token, key="secret", algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE)
"#,
        );

        let detected = format!(
            "{}\n{}",
            detected_text(&ts_output),
            detected_text(&py_output)
        );
        for leaked in [
            "dev-secret",
            "opaque-token",
            "short-token",
            "\"secret\"",
            "user-123",
        ] {
            assert!(!detected.contains(leaked), "{leaked} leaked in {detected}");
        }
    }

    #[test]
    fn detects_pyjwt_keyword_key_without_confusing_other_keywords() {
        let missing_key = detect(
            Language::Python,
            r#"
import jwt
def verify_access_jwt(token):
    return jwt.decode(token, algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE)
"#,
        );
        let artifact = missing_key
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        let attributes = artifact.jwt_attributes.as_ref().expect("attributes");
        assert_eq!(
            attributes.signature_verification.state,
            JwtAttributeState::Missing
        );
        assert_eq!(attributes.key_reference.state, JwtAttributeState::Missing);

        let keyword_key = detect(
            Language::Python,
            r#"
import jwt
def verify_access_jwt(token):
    return jwt.decode(token, key=PUBLIC_KEY, algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE)
"#,
        );
        let artifact = keyword_key
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        let attributes = artifact.jwt_attributes.as_ref().expect("attributes");
        assert_eq!(
            attributes.signature_verification.state,
            JwtAttributeState::Present
        );
        assert_eq!(
            attributes.key_reference.value.as_deref(),
            Some("PUBLIC_KEY")
        );

        let encode_keyword_key = detect(
            Language::Python,
            r#"
import jwt
def issue_access_jwt(user_id):
    claims = {"sub": user_id, "exp": expires_at}
    return jwt.encode(payload=claims, key=JWT_SECRET, algorithm="HS256")
"#,
        );
        let artifact = encode_keyword_key
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        let attributes = artifact.jwt_attributes.as_ref().expect("attributes");
        assert_eq!(
            attributes.key_reference.value.as_deref(),
            Some("JWT_SECRET")
        );
        assert!(attributes.identity_claims.is_some());
    }

    #[test]
    fn jose_uses_max_token_age_for_explicit_expiry_enforcement() {
        let output = detect(
            Language::TypeScript,
            r#"
import { jwtVerify } from "jose";
export async function verifyAccessJwt(token: string) {
  return jwtVerify(token, key, { issuer, audience, maxTokenAge: "15m" });
}
export async function verifyLegacyJwt(token: string) {
  return jwtVerify(token, key, { issuer, audience, maxAge: "15m" });
}
"#,
        );

        let access = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        assert_eq!(
            access
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::Present
        );

        let legacy = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("legacy_access_jwt"))
            .expect("legacy JWT should exist");
        assert_eq!(
            legacy
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .expiry_enforcement
                .state,
            JwtAttributeState::FrameworkDefault
        );
    }

    #[test]
    fn scoped_aliases_must_precede_the_jwt_call() {
        let output = detect(
            Language::TypeScript,
            r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "PLACEHOLDER_SECRET_DO_NOT_USE";
function unrelated() {
  const claims = { sub: otherUser, tenant_id: otherTenant };
  return claims;
}
export function issueAccessJwt(userId: string) {
  return jwt.sign(claims, JWT_SECRET, { expiresIn: "15m" });
  const claims = { sub: userId, tenant_id: tenantId };
}
export function issueRefreshJwt(userId: string) {
  const claims = { sub: userId, tenant_id: tenantId };
  return jwt.sign(claims, JWT_SECRET, { expiresIn: "7d" });
}
"#,
        );

        let access = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("access_jwt"))
            .expect("access JWT should exist");
        assert!(
            access
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .identity_claims
                .is_none()
        );

        let refresh = output
            .artifacts
            .iter()
            .find(|artifact| artifact.display_name.as_deref() == Some("refresh_jwt"))
            .expect("refresh JWT should exist");
        assert_eq!(
            refresh
                .jwt_attributes
                .as_ref()
                .expect("attributes")
                .identity_claims
                .as_ref()
                .expect("identity claims")
                .subject
                .value
                .as_deref(),
            Some("userId")
        );
    }

    #[test]
    fn detects_jsonwebtoken_namespace_and_commonjs_import_forms() {
        let namespace_output = detect(
            Language::TypeScript,
            r#"
import * as tokenLib from "jsonwebtoken";
export function issueAccessJwt(userId: string) {
  return tokenLib.sign({ sub: userId, exp: expiresAt }, JWT_SECRET);
}
"#,
        );
        assert!(namespace_output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("access_jwt")
                && !artifact.lifecycle_evidence.issue.is_empty()
        }));

        let commonjs_output = detect(
            Language::JavaScript,
            r#"
const { verify } = require("jsonwebtoken");
function verifyAccessJwt(token) {
  return verify(token, JWT_SECRET, { issuer: ISSUER, audience: AUDIENCE });
}
"#,
        );
        assert!(commonjs_output.artifacts.iter().any(|artifact| {
            artifact.display_name.as_deref() == Some("access_jwt")
                && !artifact.lifecycle_evidence.validate.is_empty()
        }));
    }

    #[test]
    fn ignores_comments_and_strings() {
        let output = detect(
            Language::TypeScript,
            r#"
// jwt.verify(token, secret)
const text = "jwt.sign(payload, secret)";
"#,
        );

        assert!(output.artifacts.is_empty());
        assert!(output.evidence.is_empty());
    }

    fn detected_text(output: &DetectionOutput) -> String {
        let excerpts = output
            .evidence
            .iter()
            .filter_map(|evidence| evidence.excerpt.as_ref())
            .map(|excerpt| excerpt.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let values = output
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.jwt_attributes.as_ref())
            .flat_map(|attributes| {
                let mut observations = vec![
                    &attributes.operation,
                    &attributes.algorithm,
                    &attributes.key_reference,
                    &attributes.issuer,
                    &attributes.audience,
                    &attributes.expiration,
                    &attributes.signature_verification,
                    &attributes.expiry_enforcement,
                ];
                if let Some(identity_claims) = &attributes.identity_claims {
                    observations.extend([
                        &identity_claims.subject,
                        &identity_claims.user_id,
                        &identity_claims.tenant_id,
                        &identity_claims.org_id,
                        &identity_claims.workspace_id,
                        &identity_claims.roles,
                        &identity_claims.scopes,
                        &identity_claims.groups,
                        &identity_claims.email,
                        &identity_claims.email_verified,
                        &identity_claims.auth_method,
                        &identity_claims.auth_class,
                    ]);
                }
                observations
            })
            .filter_map(|observation| observation.value.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        format!("{excerpts}\n{values}")
    }
}
