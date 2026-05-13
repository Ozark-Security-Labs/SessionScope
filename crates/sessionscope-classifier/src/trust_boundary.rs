use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, ArtifactId, ArtifactType, Evidence, EvidenceId, Finding, FindingCategory, ScanReport,
    Severity, TokenBoundaryAttributeState, TokenBoundaryAttributes, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut groups = token_groups(report, &evidence_by_id);
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for group in groups.values_mut() {
        group.sort();
        if let Some(finding) = classify_inbound_outbound_reuse(group, &mut seen) {
            findings.push(finding);
        }
        if let Some(finding) = classify_frontend_backend_reuse(group, &mut seen) {
            findings.push(finding);
        }
        if let Some(finding) = classify_environment_reuse(group, &mut seen) {
            findings.push(finding);
        }
        if let Some(finding) = classify_provider_boundary_review(group, &mut seen) {
            findings.push(finding);
        }
    }

    findings
}

#[derive(Clone)]
struct BoundaryGroup<'a> {
    key: String,
    artifacts: Vec<&'a Artifact>,
    evidence: Vec<&'a Evidence>,
}

impl<'a> BoundaryGroup<'a> {
    fn sort(&mut self) {
        self.artifacts.sort_by(|left, right| left.id.cmp(&right.id));
        self.artifacts.dedup_by(|left, right| left.id == right.id);
        self.evidence.sort_by(|left, right| left.id.cmp(&right.id));
        self.evidence.dedup_by(|left, right| left.id == right.id);
    }
}

fn token_groups<'a>(
    report: &'a ScanReport,
    evidence_by_id: &'a BTreeMap<&str, &'a Evidence>,
) -> BTreeMap<String, BoundaryGroup<'a>> {
    let mut groups = BTreeMap::new();
    for artifact in &report.artifacts {
        if !is_boundary_token_artifact(artifact.artifact_type) {
            continue;
        }
        let key = boundary_group_key(artifact);
        let group = groups.entry(key.clone()).or_insert_with(|| BoundaryGroup {
            key,
            artifacts: Vec::new(),
            evidence: Vec::new(),
        });
        group.artifacts.push(artifact);
        group
            .evidence
            .extend(evidence_for_artifact(artifact, evidence_by_id));
    }
    groups
}

fn classify_inbound_outbound_reuse(
    group: &BoundaryGroup<'_>,
    seen: &mut BTreeSet<(String, String)>,
) -> Option<Finding> {
    let inbound = group
        .evidence
        .iter()
        .filter(|evidence| {
            matches!(
                evidence.detector_id.as_str(),
                "bearer.read.inbound" | "query_param.read" | "query_param.read.dynamic"
            )
        })
        .copied()
        .collect::<Vec<_>>();
    let outbound = group
        .evidence
        .iter()
        .filter(|evidence| {
            matches!(
                evidence.detector_id.as_str(),
                "bearer.transmit" | "bearer.transmit.url_query"
            )
        })
        .copied()
        .collect::<Vec<_>>();
    if inbound.is_empty() || outbound.is_empty() || has_boundary_constraint(group) {
        return None;
    }

    finding(
        group,
        seen,
        "trust_boundary_inbound_outbound_reuse_review",
        Severity::Medium,
        evidence_ids(inbound.into_iter().chain(outbound).collect()),
        format!(
            "Token `{}` may cross inbound and outbound trust boundaries",
            display_name(group)
        ),
        "The same token-like artifact has inbound authentication evidence and outbound service-call evidence, but no linked audience, service, or scope boundary evidence was visible locally."
            .to_string(),
        "Use a distinct downstream service token or make audience/service/scope constraints visible in the source or provider configuration."
            .to_string(),
        "Is the inbound credential ever forwarded to another service, or is it exchanged for a bounded service token first?"
            .to_string(),
    )
}

fn classify_frontend_backend_reuse(
    group: &BoundaryGroup<'_>,
    seen: &mut BTreeSet<(String, String)>,
) -> Option<Finding> {
    if !has_frontend_context(group) || !has_backend_context(group) {
        return None;
    }

    finding(
        group,
        seen,
        "trust_boundary_frontend_backend_reuse_review",
        Severity::Low,
        boundary_or_all_evidence_ids(group),
        format!(
            "Token `{}` appears in frontend and backend contexts",
            display_name(group)
        ),
        "The same token-like artifact name appears in client-exposed and server-side contexts. Static analysis cannot prove whether the runtime credentials are separated."
            .to_string(),
        "Use distinct client and server token names/configuration, or document that the client-visible value is not a secret credential."
            .to_string(),
        "Are the frontend and backend values intentionally separate at runtime?".to_string(),
    )
}

fn classify_environment_reuse(
    group: &BoundaryGroup<'_>,
    seen: &mut BTreeSet<(String, String)>,
) -> Option<Finding> {
    let environments = boundary_values(group, |attributes| &attributes.environment);
    let environment_evidence_count = group
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == "bearer.boundary.environment")
        .count();
    if environments.len() < 2 && environment_evidence_count < 2 {
        return None;
    }

    finding(
        group,
        seen,
        "trust_boundary_environment_reuse_review",
        Severity::Low,
        boundary_or_all_evidence_ids(group),
        format!(
            "Token `{}` appears across multiple environment boundaries",
            display_name(group)
        ),
        "The same token-like artifact name appears with multiple environment hints. Static analysis cannot confirm whether production, staging, and development credentials are isolated."
            .to_string(),
        "Use environment-specific token names and secret references so reuse across production and non-production is visibly prevented."
            .to_string(),
        "Which runtime secret store guarantees these environment-specific values are separated?"
            .to_string(),
    )
}

fn classify_provider_boundary_review(
    group: &BoundaryGroup<'_>,
    seen: &mut BTreeSet<(String, String)>,
) -> Option<Finding> {
    let provider_ids = group
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == "bearer.dynamic_provider")
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();
    if provider_ids.is_empty() || has_boundary_constraint(group) {
        return None;
    }

    finding(
        group,
        seen,
        "trust_boundary_provider_scope_review",
        Severity::Low,
        provider_ids,
        format!(
            "Provider-managed token `{}` needs boundary review",
            display_name(group)
        ),
        "Provider or wrapper-managed token handling was detected without visible local audience, service, or scope boundary evidence."
            .to_string(),
        "Document the provider configuration that binds this token to the intended audience, service, tenant, and scopes."
            .to_string(),
        "Which provider setting prevents this token from being reused outside the intended boundary?"
            .to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn finding(
    group: &BoundaryGroup<'_>,
    seen: &mut BTreeSet<(String, String)>,
    rule_id: &str,
    severity: Severity,
    mut evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
) -> Option<Finding> {
    evidence_ids.sort();
    evidence_ids.dedup();
    let artifact_ids = artifact_ids(group);
    let key = (rule_id.to_string(), group.key.clone());
    if !seen.insert(key) {
        return None;
    }
    let evidence_part = evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");

    Some(Finding {
        id: stable_finding_id(&[rule_id, group.key.as_str(), evidence_part]),
        category: FindingCategory::DynamicReviewRequired,
        severity,
        artifact_ids,
        evidence_ids,
        title,
        description,
        suggested_fix: Some(suggested_fix),
        reviewer_question: Some(reviewer_question),
    })
}

fn evidence_for_artifact<'a>(
    artifact: &Artifact,
    evidence_by_id: &'a BTreeMap<&str, &'a Evidence>,
) -> Vec<&'a Evidence> {
    lifecycle_evidence_ids(artifact)
        .into_iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()).copied())
        .collect()
}

fn lifecycle_evidence_ids(artifact: &Artifact) -> Vec<&EvidenceId> {
    let mut ids = Vec::new();
    ids.extend(&artifact.lifecycle_evidence.issue);
    ids.extend(&artifact.lifecycle_evidence.store);
    ids.extend(&artifact.lifecycle_evidence.transmit);
    ids.extend(&artifact.lifecycle_evidence.validate);
    ids.extend(&artifact.lifecycle_evidence.refresh);
    ids.extend(&artifact.lifecycle_evidence.revoke);
    ids.extend(&artifact.lifecycle_evidence.expire);
    ids.extend(&artifact.lifecycle_evidence.introspect);
    ids
}

fn has_boundary_constraint(group: &BoundaryGroup<'_>) -> bool {
    group.artifacts.iter().any(|artifact| {
        artifact
            .token_boundary_attributes
            .as_ref()
            .is_some_and(|attributes| {
                is_present(&attributes.audience)
                    || is_present(&attributes.service)
                    || is_present(&attributes.scope)
                    || is_present(&attributes.tenant)
            })
    }) || group.evidence.iter().any(|evidence| {
        matches!(
            evidence.detector_id.as_str(),
            "bearer.boundary.audience"
                | "bearer.boundary.service"
                | "bearer.boundary.tenant"
                | "bearer.scope"
        )
    })
}

fn boundary_values(
    group: &BoundaryGroup<'_>,
    select: fn(&TokenBoundaryAttributes) -> &sessionscope_model::TokenBoundaryObservation,
) -> BTreeSet<String> {
    group
        .artifacts
        .iter()
        .filter_map(|artifact| artifact.token_boundary_attributes.as_ref())
        .map(select)
        .filter(|observation| is_present(observation))
        .filter_map(|observation| observation.value.clone())
        .collect()
}

fn is_present(observation: &sessionscope_model::TokenBoundaryObservation) -> bool {
    observation.state == TokenBoundaryAttributeState::Present
}

fn has_frontend_context(group: &BoundaryGroup<'_>) -> bool {
    group.artifacts.iter().any(|artifact| {
        artifact.locations.iter().any(|location| {
            let path = normalized_path(&location.path);
            path.contains("/frontend/")
                || path.contains("/client/")
                || path.contains("/public/")
                || path.contains("/browser/")
                || path.ends_with(".tsx")
        })
    }) || group.evidence.iter().any(|evidence| {
        matches!(
            evidence.detector_id.as_str(),
            "bearer.store.public_config" | "bearer.store.frontend_bundle"
        )
    })
}

fn has_backend_context(group: &BoundaryGroup<'_>) -> bool {
    group.artifacts.iter().any(|artifact| {
        artifact.locations.iter().any(|location| {
            let path = normalized_path(&location.path);
            path.contains("/server/") || path.contains("/backend/") || path.contains("/api/")
        })
    }) || group.evidence.iter().any(|evidence| {
        matches!(
            evidence.detector_id.as_str(),
            "bearer.read.inbound" | "bearer.transmit" | "bearer.validate"
        )
    })
}

fn boundary_or_all_evidence_ids(group: &BoundaryGroup<'_>) -> Vec<EvidenceId> {
    let boundary = group
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.detector_id.starts_with("bearer.boundary.")
                || matches!(
                    evidence.detector_id.as_str(),
                    "bearer.store.public_config" | "bearer.store.frontend_bundle"
                )
        })
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();
    if boundary.is_empty() {
        evidence_ids(group.evidence.clone())
    } else {
        boundary
    }
}

fn evidence_ids(evidence: Vec<&Evidence>) -> Vec<EvidenceId> {
    evidence
        .into_iter()
        .map(|evidence| evidence.id.clone())
        .collect()
}

fn artifact_ids(group: &BoundaryGroup<'_>) -> Vec<ArtifactId> {
    let mut ids = group
        .artifacts
        .iter()
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn display_name(group: &BoundaryGroup<'_>) -> String {
    group
        .artifacts
        .first()
        .and_then(|artifact| artifact.display_name.as_deref())
        .unwrap_or("token")
        .to_string()
}

fn boundary_group_key(artifact: &Artifact) -> String {
    let name = normalized_artifact_name(artifact);
    if is_generic_name(&name) {
        let path = artifact
            .locations
            .first()
            .map(|location| normalized_path(&location.path))
            .unwrap_or_default();
        format!(
            "{}:{path}:{name}",
            artifact_type_family(artifact.artifact_type)
        )
    } else {
        format!("{}:{name}", artifact_type_family(artifact.artifact_type))
    }
}

fn normalized_artifact_name(artifact: &Artifact) -> String {
    artifact
        .display_name
        .as_deref()
        .unwrap_or("token")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn is_generic_name(name: &str) -> bool {
    matches!(name, "token" | "unknown_token" | "opaque_bearer_token")
}

fn artifact_type_family(artifact_type: ArtifactType) -> &'static str {
    match artifact_type {
        ArtifactType::AccessJwt | ArtifactType::OpaqueBearerToken | ArtifactType::UnknownToken => {
            "bearer"
        }
        ArtifactType::ApiKey => "api_key",
        ArtifactType::ServiceToken => "service_token",
        _ => "token",
    }
}

fn is_boundary_token_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::AccessJwt
            | ArtifactType::RefreshJwt
            | ArtifactType::OpaqueBearerToken
            | ArtifactType::ApiKey
            | ArtifactType::ServiceToken
            | ArtifactType::UnknownToken
    )
}

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, LifecycleEvidence, LifecycleStage, SCHEMA_VERSION,
        SanitizedExcerpt, ScanSummary, SourceLocation, TokenBoundaryObservation,
    };

    use super::*;

    fn classify_artifacts(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> Vec<Finding> {
        classify(&ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts,
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        })
    }

    fn artifact(
        id: &str,
        artifact_type: ArtifactType,
        name: &str,
        path: &str,
        lifecycle_evidence: LifecycleEvidence,
        boundary: Option<TokenBoundaryAttributes>,
    ) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location(path, 1)],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: vec!["test".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: boundary,
        }
    }

    fn evidence(id: &str, detector_id: &str, stage: LifecycleStage, path: &str) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location(path, 3),
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt("redacted boundary evidence".to_string())),
            dynamic: detector_id == "bearer.dynamic_provider",
            framework_default: false,
        }
    }

    fn lifecycle(transmit: &[&str], validate: &[&str], introspect: &[&str]) -> LifecycleEvidence {
        LifecycleEvidence {
            transmit: ids(transmit),
            validate: ids(validate),
            introspect: ids(introspect),
            ..LifecycleEvidence::default()
        }
    }

    fn ids(values: &[&str]) -> Vec<EvidenceId> {
        values
            .iter()
            .map(|value| EvidenceId((*value).to_string()))
            .collect()
    }

    fn location(path: &str, line: usize) -> SourceLocation {
        SourceLocation {
            path: path.to_string(),
            line: Some(line),
            column: Some(1),
        }
    }

    fn boundary(field: &str, value: &str, evidence_id: &str) -> TokenBoundaryAttributes {
        let unknown = TokenBoundaryObservation {
            state: TokenBoundaryAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        };
        let present = TokenBoundaryObservation {
            state: TokenBoundaryAttributeState::Present,
            value: Some(value.to_string()),
            evidence_ids: vec![EvidenceId(evidence_id.to_string())],
            confidence: Confidence::High,
        };
        let mut attributes = TokenBoundaryAttributes {
            issuer: unknown.clone(),
            audience: unknown.clone(),
            service: unknown.clone(),
            environment: unknown.clone(),
            tenant: unknown.clone(),
            provider: unknown.clone(),
            scope: unknown.clone(),
            trust_boundary: unknown,
        };
        match field {
            "audience" => attributes.audience = present,
            "service" => attributes.service = present,
            "environment" => attributes.environment = present,
            "scope" => attributes.scope = present,
            _ => {}
        }
        attributes
    }

    #[test]
    fn inbound_outbound_without_boundary_is_review_required() {
        let findings = classify_artifacts(
            vec![artifact(
                "artifact_token",
                ArtifactType::OpaqueBearerToken,
                "authorization_bearer",
                "src/api/auth.ts",
                lifecycle(&["e_in", "e_out"], &[], &[]),
                None,
            )],
            vec![
                evidence(
                    "e_in",
                    "bearer.read.inbound",
                    LifecycleStage::Transmit,
                    "src/api/auth.ts",
                ),
                evidence(
                    "e_out",
                    "bearer.transmit",
                    LifecycleStage::Transmit,
                    "src/api/auth.ts",
                ),
            ],
        );

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("inbound and outbound trust boundaries")
                && finding.category == FindingCategory::DynamicReviewRequired
        }));
    }

    #[test]
    fn boundary_evidence_suppresses_inbound_outbound_review() {
        let findings = classify_artifacts(
            vec![artifact(
                "artifact_token",
                ArtifactType::OpaqueBearerToken,
                "authorization_bearer",
                "src/api/auth.ts",
                lifecycle(&["e_in", "e_out"], &[], &["e_aud"]),
                Some(boundary("audience", "internal", "e_aud")),
            )],
            vec![
                evidence(
                    "e_in",
                    "bearer.read.inbound",
                    LifecycleStage::Transmit,
                    "src/api/auth.ts",
                ),
                evidence(
                    "e_out",
                    "bearer.transmit",
                    LifecycleStage::Transmit,
                    "src/api/auth.ts",
                ),
                evidence(
                    "e_aud",
                    "bearer.boundary.audience",
                    LifecycleStage::Introspect,
                    "src/api/auth.ts",
                ),
            ],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn frontend_backend_same_name_is_review_required() {
        let findings = classify_artifacts(
            vec![
                artifact(
                    "artifact_client",
                    ArtifactType::ApiKey,
                    "api_key",
                    "src/client/app.ts",
                    lifecycle(&[], &[], &[]),
                    None,
                ),
                artifact(
                    "artifact_server",
                    ArtifactType::ApiKey,
                    "api_key",
                    "src/server/auth.ts",
                    lifecycle(&["e_out"], &[], &[]),
                    None,
                ),
            ],
            vec![evidence(
                "e_out",
                "bearer.transmit",
                LifecycleStage::Transmit,
                "src/server/auth.ts",
            )],
        );

        assert!(
            findings
                .iter()
                .any(|finding| { finding.title.contains("frontend and backend contexts") })
        );
    }

    #[test]
    fn environment_reuse_is_review_required() {
        let findings = classify_artifacts(
            vec![
                artifact(
                    "artifact_prod",
                    ArtifactType::ServiceToken,
                    "service_token",
                    "config/prod.json",
                    lifecycle(&[], &[], &["e_prod"]),
                    Some(boundary("environment", "prod", "e_prod")),
                ),
                artifact(
                    "artifact_stage",
                    ArtifactType::ServiceToken,
                    "service_token",
                    "config/staging.json",
                    lifecycle(&[], &[], &["e_stage"]),
                    Some(boundary("environment", "staging", "e_stage")),
                ),
            ],
            vec![
                evidence(
                    "e_prod",
                    "bearer.boundary.environment",
                    LifecycleStage::Introspect,
                    "config/prod.json",
                ),
                evidence(
                    "e_stage",
                    "bearer.boundary.environment",
                    LifecycleStage::Introspect,
                    "config/staging.json",
                ),
            ],
        );

        assert!(
            findings
                .iter()
                .any(|finding| { finding.title.contains("multiple environment boundaries") })
        );
    }

    #[test]
    fn provider_wrapper_without_scope_is_review_required_once() {
        let findings = classify_artifacts(
            vec![artifact(
                "artifact_provider",
                ArtifactType::ServiceToken,
                "service_token",
                "src/provider.ts",
                lifecycle(&["e_provider", "e_provider"], &[], &[]),
                None,
            )],
            vec![evidence(
                "e_provider",
                "bearer.dynamic_provider",
                LifecycleStage::Transmit,
                "src/provider.ts",
            )],
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Provider-managed"))
                .count(),
            1
        );
    }
}
