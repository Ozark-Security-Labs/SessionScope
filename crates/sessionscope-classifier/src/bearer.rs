use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, ArtifactType, Evidence, EvidenceId, Finding, FindingCategory, LifecycleEvidence,
    LifecycleStage, ScanReport, Severity, stable_finding_id,
};

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();

    for context in token_contexts(report, &evidence_by_id) {
        let high_evidence = high_confidence_evidence_ids(&context);
        findings.extend(classify_deterministic_risks(&context));
        findings.extend(classify_missing_validation(&context, report));
        findings.extend(classify_issue_without_expiry(&context, report));
        findings.extend(classify_missing_rotation_or_revocation(&context, report));
        findings.extend(classify_missing_scope(&context, report));
        findings.extend(classify_dynamic_review(&context, &high_evidence));
    }

    findings
}

struct TokenContext<'a> {
    artifact: &'a Artifact,
    evidence: Vec<&'a Evidence>,
}

fn token_contexts<'a>(
    report: &'a ScanReport,
    evidence_by_id: &'a BTreeMap<&str, &'a Evidence>,
) -> Vec<TokenContext<'a>> {
    let mut contexts = BTreeMap::<&str, TokenContext<'a>>::new();

    for artifact in &report.artifacts {
        if !is_bearer_like_artifact(artifact.artifact_type) {
            continue;
        }

        let context = contexts
            .entry(artifact.id.0.as_str())
            .or_insert_with(|| TokenContext {
                artifact,
                evidence: Vec::new(),
            });
        context
            .evidence
            .extend(evidence_for_artifact(artifact, evidence_by_id));
    }

    for context in contexts.values_mut() {
        context
            .evidence
            .sort_by(|left, right| left.id.cmp(&right.id));
        context.evidence.dedup_by(|left, right| left.id == right.id);
    }

    contexts.into_values().collect()
}

fn classify_deterministic_risks(context: &TokenContext<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for evidence in &context.evidence {
        match evidence.detector_id.as_str() {
            "bearer.transmit.url_query" => findings.push(finding(
                "bearer_token_in_url_query",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                context.artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` is transmitted in a URL query parameter",
                    artifact_name(context.artifact)
                ),
                "Bearer/API-key token evidence appears in a URL query parameter, which can be logged, cached, or forwarded outside the intended trust boundary."
                    .to_string(),
                "Transmit tokens in headers or another channel that is not embedded in URLs."
                    .to_string(),
                "Can this token be moved out of query parameters on every request path?"
                    .to_string(),
            )),
            "bearer.store.browser" => findings.push(finding(
                "bearer_token_browser_storage",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                context.artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` is stored in browser storage",
                    artifact_name(context.artifact)
                ),
                "Bearer/API-key or session-like token evidence is stored in localStorage or sessionStorage, where browser JavaScript can read it."
                    .to_string(),
                "Use an HttpOnly cookie or another storage pattern that prevents direct script access when possible."
                    .to_string(),
                "Is this token intended to be readable by browser JavaScript?".to_string(),
            )),
            "bearer.literal.static" => findings.push(finding(
                "bearer_static_secret_literal",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                context.artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` has static secret-like literal evidence",
                    artifact_name(context.artifact)
                ),
                "Source evidence contains a static token/API-key style literal. The value is redacted in reports, but the code path should not carry runtime secrets in source."
                    .to_string(),
                "Move runtime token values to approved secret storage and keep source/config references value-free."
                    .to_string(),
                "Is this placeholder-only fixture code, or can production source contain a token value here?"
                    .to_string(),
            )),
            "bearer.store.public_config" => findings.push(finding(
                "bearer_public_runtime_config_exposure",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                context.artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` is exposed through public runtime config",
                    artifact_name(context.artifact)
                ),
                "Token/API-key evidence appears in public runtime or client-exposed configuration, making it available to browser-side code or generated bundles."
                    .to_string(),
                "Move token material and non-public API keys to server-only configuration or proxy the operation through trusted server code."
                    .to_string(),
                "Is this configuration key intentionally exposed to client-side code?".to_string(),
            )),
            "bearer.store.frontend_bundle" => findings.push(finding(
                "bearer_frontend_bundle_exposure",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                context.artifact,
                vec![evidence.id.clone()],
                format!(
                    "Token `{}` is referenced from frontend bundle code",
                    artifact_name(context.artifact)
                ),
                "Token/API-key evidence appears in browser or frontend bundle code, where compiled assets can expose the token path or value."
                    .to_string(),
                "Keep token handling in server-side code and expose only least-privilege, non-secret client identifiers when necessary."
                    .to_string(),
                "Can this token flow be moved behind a server-side boundary?".to_string(),
            )),
            _ => {}
        }
    }

    findings
}

fn classify_missing_validation(context: &TokenContext<'_>, report: &ScanReport) -> Option<Finding> {
    let inbound_ids = context
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == "bearer.read.inbound")
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();

    if inbound_ids.is_empty()
        || context_has_stage(context, LifecycleStage::Validate)
        || has_related_stage(context.artifact, report, LifecycleStage::Validate)
    {
        return None;
    }

    Some(finding(
        "bearer_missing_validation",
        FindingCategory::MissingValidationEvidence,
        Severity::Medium,
        context.artifact,
        inbound_ids,
        format!(
            "Inbound token `{}` is read without linked validation evidence",
            artifact_name(context.artifact)
        ),
        "Inbound bearer/API-key evidence was detected, but no local validation, lookup, or compare evidence was linked for the same token artifact."
            .to_string(),
        "Add or identify source-bound validation evidence before the token is trusted."
            .to_string(),
        "Where is this inbound token checked before it authorizes access?".to_string(),
    ))
}

fn classify_issue_without_expiry(
    context: &TokenContext<'_>,
    report: &ScanReport,
) -> Option<Finding> {
    let artifact = context.artifact;
    if !matches!(
        artifact.artifact_type,
        ArtifactType::ApiKey | ArtifactType::ServiceToken
    ) || !has_local_lifecycle_evidence(context)
        || context_has_stage(context, LifecycleStage::Expire)
        || has_related_stage(artifact, report, LifecycleStage::Expire)
    {
        return None;
    }

    Some(finding(
        "bearer_issue_without_expiry",
        FindingCategory::LifecycleGap,
        Severity::Low,
        artifact,
        lifecycle_evidence_ids_for_context(context, &[LifecycleStage::Issue, LifecycleStage::Store]),
        format!(
            "Token `{}` has no linked expiry evidence",
            artifact_name(artifact)
        ),
        "Service/API token issue or persistence evidence was detected without linked expiry or TTL evidence."
            .to_string(),
        "Set an explicit expiry or rotation policy for issued service/API tokens.".to_string(),
        "What effective lifetime does this issued token have?".to_string(),
    ))
}

fn classify_missing_rotation_or_revocation(
    context: &TokenContext<'_>,
    report: &ScanReport,
) -> Option<Finding> {
    let artifact = context.artifact;
    if !matches!(
        artifact.artifact_type,
        ArtifactType::ApiKey | ArtifactType::ServiceToken
    ) || !has_local_lifecycle_evidence(context)
        || context_has_stage(context, LifecycleStage::Refresh)
        || context_has_stage(context, LifecycleStage::Revoke)
        || has_related_stage(artifact, report, LifecycleStage::Refresh)
        || has_related_stage(artifact, report, LifecycleStage::Revoke)
    {
        return None;
    }

    Some(finding(
        "bearer_missing_rotation_or_revocation",
        FindingCategory::LifecycleGap,
        Severity::Low,
        artifact,
        lifecycle_evidence_ids_for_context(context, &[LifecycleStage::Issue, LifecycleStage::Store]),
        format!(
            "Token `{}` has no linked rotation or revocation evidence",
            artifact_name(artifact)
        ),
        "Service/API token issue or persistence evidence was detected without linked rotation, regeneration, disable, or revoke evidence."
            .to_string(),
        "Document and implement a rotation and revocation path for long-lived service/API tokens."
            .to_string(),
        "How can this token be rotated or revoked when access changes?".to_string(),
    ))
}

fn classify_missing_scope(context: &TokenContext<'_>, report: &ScanReport) -> Option<Finding> {
    let artifact = context.artifact;
    if !matches!(
        artifact.artifact_type,
        ArtifactType::ApiKey | ArtifactType::ServiceToken | ArtifactType::OpaqueBearerToken
    ) || !(context_has_stage(context, LifecycleStage::Issue)
        || context_has_detector(context, "bearer.transmit"))
        || context_has_detector(context, "bearer.scope")
        || has_related_detector(artifact, report, "bearer.scope")
    {
        return None;
    }

    Some(finding(
        "bearer_missing_scope_evidence",
        FindingCategory::MissingValidationEvidence,
        Severity::Low,
        artifact,
        lifecycle_evidence_ids_for_context(context, &[LifecycleStage::Issue, LifecycleStage::Transmit]),
        format!(
            "Token `{}` has no linked scope evidence",
            artifact_name(artifact)
        ),
        "Token issuance or forwarding evidence was detected without visible scope, audience, or permission evidence in the local source."
            .to_string(),
        "Bind tokens to the narrowest available scope or document the upstream provider policy when scope is external."
            .to_string(),
        "Where are this token's audience, scope, or permissions constrained?".to_string(),
    ))
}

fn classify_dynamic_review(
    context: &TokenContext<'_>,
    high_evidence: &BTreeSet<EvidenceId>,
) -> Option<Finding> {
    let ids = context
        .evidence
        .iter()
        .filter(|evidence| {
            !high_evidence.contains(&evidence.id)
                && (evidence.detector_id == "bearer.dynamic_provider"
                    || evidence.detector_id == "bearer.store.config"
                    || (evidence.detector_id == "bearer.transmit"
                        && server_to_server_needs_review(context))
                    || evidence.dynamic)
        })
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();

    if ids.is_empty() {
        return None;
    }

    Some(finding(
        "bearer_dynamic_provider_review",
        FindingCategory::DynamicReviewRequired,
        Severity::Low,
        context.artifact,
        ids,
        format!(
            "Token `{}` has provider-managed or dynamic handling",
            artifact_name(context.artifact)
        ),
        "Bearer/API-key behavior appears dynamic, provider-managed, config-driven, or server-to-server only, so the static evidence should be reviewed before treating lifecycle controls as deterministic."
            .to_string(),
        "Document the provider, wrapper, or server-side policy for issuance, storage, validation, scope, expiry, rotation, and revocation."
            .to_string(),
        "Which runtime configuration or provider settings govern this token lifecycle?".to_string(),
    ))
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

fn high_confidence_evidence_ids(context: &TokenContext<'_>) -> BTreeSet<EvidenceId> {
    context
        .evidence
        .iter()
        .filter(|evidence| {
            matches!(
                evidence.detector_id.as_str(),
                "bearer.transmit.url_query"
                    | "bearer.store.browser"
                    | "bearer.literal.static"
                    | "bearer.store.public_config"
                    | "bearer.store.frontend_bundle"
            )
        })
        .map(|evidence| evidence.id.clone())
        .collect()
}

fn context_has_stage(context: &TokenContext<'_>, stage: LifecycleStage) -> bool {
    context
        .evidence
        .iter()
        .any(|evidence| evidence.lifecycle_stage == stage)
}

fn context_has_detector(context: &TokenContext<'_>, detector_id: &str) -> bool {
    context
        .evidence
        .iter()
        .any(|evidence| evidence.detector_id == detector_id)
}

fn server_to_server_needs_review(context: &TokenContext<'_>) -> bool {
    context_has_detector(context, "bearer.transmit")
        && !(context_has_detector(context, "bearer.scope")
            && context_has_stage(context, LifecycleStage::Expire)
            && (context_has_stage(context, LifecycleStage::Refresh)
                || context_has_stage(context, LifecycleStage::Revoke)))
}

fn has_local_lifecycle_evidence(context: &TokenContext<'_>) -> bool {
    context.evidence.iter().any(|evidence| {
        matches!(
            evidence.lifecycle_stage,
            LifecycleStage::Issue | LifecycleStage::Store
        ) && !matches!(
            evidence.detector_id.as_str(),
            "bearer.store.browser"
                | "bearer.store.public_config"
                | "bearer.store.frontend_bundle"
                | "bearer.literal.static"
        )
    })
}

fn lifecycle_evidence_ids_for_context(
    context: &TokenContext<'_>,
    stages: &[LifecycleStage],
) -> Vec<EvidenceId> {
    context
        .evidence
        .iter()
        .filter(|evidence| stages.contains(&evidence.lifecycle_stage))
        .map(|evidence| evidence.id.clone())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    category: FindingCategory,
    severity: Severity,
    artifact: &Artifact,
    mut evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
) -> Finding {
    evidence_ids.sort();
    evidence_ids.dedup();
    let evidence_part = evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let name_part = artifact.display_name.as_deref().unwrap_or("dynamic");
    let id = stable_finding_id(&[rule_id, artifact.id.0.as_str(), evidence_part, name_part]);

    Finding {
        id,
        category,
        severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids,
        title,
        description,
        suggested_fix: Some(suggested_fix),
        reviewer_question: Some(reviewer_question),
    }
}

fn artifact_name(artifact: &Artifact) -> &str {
    artifact.display_name.as_deref().unwrap_or("token")
}

fn is_bearer_like_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::OpaqueBearerToken
            | ArtifactType::ApiKey
            | ArtifactType::ServiceToken
            | ArtifactType::UnknownToken
    )
}

fn has_related_stage(artifact: &Artifact, report: &ScanReport, stage: LifecycleStage) -> bool {
    report.artifacts.iter().any(|candidate| {
        is_related_token_artifact(artifact, candidate)
            && !lifecycle_ids_for_stage(&candidate.lifecycle_evidence, stage).is_empty()
    })
}

fn has_related_detector(artifact: &Artifact, report: &ScanReport, detector_id: &str) -> bool {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();

    report.artifacts.iter().any(|candidate| {
        is_related_token_artifact(artifact, candidate)
            && evidence_for_artifact(candidate, &evidence_by_id)
                .iter()
                .any(|evidence| evidence.detector_id == detector_id)
    })
}

fn is_related_token_artifact(left: &Artifact, right: &Artifact) -> bool {
    if !is_bearer_like_artifact(left.artifact_type) || !is_bearer_like_artifact(right.artifact_type)
    {
        return false;
    }

    left.id == right.id
        || (left.display_name.is_some()
            && left.display_name == right.display_name
            && related_artifact_context(left, right))
}

fn related_artifact_context(left: &Artifact, right: &Artifact) -> bool {
    let same_framework = left
        .framework_hints
        .iter()
        .any(|hint| right.framework_hints.contains(hint));
    if same_framework {
        return true;
    }

    match (first_path_prefix(left), first_path_prefix(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn first_path_prefix(artifact: &Artifact) -> Option<String> {
    let path = artifact.locations.first()?.path.replace('\\', "/");
    let mut parts = path.split('/').filter(|part| !part.is_empty());
    let first = parts.next()?;
    let second = parts.next();
    Some(match second {
        Some(second) => format!("{first}/{second}"),
        None => first.to_string(),
    })
}

fn lifecycle_ids_for_stage(
    lifecycle_evidence: &LifecycleEvidence,
    stage: LifecycleStage,
) -> &[EvidenceId] {
    match stage {
        LifecycleStage::Issue => &lifecycle_evidence.issue,
        LifecycleStage::Store => &lifecycle_evidence.store,
        LifecycleStage::Transmit => &lifecycle_evidence.transmit,
        LifecycleStage::Validate => &lifecycle_evidence.validate,
        LifecycleStage::Refresh => &lifecycle_evidence.refresh,
        LifecycleStage::Revoke => &lifecycle_evidence.revoke,
        LifecycleStage::Expire => &lifecycle_evidence.expire,
        LifecycleStage::Introspect => &lifecycle_evidence.introspect,
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Confidence, SCHEMA_VERSION, SanitizedExcerpt, ScanSummary, SourceLocation,
    };

    use super::*;

    fn classify_artifact(artifact: Artifact, evidence: Vec<Evidence>) -> Vec<Finding> {
        classify_artifacts(vec![artifact], evidence)
    }

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
        artifact_type: ArtifactType,
        name: &str,
        lifecycle_evidence: LifecycleEvidence,
    ) -> Artifact {
        Artifact {
            id: ArtifactId(format!("artifact_{name}")),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location(1)],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: vec!["test".to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn evidence(id: &str, detector_id: &str, stage: LifecycleStage) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location(3),
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt::from_sanitized(
                "redacted context".to_string(),
            )),
            dynamic: detector_id == "bearer.dynamic_provider",
            framework_default: false,
        }
    }

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            path: "app.ts".to_string(),
            line: Some(line),
            column: Some(1),
        }
    }

    #[test]
    fn url_query_and_browser_storage_are_high_confidence() {
        let artifact = artifact(
            ArtifactType::ApiKey,
            "api_key",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_url".to_string())],
                store: vec![EvidenceId("evidence_browser".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![
                evidence(
                    "evidence_url",
                    "bearer.transmit.url_query",
                    LifecycleStage::Transmit,
                ),
                evidence(
                    "evidence_browser",
                    "bearer.store.browser",
                    LifecycleStage::Store,
                ),
            ],
        );

        assert_eq!(
            findings
                .iter()
                .filter(
                    |finding| finding.category == FindingCategory::HighConfidenceMisconfiguration
                )
                .count(),
            2
        );
    }

    #[test]
    fn inbound_read_without_validate_is_missing_validation() {
        let artifact = artifact(
            ArtifactType::OpaqueBearerToken,
            "authorization_bearer",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_read".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_read",
                "bearer.read.inbound",
                LifecycleStage::Transmit,
            )],
        );

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::MissingValidationEvidence
                && finding.title.contains("without linked validation")
        }));
    }

    #[test]
    fn issued_service_token_without_expiry_is_lifecycle_gap() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_issue",
                "bearer.issue",
                LifecycleStage::Issue,
            )],
        );

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap && finding.severity == Severity::Low
        }));
    }

    #[test]
    fn dynamic_provider_is_review_required() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_provider".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_provider",
                "bearer.dynamic_provider",
                LifecycleStage::Transmit,
            )],
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == FindingCategory::DynamicReviewRequired)
        );
    }

    #[test]
    fn public_config_frontend_bundle_and_static_literals_are_high_confidence() {
        let artifact = artifact(
            ArtifactType::ApiKey,
            "api_key",
            LifecycleEvidence {
                store: vec![
                    EvidenceId("evidence_public".to_string()),
                    EvidenceId("evidence_frontend".to_string()),
                    EvidenceId("evidence_static".to_string()),
                ],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![
                evidence(
                    "evidence_public",
                    "bearer.store.public_config",
                    LifecycleStage::Store,
                ),
                evidence(
                    "evidence_frontend",
                    "bearer.store.frontend_bundle",
                    LifecycleStage::Store,
                ),
                evidence(
                    "evidence_static",
                    "bearer.literal.static",
                    LifecycleStage::Store,
                ),
            ],
        );

        assert_eq!(
            findings
                .iter()
                .filter(
                    |finding| finding.category == FindingCategory::HighConfidenceMisconfiguration
                )
                .count(),
            3
        );
    }

    #[test]
    fn issued_service_token_reports_rotation_and_scope_gaps() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![evidence(
                "evidence_issue",
                "bearer.issue",
                LifecycleStage::Issue,
            )],
        );

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("rotation or revocation")
        }));
        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::MissingValidationEvidence
                && finding.title.contains("scope")
        }));
    }

    #[test]
    fn dynamic_config_and_incomplete_server_forwarding_are_review_required() {
        let artifact = artifact(
            ArtifactType::ApiKey,
            "api_key",
            LifecycleEvidence {
                store: vec![EvidenceId("evidence_config".to_string())],
                transmit: vec![EvidenceId("evidence_transmit".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![
                evidence(
                    "evidence_config",
                    "bearer.store.config",
                    LifecycleStage::Store,
                ),
                evidence(
                    "evidence_transmit",
                    "bearer.transmit",
                    LifecycleStage::Transmit,
                ),
            ],
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == FindingCategory::DynamicReviewRequired)
        );
    }

    #[test]
    fn complete_server_side_usage_has_no_bearer_finding() {
        let artifact = artifact(
            ArtifactType::ServiceToken,
            "service_token",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                store: vec![EvidenceId("evidence_store".to_string())],
                transmit: vec![EvidenceId("evidence_transmit".to_string())],
                validate: vec![
                    EvidenceId("evidence_validate".to_string()),
                    EvidenceId("evidence_scope".to_string()),
                ],
                expire: vec![EvidenceId("evidence_expire".to_string())],
                refresh: vec![EvidenceId("evidence_rotate".to_string())],
                revoke: vec![EvidenceId("evidence_revoke".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifact(
            artifact,
            vec![
                evidence("evidence_issue", "bearer.issue", LifecycleStage::Issue),
                evidence("evidence_store", "bearer.store", LifecycleStage::Store),
                evidence(
                    "evidence_transmit",
                    "bearer.transmit",
                    LifecycleStage::Transmit,
                ),
                evidence(
                    "evidence_validate",
                    "bearer.validate",
                    LifecycleStage::Validate,
                ),
                evidence("evidence_scope", "bearer.scope", LifecycleStage::Validate),
                evidence("evidence_expire", "bearer.expire", LifecycleStage::Expire),
                evidence("evidence_rotate", "bearer.rotate", LifecycleStage::Refresh),
                evidence("evidence_revoke", "bearer.revoke", LifecycleStage::Revoke),
            ],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn duplicate_artifact_records_do_not_duplicate_findings() {
        let artifact = artifact(
            ArtifactType::ApiKey,
            "api_key",
            LifecycleEvidence {
                transmit: vec![EvidenceId("evidence_url".to_string())],
                ..LifecycleEvidence::default()
            },
        );
        let findings = classify_artifacts(
            vec![artifact.clone(), artifact],
            vec![evidence(
                "evidence_url",
                "bearer.transmit.url_query",
                LifecycleStage::Transmit,
            )],
        );

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("URL query"))
                .count(),
            1
        );
    }
}
