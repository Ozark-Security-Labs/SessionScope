use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, ArtifactType, Confidence, CookieAttributeState, Evidence, EvidenceId, Finding,
    FindingCategory, LifecycleEvidence, LifecyclePath, LifecyclePathStep, LifecycleStage,
    ScanReport, Severity, SourceLocation, stable_finding_id, stable_lifecycle_path_id,
};

const STAGES: [LifecycleStage; 8] = LifecycleStage::ORDERED;
const REFRESH_LINK_MAX_LINE_DISTANCE: usize = 80;

pub fn link(report: &ScanReport) -> Vec<LifecyclePath> {
    let evidence_by_id = evidence_by_id(report);
    let mut paths = report
        .artifacts
        .iter()
        .filter_map(|artifact| path_for_artifact(artifact, &evidence_by_id))
        .collect::<Vec<_>>();
    merge_revoke_only_paths(report, &evidence_by_id, &mut paths);
    merge_query_param_paths(report, &evidence_by_id, &mut paths);
    merge_refresh_paths(report, &evidence_by_id, &mut paths);
    sort_paths(&mut paths);
    paths
}

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    let evidence_by_id = evidence_by_id(report);

    for path in &report.lifecycle_paths {
        let Some(artifact) = artifact_for_path(report, path) else {
            continue;
        };

        findings.extend(classify_issue_without_validate(artifact, path));
        findings.extend(classify_refresh_without_revoke(
            artifact,
            path,
            &evidence_by_id,
        ));
        findings.extend(classify_reset_without_expiry(artifact, path));
        findings.extend(classify_reset_without_single_use(artifact, path));
        findings.extend(classify_clear_cookie_only_logout(
            artifact,
            path,
            &evidence_by_id,
        ));
        findings.extend(classify_cookie_clear_attribute_mismatch(
            artifact,
            path,
            &evidence_by_id,
        ));
        findings.extend(classify_jwt_denylist_absent_on_logout(
            artifact,
            path,
            report,
            &evidence_by_id,
        ));
        findings.extend(classify_refresh_family_revocation_absent_on_logout(
            artifact,
            path,
            report,
            &evidence_by_id,
        ));
        findings.extend(classify_sliding_expiry_without_rotation(
            artifact,
            path,
            report,
            &evidence_by_id,
        ));
        findings.extend(classify_password_change_global_revocation_absent(
            artifact,
            path,
            report,
            &evidence_by_id,
        ));
    }

    findings
}

struct FindingSpec {
    rule_id: &'static str,
    category: FindingCategory,
    severity: Severity,
    evidence_ids: Vec<EvidenceId>,
    title: String,
    description: String,
    suggested_fix: String,
    reviewer_question: String,
}

fn merge_revoke_only_paths(
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    paths: &mut Vec<LifecyclePath>,
) {
    let artifact_by_id = artifact_by_id(report);
    let mut absorbed = BTreeSet::new();

    for source_index in 0..paths.len() {
        if !is_revoke_only_path(&paths[source_index]) {
            continue;
        }
        let Some(source_artifact) =
            artifact_for_path_with_lookup(&artifact_by_id, &paths[source_index])
        else {
            continue;
        };

        let target_index = (0..paths.len()).find(|target_index| {
            *target_index != source_index
                && !absorbed.contains(target_index)
                && artifact_for_path_with_lookup(&artifact_by_id, &paths[*target_index])
                    .is_some_and(|target_artifact| {
                        revoke_paths_are_linkable(
                            source_artifact,
                            target_artifact,
                            &paths[source_index],
                            &paths[*target_index],
                            evidence_by_id,
                        )
                    })
        });

        let Some(target_index) = target_index else {
            continue;
        };

        let source_path = paths[source_index].clone();
        merge_path(&source_path, &mut paths[target_index]);
        refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut paths[target_index]);
        absorbed.insert(source_index);
    }

    if !absorbed.is_empty() {
        let mut index = 0usize;
        paths.retain(|_| {
            let keep = !absorbed.contains(&index);
            index += 1;
            keep
        });
    }
}

fn merge_refresh_paths(
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    paths: &mut Vec<LifecyclePath>,
) {
    let artifact_by_id = artifact_by_id(report);
    let mut absorbed = BTreeSet::new();

    for target_index in 0..paths.len() {
        if absorbed.contains(&target_index)
            || !is_refresh_path(&artifact_by_id, &paths[target_index])
        {
            continue;
        }

        for source_index in (target_index + 1)..paths.len() {
            if absorbed.contains(&source_index)
                || !is_refresh_path(&artifact_by_id, &paths[source_index])
            {
                continue;
            }

            let Some(target_artifact) =
                artifact_for_path_with_lookup(&artifact_by_id, &paths[target_index])
            else {
                continue;
            };
            let Some(source_artifact) =
                artifact_for_path_with_lookup(&artifact_by_id, &paths[source_index])
            else {
                continue;
            };

            if compatible_refresh_artifacts(source_artifact, target_artifact)
                && paths_have_linkable_source_context(
                    &paths[source_index],
                    &paths[target_index],
                    evidence_by_id,
                )
            {
                let source_path = paths[source_index].clone();
                merge_path(&source_path, &mut paths[target_index]);
                absorbed.insert(source_index);
            }
        }

        refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut paths[target_index]);
    }

    if !absorbed.is_empty() {
        let mut index = 0usize;
        paths.retain(|_| {
            let keep = !absorbed.contains(&index);
            index += 1;
            keep
        });
    }
}

fn merge_query_param_paths(
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    paths: &mut Vec<LifecyclePath>,
) {
    let artifact_by_id = artifact_by_id(report);
    let mut absorbed = BTreeSet::new();

    for source_index in 0..paths.len() {
        if absorbed.contains(&source_index)
            || !is_query_param_transmit_path(&paths[source_index], evidence_by_id)
        {
            continue;
        }

        let Some(source_artifact) =
            artifact_for_path_with_lookup(&artifact_by_id, &paths[source_index])
        else {
            continue;
        };

        let target_index = (0..paths.len()).find(|target_index| {
            *target_index != source_index
                && !absorbed.contains(target_index)
                && !is_query_param_transmit_path(&paths[*target_index], evidence_by_id)
                && artifact_for_path_with_lookup(&artifact_by_id, &paths[*target_index])
                    .is_some_and(|target_artifact| {
                        compatible_query_param_artifacts(source_artifact, target_artifact)
                            && paths_have_linkable_source_context(
                                &paths[source_index],
                                &paths[*target_index],
                                evidence_by_id,
                            )
                    })
        });

        let Some(target_index) = target_index else {
            continue;
        };

        let source_path = paths[source_index].clone();
        merge_path(&source_path, &mut paths[target_index]);
        refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut paths[target_index]);
        absorbed.insert(source_index);
    }

    if !absorbed.is_empty() {
        let mut index = 0usize;
        paths.retain(|_| {
            let keep = !absorbed.contains(&index);
            index += 1;
            keep
        });
    }
}

pub fn sort_paths(paths: &mut [LifecyclePath]) {
    for path in paths.iter_mut() {
        path.artifact_ids.sort();
        for step in &mut path.stages {
            step.evidence_ids.sort();
            step.evidence_ids.dedup();
        }
        path.stages.sort_by_key(|step| step.stage);
    }

    paths.sort_by(|left, right| {
        left.artifact_ids
            .cmp(&right.artifact_ids)
            .then_with(|| left.stages.cmp(&right.stages))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn path_for_artifact(
    artifact: &Artifact,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<LifecyclePath> {
    let mut stages = Vec::new();
    let mut all_evidence_ids = Vec::new();
    let mut evidence_locations = Vec::new();
    let mut confidence = artifact.confidence;
    let mut dynamic = false;
    let mut framework_default = false;

    for stage in STAGES {
        let mut evidence_ids = lifecycle_ids_for_stage(&artifact.lifecycle_evidence, stage);
        evidence_ids.sort();
        evidence_ids.dedup();
        if evidence_ids.is_empty() {
            continue;
        }

        for evidence_id in &evidence_ids {
            all_evidence_ids.push(evidence_id.clone());
            if let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) {
                confidence = min_confidence(confidence, evidence.confidence);
                dynamic |= evidence.dynamic;
                framework_default |= evidence.framework_default;
                evidence_locations.push(location_part(&evidence.location));
            }
        }

        stages.push(LifecyclePathStep {
            stage,
            evidence_ids,
        });
    }

    if stages.is_empty() {
        return None;
    }

    all_evidence_ids.sort();
    all_evidence_ids.dedup();
    evidence_locations.sort();
    evidence_locations.dedup();

    let mut id_parts = vec![
        "lifecycle_path".to_string(),
        artifact.id.0.clone(),
        artifact_type_part(artifact.artifact_type).to_string(),
    ];
    id_parts.extend(
        stages
            .iter()
            .map(|step| format_stage(step.stage).to_string()),
    );
    id_parts.extend(all_evidence_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(evidence_locations);

    let mut path = LifecyclePath {
        id: stable_lifecycle_path_id(&id_parts),
        artifact_ids: vec![artifact.id.clone()],
        stages,
        confidence,
        dynamic,
        reviewer_question: reviewer_question_for_path(dynamic, framework_default, artifact),
    };
    let artifact_by_id = [(artifact.id.0.as_str(), artifact)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    refresh_path_metadata(&artifact_by_id, evidence_by_id, &mut path);
    Some(path)
}

fn classify_issue_without_validate(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !is_jwt_artifact(artifact.artifact_type)
        || !has_stage(path, LifecycleStage::Issue)
        || has_stage(path, LifecycleStage::Validate)
    {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("JWT");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_issue_without_validate",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            evidence_ids: evidence_ids_for_stage(path, LifecycleStage::Issue),
            title: format!("JWT `{name}` is issued without linked validation evidence"),
            description: "JWT issue evidence was linked into a lifecycle path, but no validation evidence was linked for the same artifact."
                .to_string(),
            suggested_fix:
                "Add or identify verification evidence that validates this token before claims are trusted."
                    .to_string(),
            reviewer_question: "Where is this issued JWT validated before use?".to_string(),
        },
    ))
}

fn classify_refresh_without_revoke(
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !has_stage(path, LifecycleStage::Refresh) || has_server_revoke(path, evidence_by_id) {
        return None;
    }

    if !is_refresh_artifact(artifact) && !has_refresh_detector_evidence(path, evidence_by_id) {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("token");
    if has_dynamic_or_provider_refresh(path, evidence_by_id) {
        return Some(finding(
            artifact,
            path,
            FindingSpec {
                rule_id: "lifecycle_refresh_dynamic_review",
                category: FindingCategory::DynamicReviewRequired,
                severity: Severity::Low,
                evidence_ids: evidence_ids_for_stage(path, LifecycleStage::Refresh),
                title: format!(
                    "Token `{name}` has dynamic refresh behavior without linked revocation evidence"
                ),
                description: "Refresh lifecycle evidence appears provider-managed or dynamic, and no deterministic source-bound revoke or rotation evidence was linked for the same artifact."
                    .to_string(),
                suggested_fix:
                    "Confirm the provider or runtime refresh policy rotates or revokes previous refresh tokens."
                        .to_string(),
                reviewer_question: format!(
                    "Which provider setting or runtime path revokes previous refresh tokens for `{name}`?"
                ),
            },
        ));
    }

    let reviewer_question = if has_client_cookie_clear(path, evidence_by_id) {
        "Where is the previous refresh token revoked or marked used server-side, beyond clearing the client cookie?"
    } else {
        "Where is the previous refresh token revoked or marked used during refresh?"
    };
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_refresh_without_revoke",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            evidence_ids: evidence_ids_for_stage(path, LifecycleStage::Refresh),
            title: format!("Token `{name}` has refresh evidence without linked revocation evidence"),
            description: "Refresh lifecycle evidence was linked, but no source-bound revoke or rotation evidence was linked for the same artifact."
                .to_string(),
            suggested_fix:
                "Rotate refresh tokens and revoke the previous token when issuing a replacement."
                    .to_string(),
            reviewer_question: reviewer_question.to_string(),
        },
    ))
}

fn has_refresh_detector_evidence(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Refresh)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id.starts_with("refresh."))
        })
}

fn classify_reset_without_single_use(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::PasswordResetToken | ArtifactType::EmailVerificationToken
    ) || !has_stage(path, LifecycleStage::Issue)
        || has_stage(path, LifecycleStage::Revoke)
    {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("reset token");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_reset_without_single_use",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Low,
            evidence_ids: fallback_path_ids(path),
            title: format!("Token `{name}` has no linked single-use or revocation evidence"),
            description: "Reset or verification token evidence was linked, but no source-bound single-use, consume, or revocation evidence was linked for the same artifact."
                .to_string(),
            suggested_fix:
                "Store reset and verification tokens with expiry and mark them consumed after successful use."
                    .to_string(),
            reviewer_question:
                "Where is this reset or verification token consumed so it cannot be reused?"
                    .to_string(),
        },
    ))
}

fn classify_reset_without_expiry(artifact: &Artifact, path: &LifecyclePath) -> Option<Finding> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::PasswordResetToken | ArtifactType::EmailVerificationToken
    ) || !has_stage(path, LifecycleStage::Issue)
        || has_stage(path, LifecycleStage::Expire)
    {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("reset token");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_reset_without_expiry",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Low,
            evidence_ids: fallback_path_ids(path),
            title: format!("Token `{name}` has no linked expiry evidence"),
            description: "Reset or verification token evidence was linked, but no source-bound expiry or TTL evidence was linked for the same artifact."
                .to_string(),
            suggested_fix: "Store reset and verification tokens with a short expiry."
                .to_string(),
            reviewer_question: "Where is this reset or verification token expired?".to_string(),
        },
    ))
}

fn classify_clear_cookie_only_logout(
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !has_client_cookie_clear(path, evidence_by_id) || has_server_revoke(path, evidence_by_id) {
        return None;
    }
    if !matches!(
        artifact.artifact_type,
        ArtifactType::SessionCookie
            | ArtifactType::SignedCookie
            | ArtifactType::SessionRecord
            | ArtifactType::RefreshJwt
            | ArtifactType::Unknown
    ) {
        return None;
    }

    let name = artifact.display_name.as_deref().unwrap_or("session");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_clear_cookie_only_logout",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Low,
            evidence_ids: client_cookie_clear_ids(path, evidence_by_id),
            title: format!("Cookie `{name}` is cleared on logout without linked server-side revocation"),
            description: "Logout evidence clears a client-side cookie, but no linked server-side session, token, or provider revocation evidence was found for the same lifecycle path."
                .to_string(),
            suggested_fix:
                "Invalidate the server-side session or refresh token in addition to deleting the browser cookie."
                    .to_string(),
            reviewer_question: format!(
                "Where is the server-side session or token behind `{name}` revoked during logout?"
            ),
        },
    ))
}

fn classify_cookie_clear_attribute_mismatch(
    artifact: &Artifact,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !has_client_cookie_clear(path, evidence_by_id)
        || !matches!(
            artifact.artifact_type,
            ArtifactType::SessionCookie | ArtifactType::SignedCookie
        )
    {
        return None;
    }

    let attributes = artifact.cookie_attributes.as_ref()?;
    let clear_excerpts = client_cookie_clear_ids(path, evidence_by_id)
        .into_iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()))
        .filter_map(|evidence| evidence.excerpt.as_ref())
        .map(|excerpt| excerpt.as_str().to_string())
        .collect::<Vec<_>>();
    let mut mismatches = Vec::new();
    let mut evidence_ids = client_cookie_clear_ids(path, evidence_by_id);

    if attribute_missing_or_mismatched(&attributes.path, "path", &clear_excerpts) {
        mismatches.push("path");
        evidence_ids.extend(attributes.path.evidence_ids.clone());
    }
    if attribute_missing_or_mismatched(&attributes.domain, "domain", &clear_excerpts) {
        mismatches.push("domain");
        evidence_ids.extend(attributes.domain.evidence_ids.clone());
    }
    if mismatches.is_empty() {
        return None;
    }

    evidence_ids.sort();
    evidence_ids.dedup();
    let name = artifact.display_name.as_deref().unwrap_or("cookie");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "lifecycle_cookie_clear_attribute_mismatch",
            category: FindingCategory::DynamicReviewRequired,
            severity: Severity::Low,
            evidence_ids,
            title: format!("Cookie `{name}` is cleared without matching deletion attributes"),
            description: format!(
                "The cookie is set with a static {} attribute, but the linked clear-cookie evidence does not show matching deletion options.",
                mismatches.join("/")
            ),
            suggested_fix:
                "Delete the cookie with the same path and domain attributes used when setting it."
                    .to_string(),
            reviewer_question: format!(
                "Does every logout path clear `{name}` using the same {} options used when setting it?",
                mismatches.join("/")
            ),
        },
    ))
}

fn classify_jwt_denylist_absent_on_logout(
    artifact: &Artifact,
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if artifact.artifact_type != ArtifactType::AccessJwt
        || !(has_stage(path, LifecycleStage::Issue) || has_stage(path, LifecycleStage::Validate))
    {
        return None;
    }

    let logout_ids = linked_logout_handler_ids(path, report, evidence_by_id);
    if logout_ids.is_empty() || has_linked_jwt_denylist_or_revoke(path, report, evidence_by_id) {
        return None;
    }

    let mut evidence_ids = logout_ids;
    evidence_ids.extend(evidence_ids_for_stage(path, LifecycleStage::Issue));
    if evidence_ids.len() == 1 {
        evidence_ids.extend(evidence_ids_for_stage(path, LifecycleStage::Validate));
    }
    evidence_ids.sort();
    evidence_ids.dedup();

    let name = artifact.display_name.as_deref().unwrap_or("access_jwt");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "jwt_denylist_absent_on_logout_review",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            evidence_ids,
            title: format!("JWT `{name}` has logout evidence without linked denylist evidence"),
            description: "A logout handler and access-JWT lifecycle evidence were detected in linked source context, but no source-bound denylist, blocklist, or token revocation-store insertion evidence was linked for the same logout flow."
                .to_string(),
            suggested_fix:
                "Insert the JWT identifier into a denylist/blocklist or revoke-store on logout, or document the intentional short-TTL stateless model for reviewer confirmation."
                    .to_string(),
            reviewer_question: format!(
                "Where does logout revoke or denylist outstanding `{name}` tokens?"
            ),
        },
    ))
}

fn classify_refresh_family_revocation_absent_on_logout(
    artifact: &Artifact,
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !is_refresh_artifact(artifact)
        || !(has_stage(path, LifecycleStage::Issue)
            || has_stage(path, LifecycleStage::Store)
            || has_stage(path, LifecycleStage::Refresh)
            || has_stage(path, LifecycleStage::Validate))
    {
        return None;
    }

    let logout_ids = linked_logout_handler_ids(path, report, evidence_by_id);
    if logout_ids.is_empty() || has_linked_refresh_family_revoke(path, report, evidence_by_id) {
        return None;
    }

    let mut evidence_ids = logout_ids;
    evidence_ids.extend(evidence_ids_for_stage(path, LifecycleStage::Refresh));
    if evidence_ids.len() == 1 {
        evidence_ids.extend(evidence_ids_for_stage(path, LifecycleStage::Store));
    }
    if evidence_ids.len() == 1 {
        evidence_ids.extend(evidence_ids_for_stage(path, LifecycleStage::Issue));
    }
    evidence_ids.sort();
    evidence_ids.dedup();

    let name = artifact.display_name.as_deref().unwrap_or("refresh_token");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "refresh_family_revocation_absent_on_logout_review",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            evidence_ids,
            title: format!(
                "Refresh token `{name}` has logout evidence without family revocation"
            ),
            description: "Logout and refresh-token lifecycle evidence were detected in linked source context, but no source-bound user-scoped or refresh-family revocation evidence was linked for the logout flow."
                .to_string(),
            suggested_fix:
                "Revoke the user's refresh-token family, delete user-scoped refresh-token records, or remove the refresh-family cache key during logout."
                    .to_string(),
            reviewer_question: format!(
                "Where does logout revoke every refresh token in the `{name}` family or for the current user?"
            ),
        },
    ))
}

fn classify_sliding_expiry_without_rotation(
    artifact: &Artifact,
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    if !matches!(
        artifact.artifact_type,
        ArtifactType::SessionCookie
            | ArtifactType::SignedCookie
            | ArtifactType::SessionRecord
            | ArtifactType::RefreshJwt
            | ArtifactType::Unknown
    ) || !has_sliding_expiry_evidence(path, evidence_by_id)
        || has_linked_rotation_evidence(path, report, evidence_by_id)
    {
        return None;
    }

    let evidence_ids = sliding_expiry_ids(path, evidence_by_id);
    let name = artifact.display_name.as_deref().unwrap_or("session");
    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "sliding_expiry_without_rotation_review",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Low,
            evidence_ids,
            title: format!("Session `{name}` uses sliding expiry without linked rotation"),
            description: "Sliding or rolling TTL/Max-Age evidence was detected, but no linked session regeneration, session-key cycling, refresh-token rotation, or reissue evidence was found for the same lifecycle path."
                .to_string(),
            suggested_fix:
                "Pair sliding expiry with session or refresh-token rotation, or document the framework-managed rotation behavior for reviewer confirmation."
                    .to_string(),
            reviewer_question: format!(
                "Where is `{name}` rotated when its idle/sliding expiry is extended?"
            ),
        },
    ))
}

fn classify_password_change_global_revocation_absent(
    artifact: &Artifact,
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Option<Finding> {
    let handler_ids = password_change_handler_ids(path, evidence_by_id);
    if handler_ids.is_empty()
        || has_linked_password_change_global_revoke(path, report, evidence_by_id)
    {
        return None;
    }

    let mut evidence_ids = handler_ids;
    evidence_ids.sort();
    evidence_ids.dedup();

    Some(finding(
        artifact,
        path,
        FindingSpec {
            rule_id: "password_change_global_revocation_absent_review",
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            evidence_ids,
            title: "Password-change handler lacks linked global session revocation".to_string(),
            description: "A password-change handler was detected, but no linked global session invalidation, refresh-family revocation, or token-version bump evidence was found in the same source scope."
                .to_string(),
            suggested_fix:
                "After password changes, revoke all active sessions/refresh-token families or bump a token/session version checked during authentication."
                    .to_string(),
            reviewer_question:
                "Where are existing sessions and refresh-token families invalidated after this password change?"
                    .to_string(),
        },
    ))
}

fn attribute_missing_or_mismatched(
    observation: &sessionscope_model::CookieAttributeObservation,
    attribute: &str,
    clear_excerpts: &[String],
) -> bool {
    if observation.state != CookieAttributeState::Present {
        return false;
    }
    let clear_values = option_values_from_excerpts(clear_excerpts, attribute);
    if clear_values.is_empty() {
        return true;
    }
    observation.value.as_ref().is_some_and(|set_value| {
        !clear_values
            .iter()
            .any(|clear_value| clear_value.eq_ignore_ascii_case(set_value))
    })
}

fn option_values_from_excerpts(excerpts: &[String], attribute: &str) -> Vec<String> {
    excerpts
        .iter()
        .filter_map(|excerpt| option_value_from_excerpt(excerpt, attribute))
        .collect()
}

fn option_value_from_excerpt(excerpt: &str, attribute: &str) -> Option<String> {
    let lower = excerpt.to_ascii_lowercase();
    let index = lower.find(attribute)?;
    let mut chars = excerpt[index + attribute.len()..].chars().peekable();
    while matches!(chars.peek(), Some(ch) if ch.is_ascii_whitespace()) {
        chars.next();
    }
    if !matches!(chars.next(), Some(':' | '=')) {
        return None;
    }
    while matches!(chars.peek(), Some(ch) if ch.is_ascii_whitespace()) {
        chars.next();
    }
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut value = String::new();
    for ch in chars {
        if ch == quote {
            return Some(value);
        }
        value.push(ch);
    }
    None
}

fn finding(artifact: &Artifact, path: &LifecyclePath, spec: FindingSpec) -> Finding {
    let evidence_part = spec
        .evidence_ids
        .first()
        .map(|id| id.0.as_str())
        .unwrap_or("no_evidence");
    let id = stable_finding_id(&[
        spec.rule_id,
        path.id.0.as_str(),
        artifact.id.0.as_str(),
        evidence_part,
    ]);

    Finding {
        id,
        category: spec.category,
        severity: spec.severity,
        artifact_ids: vec![artifact.id.clone()],
        evidence_ids: spec.evidence_ids,
        title: spec.title,
        description: spec.description,
        suggested_fix: Some(spec.suggested_fix),
        reviewer_question: Some(spec.reviewer_question),
    }
}

fn evidence_by_id(report: &ScanReport) -> BTreeMap<&str, &Evidence> {
    report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect()
}

fn artifact_by_id(report: &ScanReport) -> BTreeMap<&str, &Artifact> {
    report
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.0.as_str(), artifact))
        .collect()
}

fn artifact_for_path<'a>(report: &'a ScanReport, path: &LifecyclePath) -> Option<&'a Artifact> {
    let artifact_by_id = artifact_by_id(report);
    artifact_for_path_with_lookup(&artifact_by_id, path)
}

fn artifact_for_path_with_lookup<'a>(
    artifact_by_id: &BTreeMap<&str, &'a Artifact>,
    path: &LifecyclePath,
) -> Option<&'a Artifact> {
    path.artifact_ids
        .iter()
        .filter_map(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        .find(|artifact| !artifact_has_only_revoke_evidence(artifact))
        .or_else(|| {
            path.artifact_ids
                .first()
                .and_then(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        })
}

fn lifecycle_ids_for_stage(
    lifecycle_evidence: &LifecycleEvidence,
    stage: LifecycleStage,
) -> Vec<EvidenceId> {
    match stage {
        LifecycleStage::Issue => lifecycle_evidence.issue.clone(),
        LifecycleStage::Store => lifecycle_evidence.store.clone(),
        LifecycleStage::Transmit => lifecycle_evidence.transmit.clone(),
        LifecycleStage::Validate => lifecycle_evidence.validate.clone(),
        LifecycleStage::Refresh => lifecycle_evidence.refresh.clone(),
        LifecycleStage::Revoke => lifecycle_evidence.revoke.clone(),
        LifecycleStage::Expire => lifecycle_evidence.expire.clone(),
        LifecycleStage::Introspect => lifecycle_evidence.introspect.clone(),
    }
}

fn has_stage(path: &LifecyclePath, stage: LifecycleStage) -> bool {
    path.stages.iter().any(|step| step.stage == stage)
}

fn has_client_cookie_clear(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "logout.cookie_clear")
        })
}

fn has_server_revoke(path: &LifecyclePath, evidence_by_id: &BTreeMap<&str, &Evidence>) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| is_server_revoke_evidence(evidence))
        })
}

fn is_server_revoke_evidence(evidence: &Evidence) -> bool {
    matches!(
        evidence.detector_id.as_str(),
        "logout.session_destroy"
            | "logout.token_revoke"
            | "logout.provider_revoke"
            | "refresh.rotate"
            | "refresh.revoke"
            | "refresh.provider"
    ) || (evidence.detector_id == "refresh.reuse_detection"
        && evidence.lifecycle_stage == LifecycleStage::Revoke)
}

fn has_dynamic_or_provider_refresh(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Refresh)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| {
                    evidence.dynamic || evidence.detector_id == "refresh.provider"
                })
        })
}

fn linked_logout_handler_ids(
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<EvidenceId> {
    let direct_ids = evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .into_iter()
        .filter(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "logout.handler")
        })
        .collect::<Vec<_>>();
    if !direct_ids.is_empty() {
        return direct_ids;
    }

    report
        .evidence
        .iter()
        .filter(|evidence| evidence.detector_id == "logout.handler")
        .filter(|evidence| evidence_linked_to_path_context(evidence, path, evidence_by_id))
        .map(|evidence| evidence.id.clone())
        .collect()
}

fn has_linked_jwt_denylist_or_revoke(
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| is_jwt_denylist_or_revoke_evidence(evidence))
        })
        || report.evidence.iter().any(|evidence| {
            is_jwt_denylist_or_revoke_evidence(evidence)
                && evidence_linked_to_path_context(evidence, path, evidence_by_id)
        })
}

fn has_linked_refresh_family_revoke(
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| is_refresh_family_revoke_evidence(evidence))
        })
        || report.evidence.iter().any(|evidence| {
            is_refresh_family_revoke_evidence(evidence)
                && evidence_linked_to_path_context(evidence, path, evidence_by_id)
        })
}

fn is_refresh_family_revoke_evidence(evidence: &Evidence) -> bool {
    (evidence.detector_id == "refresh.reuse_detection"
        && evidence.lifecycle_stage == LifecycleStage::Revoke)
        || (matches!(
            evidence.detector_id.as_str(),
            "refresh.revoke" | "refresh.rotate" | "logout.token_revoke" | "logout.provider_revoke"
        ) && evidence
            .excerpt
            .as_ref()
            .is_some_and(|excerpt| contains_refresh_family_revoke_text(excerpt.as_str())))
}

fn has_sliding_expiry_evidence(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    !sliding_expiry_ids(path, evidence_by_id).is_empty()
}

fn sliding_expiry_ids(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<EvidenceId> {
    fallback_path_ids(path)
        .into_iter()
        .filter(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| is_sliding_expiry_evidence(evidence))
        })
        .collect()
}

fn is_sliding_expiry_evidence(evidence: &Evidence) -> bool {
    matches!(
        evidence.detector_id.as_str(),
        "session.middleware" | "refresh.expire" | "refresh.store"
    ) && evidence
        .excerpt
        .as_ref()
        .is_some_and(|excerpt| contains_sliding_expiry_text(excerpt.as_str()))
}

fn contains_sliding_expiry_text(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    (normalized.contains("rolling")
        || normalized.contains("sliding")
        || normalized.contains("idle")
        || normalized.contains("touch")
        || normalized.contains("refreshsessionttl")
        || normalized.contains("extend_session")
        || normalized.contains("extendsession"))
        && (normalized.contains("maxage")
            || normalized.contains("ttl")
            || normalized.contains("expires")
            || normalized.contains("expiresat")
            || normalized.contains("expire"))
}

fn has_linked_rotation_evidence(
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    evidence_ids_for_stage(path, LifecycleStage::Refresh)
        .iter()
        .any(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| is_rotation_evidence(evidence))
        })
        || report.evidence.iter().any(|evidence| {
            is_rotation_evidence(evidence)
                && evidence_linked_to_path_context(evidence, path, evidence_by_id)
        })
}

fn password_change_handler_ids(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<EvidenceId> {
    fallback_path_ids(path)
        .into_iter()
        .filter(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "password_change.handler")
        })
        .collect()
}

fn has_linked_password_change_global_revoke(
    path: &LifecyclePath,
    report: &ScanReport,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    fallback_path_ids(path).iter().any(|evidence_id| {
        evidence_by_id
            .get(evidence_id.0.as_str())
            .is_some_and(|evidence| is_password_change_global_revoke_evidence(evidence))
    }) || report.evidence.iter().any(|evidence| {
        is_password_change_global_revoke_evidence(evidence)
            && evidence_linked_to_path_context(evidence, path, evidence_by_id)
    })
}

fn is_password_change_global_revoke_evidence(evidence: &Evidence) -> bool {
    evidence.detector_id == "password_change.global_revoke"
        || is_refresh_family_revoke_evidence(evidence)
}

fn is_rotation_evidence(evidence: &Evidence) -> bool {
    matches!(
        evidence.detector_id.as_str(),
        "session.regenerate"
            | "session.reissue"
            | "session.framework_default_regenerate"
            | "refresh.rotate"
    )
}

fn contains_refresh_family_revoke_text(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    normalized.contains("refresh")
        && (normalized.contains("family")
            || normalized.contains("userid")
            || normalized.contains("user_id")
            || normalized.contains("usersessions")
            || normalized.contains("allsessions")
            || normalized.contains("allrefresh")
            || normalized.contains("tokenfamily")
            || normalized.contains("token_family")
            || normalized.contains("familyid")
            || normalized.contains("family_id"))
        && (normalized.contains("revoke")
            || normalized.contains("delete")
            || normalized.contains("del")
            || normalized.contains("invalidate")
            || normalized.contains("destroy")
            || normalized.contains("blacklist")
            || normalized.contains("denylist"))
}

fn is_jwt_denylist_or_revoke_evidence(evidence: &Evidence) -> bool {
    matches!(
        evidence.detector_id.as_str(),
        "logout.token_revoke" | "logout.provider_revoke"
    ) || evidence
        .excerpt
        .as_ref()
        .is_some_and(|excerpt| contains_jwt_denylist_text(excerpt.as_str()))
}

fn contains_jwt_denylist_text(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    (normalized.contains("denylist")
        || normalized.contains("blocklist")
        || normalized.contains("blacklist")
        || normalized.contains("revokedtokens")
        || normalized.contains("revokedtoken")
        || normalized.contains("revoketoken")
        || normalized.contains("addtoblocklist"))
        && (normalized.contains("jwt")
            || normalized.contains("jti")
            || normalized.contains("access")
            || normalized.contains("token"))
}

fn evidence_linked_to_path_context(
    evidence: &Evidence,
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    path_evidence_locations(path, evidence_by_id)
        .iter()
        .any(|location| locations_are_linkable(&evidence.location, location))
}

fn locations_are_linkable(left: &SourceLocation, right: &SourceLocation) -> bool {
    left.path == right.path
        && left.line.is_some()
        && right.line.is_some()
        && left
            .line
            .zip(right.line)
            .is_some_and(|(left, right)| left.abs_diff(right) <= REFRESH_LINK_MAX_LINE_DISTANCE)
}

fn client_cookie_clear_ids(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<EvidenceId> {
    evidence_ids_for_stage(path, LifecycleStage::Revoke)
        .into_iter()
        .filter(|evidence_id| {
            evidence_by_id
                .get(evidence_id.0.as_str())
                .is_some_and(|evidence| evidence.detector_id == "logout.cookie_clear")
        })
        .collect()
}

fn evidence_ids_for_stage(path: &LifecyclePath, stage: LifecycleStage) -> Vec<EvidenceId> {
    path.stages
        .iter()
        .find(|step| step.stage == stage)
        .map(|step| step.evidence_ids.clone())
        .unwrap_or_default()
}

fn fallback_path_ids(path: &LifecyclePath) -> Vec<EvidenceId> {
    let mut ids = path
        .stages
        .iter()
        .flat_map(|step| step.evidence_ids.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn is_revoke_only_path(path: &LifecyclePath) -> bool {
    path.stages.len() == 1 && has_stage(path, LifecycleStage::Revoke)
}

fn is_query_param_transmit_path(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    path.stages.len() == 1
        && has_stage(path, LifecycleStage::Transmit)
        && evidence_ids_for_stage(path, LifecycleStage::Transmit)
            .iter()
            .any(|evidence_id| {
                evidence_by_id
                    .get(evidence_id.0.as_str())
                    .is_some_and(|evidence| {
                        matches!(
                            evidence.detector_id.as_str(),
                            "query_param.read" | "query_param.read.dynamic"
                        )
                    })
            })
}

fn artifact_has_only_revoke_evidence(artifact: &Artifact) -> bool {
    !artifact.lifecycle_evidence.revoke.is_empty()
        && artifact.lifecycle_evidence.issue.is_empty()
        && artifact.lifecycle_evidence.store.is_empty()
        && artifact.lifecycle_evidence.transmit.is_empty()
        && artifact.lifecycle_evidence.validate.is_empty()
        && artifact.lifecycle_evidence.refresh.is_empty()
        && artifact.lifecycle_evidence.expire.is_empty()
        && artifact.lifecycle_evidence.introspect.is_empty()
}

fn compatible_revoke_artifacts(source: &Artifact, target: &Artifact) -> bool {
    let names_match = normalized_artifact_name(source) == normalized_artifact_name(target);
    let session_alias_match =
        compatible_cookie_session_types(source.artifact_type, target.artifact_type)
            && session_cookie_alias_matches(source, target);

    if !names_match && !session_alias_match {
        return false;
    }
    source.artifact_type == target.artifact_type
        || source.artifact_type == ArtifactType::Unknown
        || target.artifact_type == ArtifactType::Unknown
        || compatible_cookie_session_types(source.artifact_type, target.artifact_type)
        || compatible_token_types(source.artifact_type, target.artifact_type)
}

fn revoke_paths_are_linkable(
    source_artifact: &Artifact,
    target_artifact: &Artifact,
    source_path: &LifecyclePath,
    target_path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    if !compatible_revoke_artifacts(source_artifact, target_artifact) {
        return false;
    }

    if (is_refresh_artifact(source_artifact) && is_refresh_artifact(target_artifact))
        || session_cookie_alias_matches(source_artifact, target_artifact)
    {
        return paths_have_linkable_source_context(source_path, target_path, evidence_by_id);
    }

    true
}

fn paths_have_linkable_source_context(
    source_path: &LifecyclePath,
    target_path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> bool {
    let source_locations = path_evidence_locations(source_path, evidence_by_id);
    let target_locations = path_evidence_locations(target_path, evidence_by_id);

    source_locations.iter().any(|source| {
        target_locations.iter().any(|target| {
            source.path == target.path
                && source.line.is_some()
                && target.line.is_some()
                && source.line.zip(target.line).is_some_and(|(left, right)| {
                    left.abs_diff(right) <= REFRESH_LINK_MAX_LINE_DISTANCE
                })
        })
    })
}

fn path_evidence_locations(
    path: &LifecyclePath,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> Vec<SourceLocation> {
    path.stages
        .iter()
        .flat_map(|step| &step.evidence_ids)
        .filter_map(|evidence_id| evidence_by_id.get(evidence_id.0.as_str()))
        .map(|evidence| evidence.location.clone())
        .collect()
}

fn session_cookie_alias_matches(source: &Artifact, target: &Artifact) -> bool {
    let left = normalized_artifact_name(source);
    let right = normalized_artifact_name(target);
    is_session_cookie_alias(&left) && is_session_cookie_alias(&right)
}

fn is_session_cookie_alias(value: &str) -> bool {
    matches!(
        value,
        "session" | "sessionid" | "sid" | "connect_sid" | "connectsid"
    )
}

fn is_refresh_path(artifact_by_id: &BTreeMap<&str, &Artifact>, path: &LifecyclePath) -> bool {
    path.artifact_ids
        .iter()
        .filter_map(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        .any(is_refresh_artifact)
        || has_stage(path, LifecycleStage::Refresh)
}

fn is_refresh_artifact(artifact: &Artifact) -> bool {
    artifact.artifact_type == ArtifactType::RefreshJwt
        || matches!(
            normalized_refresh_name(artifact),
            Some("refresh_token" | "refresh_jwt")
        )
}

fn compatible_refresh_artifacts(source: &Artifact, target: &Artifact) -> bool {
    is_refresh_artifact(source)
        && is_refresh_artifact(target)
        && (source.artifact_type == target.artifact_type
            || source.artifact_type == ArtifactType::Unknown
            || target.artifact_type == ArtifactType::Unknown
            || compatible_token_types(source.artifact_type, target.artifact_type))
}

fn compatible_query_param_artifacts(source: &Artifact, target: &Artifact) -> bool {
    let names_match = normalized_artifact_name(source) == normalized_artifact_name(target);
    let exact_type_match = source.artifact_type == target.artifact_type;
    let jwt_alias_match = matches!(
        (source.artifact_type, target.artifact_type),
        (ArtifactType::AccessJwt, ArtifactType::OpaqueBearerToken)
            | (ArtifactType::OpaqueBearerToken, ArtifactType::AccessJwt)
    ) && names_match;

    (exact_type_match || jwt_alias_match)
        && names_match
        && !matches!(
            source.artifact_type,
            ArtifactType::UnknownToken | ArtifactType::Unknown
        )
}

fn normalized_refresh_name(artifact: &Artifact) -> Option<&'static str> {
    match normalized_artifact_name(artifact).as_str() {
        "refresh" | "refresh_token" => Some("refresh_token"),
        "refresh_jwt" => Some("refresh_jwt"),
        _ => None,
    }
}

fn compatible_cookie_session_types(left: ArtifactType, right: ArtifactType) -> bool {
    matches!(
        (left, right),
        (
            ArtifactType::SessionCookie | ArtifactType::SignedCookie | ArtifactType::SessionRecord,
            ArtifactType::SessionCookie | ArtifactType::SignedCookie | ArtifactType::SessionRecord
        )
    )
}

fn compatible_token_types(left: ArtifactType, right: ArtifactType) -> bool {
    matches!(
        (left, right),
        (
            ArtifactType::RefreshJwt
                | ArtifactType::AccessJwt
                | ArtifactType::OpaqueBearerToken
                | ArtifactType::ApiKey
                | ArtifactType::ServiceToken
                | ArtifactType::UnknownToken,
            ArtifactType::RefreshJwt
                | ArtifactType::AccessJwt
                | ArtifactType::OpaqueBearerToken
                | ArtifactType::ApiKey
                | ArtifactType::ServiceToken
                | ArtifactType::UnknownToken
        )
    )
}

fn normalized_artifact_name(artifact: &Artifact) -> String {
    artifact
        .display_name
        .as_deref()
        .unwrap_or("artifact")
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

fn merge_path(source: &LifecyclePath, target: &mut LifecyclePath) {
    target.artifact_ids.extend(source.artifact_ids.clone());
    for source_step in &source.stages {
        if let Some(target_step) = target
            .stages
            .iter_mut()
            .find(|step| step.stage == source_step.stage)
        {
            target_step
                .evidence_ids
                .extend(source_step.evidence_ids.clone());
        } else {
            target.stages.push(source_step.clone());
        }
    }
}

fn refresh_path_metadata(
    artifact_by_id: &BTreeMap<&str, &Artifact>,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
    path: &mut LifecyclePath,
) {
    path.artifact_ids.sort();
    path.artifact_ids.dedup();
    for step in &mut path.stages {
        step.evidence_ids.sort();
        step.evidence_ids.dedup();
    }
    path.stages.sort_by_key(|step| step.stage);

    let artifacts = path
        .artifact_ids
        .iter()
        .filter_map(|artifact_id| artifact_by_id.get(artifact_id.0.as_str()).copied())
        .collect::<Vec<_>>();
    let Some(primary_artifact) = artifact_for_path_with_lookup(artifact_by_id, path) else {
        return;
    };

    let mut confidence = primary_artifact.confidence;
    let mut dynamic = false;
    let mut framework_default = false;
    let mut evidence_locations = Vec::new();
    let mut all_evidence_ids = Vec::new();

    for artifact in artifacts {
        confidence = min_confidence(confidence, artifact.confidence);
    }
    for step in &path.stages {
        for evidence_id in &step.evidence_ids {
            all_evidence_ids.push(evidence_id.clone());
            if let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) {
                confidence = min_confidence(confidence, evidence.confidence);
                dynamic |= evidence.dynamic;
                framework_default |= evidence.framework_default;
                evidence_locations.push(location_part(&evidence.location));
            }
        }
    }

    evidence_locations.sort();
    evidence_locations.dedup();
    all_evidence_ids.sort();
    all_evidence_ids.dedup();

    let mut id_parts = vec!["lifecycle_path".to_string()];
    id_parts.extend(path.artifact_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(
        path.stages
            .iter()
            .map(|step| format_stage(step.stage).to_string()),
    );
    id_parts.extend(all_evidence_ids.iter().map(|id| id.0.clone()));
    id_parts.extend(evidence_locations);

    path.id = stable_lifecycle_path_id(&id_parts);
    path.confidence = confidence;
    path.dynamic = dynamic;
    path.reviewer_question =
        reviewer_question_for_path(dynamic, framework_default, primary_artifact);
}

fn reviewer_question_for_path(
    dynamic: bool,
    framework_default: bool,
    artifact: &Artifact,
) -> Option<String> {
    let name = artifact.display_name.as_deref().unwrap_or("this artifact");
    if dynamic {
        return Some(format!(
            "Which production code path determines the effective lifecycle behavior for `{name}`?"
        ));
    }
    if framework_default {
        return Some(format!(
            "Which framework version and deployment settings determine lifecycle behavior for `{name}`?"
        ));
    }
    None
}

fn min_confidence(left: Confidence, right: Confidence) -> Confidence {
    match (confidence_rank(left), confidence_rank(right)) {
        (left_rank, right_rank) if left_rank <= right_rank => left,
        _ => right,
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn is_jwt_artifact(artifact_type: ArtifactType) -> bool {
    matches!(
        artifact_type,
        ArtifactType::AccessJwt | ArtifactType::RefreshJwt
    )
}

fn location_part(location: &SourceLocation) -> String {
    format!(
        "{}:{}:{}",
        location.path.replace('\\', "/"),
        location.line.unwrap_or(0),
        location.column.unwrap_or(0)
    )
}

fn format_stage(stage: LifecycleStage) -> &'static str {
    match stage {
        LifecycleStage::Issue => "issue",
        LifecycleStage::Store => "store",
        LifecycleStage::Transmit => "transmit",
        LifecycleStage::Validate => "validate",
        LifecycleStage::Refresh => "refresh",
        LifecycleStage::Revoke => "revoke",
        LifecycleStage::Expire => "expire",
        LifecycleStage::Introspect => "introspect",
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
        ArtifactType::OAuthAuthCodeFlow => "oauth_auth_code_flow",
        ArtifactType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, CookieAttributeObservation, LifecyclePathId, SCHEMA_VERSION, ScanSummary,
        SourceLocation,
    };

    use super::*;

    fn report_with_artifacts(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> ScanReport {
        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts,
            evidence,
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn artifact(
        id: &str,
        artifact_type: ArtifactType,
        name: &str,
        lifecycle_evidence: LifecycleEvidence,
    ) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: vec![location("auth.ts", 1, 1)],
            lifecycle_evidence,
            confidence: Confidence::High,
            framework_hints: Vec::new(),
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn artifact_with_cookie_path(
        id: &str,
        name: &str,
        lifecycle_evidence: LifecycleEvidence,
        path_evidence_id: &str,
    ) -> Artifact {
        let missing = CookieAttributeObservation {
            state: CookieAttributeState::Missing,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::High,
        };
        let present_path = CookieAttributeObservation {
            state: CookieAttributeState::Present,
            value: Some("/app".to_string()),
            evidence_ids: vec![EvidenceId(path_evidence_id.to_string())],
            confidence: Confidence::High,
        };
        let mut artifact = artifact(id, ArtifactType::SessionCookie, name, lifecycle_evidence);
        artifact.cookie_attributes = Some(sessionscope_model::CookieAttributes {
            http_only: missing.clone(),
            secure: missing.clone(),
            same_site: missing.clone(),
            max_age: missing.clone(),
            expires: missing.clone(),
            path: present_path,
            domain: missing,
        });
        artifact
    }

    fn evidence(id: &str, stage: LifecycleStage, line: usize, dynamic: bool) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location("auth.ts", line, 1),
            detector_id: format!("test.{}", format_stage(stage)),
            confidence: if dynamic {
                Confidence::Medium
            } else {
                Confidence::High
            },
            excerpt: None,
            dynamic,
            framework_default: false,
        }
    }

    fn evidence_with_detector(
        id: &str,
        stage: LifecycleStage,
        detector_id: &str,
        line: usize,
        dynamic: bool,
    ) -> Evidence {
        Evidence {
            detector_id: detector_id.to_string(),
            ..evidence(id, stage, line, dynamic)
        }
    }

    fn evidence_with_path(
        id: &str,
        stage: LifecycleStage,
        detector_id: &str,
        path: &str,
        line: usize,
        dynamic: bool,
    ) -> Evidence {
        Evidence {
            detector_id: detector_id.to_string(),
            location: location(path, line, 1),
            ..evidence(id, stage, line, dynamic)
        }
    }

    fn evidence_with_excerpt(
        id: &str,
        stage: LifecycleStage,
        detector_id: &str,
        line: usize,
        excerpt: &str,
    ) -> Evidence {
        Evidence {
            detector_id: detector_id.to_string(),
            excerpt: Some(sessionscope_model::SanitizedExcerpt::from_sanitized(
                excerpt.to_string(),
            )),
            ..evidence(id, stage, line, false)
        }
    }

    fn location(path: &str, line: usize, column: usize) -> SourceLocation {
        SourceLocation {
            path: path.to_string(),
            line: Some(line),
            column: Some(column),
        }
    }

    fn classified_report(artifact: Artifact, evidence: Vec<Evidence>) -> ScanReport {
        let mut report = report_with_artifacts(vec![artifact], evidence);
        report.lifecycle_paths = link(&report);
        report
    }

    #[test]
    fn links_issue_to_validate_jwt_path() {
        let artifact = artifact(
            "artifact_access",
            ArtifactType::AccessJwt,
            "access_jwt",
            LifecycleEvidence {
                issue: vec![EvidenceId("evidence_issue".to_string())],
                validate: vec![EvidenceId("evidence_validate".to_string())],
                ..LifecycleEvidence::default()
            },
        );

        let report = report_with_artifacts(
            vec![artifact],
            vec![
                evidence("evidence_validate", LifecycleStage::Validate, 20, false),
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0].artifact_ids,
            vec![ArtifactId("artifact_access".to_string())]
        );
        assert!(has_stage(&paths[0], LifecycleStage::Issue));
        assert!(has_stage(&paths[0], LifecycleStage::Validate));
        assert!(
            classify(&ScanReport {
                lifecycle_paths: paths,
                ..report
            })
            .is_empty()
        );
    }

    #[test]
    fn path_ids_are_deterministic_for_shuffled_evidence() {
        let first = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    issue: vec![
                        EvidenceId("evidence_b".to_string()),
                        EvidenceId("evidence_a".to_string()),
                    ],
                    validate: vec![EvidenceId("evidence_c".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_c", LifecycleStage::Validate, 30, false),
                evidence("evidence_b", LifecycleStage::Issue, 20, false),
                evidence("evidence_a", LifecycleStage::Issue, 10, false),
            ],
        );
        let second = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    validate: vec![EvidenceId("evidence_c".to_string())],
                    issue: vec![
                        EvidenceId("evidence_a".to_string()),
                        EvidenceId("evidence_b".to_string()),
                    ],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_a", LifecycleStage::Issue, 10, false),
                evidence("evidence_b", LifecycleStage::Issue, 20, false),
                evidence("evidence_c", LifecycleStage::Validate, 30, false),
            ],
        );

        assert_eq!(link(&first)[0].id, link(&second)[0].id);
    }

    #[test]
    fn dynamic_path_gets_reviewer_question() {
        let report = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_jwt",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence("evidence_issue", LifecycleStage::Issue, 10, true)],
        );

        let path = link(&report).pop().expect("path");

        assert!(path.dynamic);
        assert_eq!(path.confidence, Confidence::Medium);
        assert!(path.reviewer_question.is_some());
    }

    #[test]
    fn refresh_with_revoke_has_no_gap() {
        let report = classified_report(
            artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_jwt",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    revoke: vec![EvidenceId("evidence_revoke".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_refresh", LifecycleStage::Refresh, 10, false),
                evidence_with_detector(
                    "evidence_revoke",
                    LifecycleStage::Revoke,
                    "refresh.revoke",
                    11,
                    false,
                ),
            ],
        );

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn refresh_without_revoke_is_lifecycle_gap() {
        let report = classified_report(
            artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_jwt",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![evidence(
                "evidence_refresh",
                LifecycleStage::Refresh,
                10,
                false,
            )],
        );

        let findings = classify(&report);

        assert!(findings.iter().any(|finding| {
            finding.category == FindingCategory::LifecycleGap
                && finding.title.contains("refresh evidence")
        }));
    }

    #[test]
    fn session_regeneration_refresh_stage_is_not_refresh_token_gap() {
        let report = classified_report(
            artifact(
                "artifact_session_record",
                ArtifactType::SessionRecord,
                "session",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_regenerate".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![evidence_with_detector(
                "evidence_regenerate",
                LifecycleStage::Refresh,
                "session.regenerate",
                10,
                false,
            )],
        );

        let findings = classify(&report);

        assert!(!findings.iter().any(|finding| {
            finding
                .title
                .contains("refresh evidence without linked revocation")
                || finding
                    .title
                    .contains("dynamic refresh behavior without linked revocation")
        }));
    }

    #[test]
    fn reset_token_with_expire_and_revoke_has_no_gap() {
        let report = classified_report(
            artifact(
                "artifact_reset",
                ArtifactType::PasswordResetToken,
                "password_reset_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    expire: vec![EvidenceId("evidence_expire".to_string())],
                    revoke: vec![EvidenceId("evidence_single_use".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence("evidence_expire", LifecycleStage::Expire, 11, false),
                evidence("evidence_single_use", LifecycleStage::Revoke, 12, false),
            ],
        );

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn reset_token_missing_single_use_is_reviewable_gap() {
        let report = classified_report(
            artifact(
                "artifact_reset",
                ArtifactType::PasswordResetToken,
                "password_reset_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    expire: vec![EvidenceId("evidence_expire".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence("evidence_expire", LifecycleStage::Expire, 11, false),
            ],
        );

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.category == FindingCategory::LifecycleGap)
            .expect("reset token gap finding");

        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn reset_token_missing_expiry_is_reviewable_gap() {
        let report = classified_report(
            artifact(
                "artifact_reset",
                ArtifactType::PasswordResetToken,
                "password_reset_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    revoke: vec![EvidenceId("evidence_single_use".to_string())],
                    ..LifecycleEvidence::default()
                },
            ),
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence("evidence_single_use", LifecycleStage::Revoke, 12, false),
            ],
        );

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("no linked expiry evidence"))
            .expect("reset token expiry gap finding");

        assert_eq!(finding.category, FindingCategory::LifecycleGap);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn same_name_revoke_only_artifact_merges_into_existing_path() {
        let report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_session_store",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        store: vec![EvidenceId("evidence_store".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_clear",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_store", LifecycleStage::Store, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].artifact_ids.len(), 2);
        assert!(has_stage(&paths[0], LifecycleStage::Store));
        assert!(has_stage(&paths[0], LifecycleStage::Revoke));
    }

    #[test]
    fn client_cookie_clear_does_not_satisfy_refresh_server_revoke() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_refresh",
                    ArtifactType::RefreshJwt,
                    "refresh_token",
                    LifecycleEvidence {
                        refresh: vec![EvidenceId("evidence_refresh".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_clear",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_refresh", LifecycleStage::Refresh, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(findings.iter().any(|finding| {
            finding.title.contains("refresh evidence")
                && finding
                    .reviewer_question
                    .as_deref()
                    .is_some_and(|question| question.contains("server-side"))
        }));
    }

    #[test]
    fn logout_handler_alone_does_not_satisfy_server_revoke() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_session_clear",
                ArtifactType::SessionCookie,
                "session",
                LifecycleEvidence {
                    revoke: vec![
                        EvidenceId("evidence_handler".to_string()),
                        EvidenceId("evidence_clear".to_string()),
                    ],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_detector(
                    "evidence_handler",
                    LifecycleStage::Revoke,
                    "logout.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    11,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("cleared on logout"))
        );
    }

    #[test]
    fn server_revoke_prevents_clear_cookie_only_finding() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_session_store",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        store: vec![EvidenceId("evidence_store".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_clear",
                    ArtifactType::SessionCookie,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_destroy",
                    ArtifactType::SessionRecord,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_destroy".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence("evidence_store", LifecycleStage::Store, 10, false),
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
                evidence_with_detector(
                    "evidence_destroy",
                    LifecycleStage::Revoke,
                    "logout.session_destroy",
                    21,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("cleared on logout"))
        );
    }

    #[test]
    fn session_cookie_alias_links_to_server_session_revoke_when_colocated() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_session_clear",
                    ArtifactType::SessionCookie,
                    "sessionid",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_clear".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_session_destroy",
                    ArtifactType::SessionRecord,
                    "session",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_destroy".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence_with_detector(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    false,
                ),
                evidence_with_detector(
                    "evidence_destroy",
                    LifecycleStage::Revoke,
                    "logout.session_destroy",
                    21,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("cleared on logout")),
            "{findings:?}"
        );
    }

    #[test]
    fn cookie_clear_without_set_path_option_is_review_required() {
        let mut report = report_with_artifacts(
            vec![artifact_with_cookie_path(
                "artifact_session",
                "session",
                LifecycleEvidence {
                    store: vec![EvidenceId("evidence_set".to_string())],
                    revoke: vec![EvidenceId("evidence_clear".to_string())],
                    ..LifecycleEvidence::default()
                },
                "evidence_set",
            )],
            vec![
                evidence("evidence_set", LifecycleStage::Store, 10, false),
                evidence_with_excerpt(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    "response.clearCookie(\"[REDACTED]\")",
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("matching deletion attributes"))
        );
    }

    #[test]
    fn cookie_clear_with_different_static_path_is_review_required() {
        let mut report = report_with_artifacts(
            vec![artifact_with_cookie_path(
                "artifact_session",
                "session",
                LifecycleEvidence {
                    store: vec![EvidenceId("evidence_set".to_string())],
                    revoke: vec![EvidenceId("evidence_clear".to_string())],
                    ..LifecycleEvidence::default()
                },
                "evidence_set",
            )],
            vec![
                evidence("evidence_set", LifecycleStage::Store, 10, false),
                evidence_with_excerpt(
                    "evidence_clear",
                    LifecycleStage::Revoke,
                    "logout.cookie_clear",
                    20,
                    "response.clearCookie(\"session\", { path: \"/logout\" })",
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("matching deletion attributes"))
        );
    }

    #[test]
    fn same_name_refresh_artifacts_merge_across_lifecycle_stages() {
        let report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_refresh_store",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        store: vec![EvidenceId("evidence_store".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_handler",
                    ArtifactType::Unknown,
                    "refresh",
                    LifecycleEvidence {
                        refresh: vec![EvidenceId("evidence_refresh".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_revoke",
                    ArtifactType::RefreshJwt,
                    "refresh_jwt",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_revoke".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence_with_detector(
                    "evidence_store",
                    LifecycleStage::Store,
                    "refresh.store",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_refresh",
                    LifecycleStage::Refresh,
                    "refresh.handler",
                    20,
                    false,
                ),
                evidence_with_detector(
                    "evidence_revoke",
                    LifecycleStage::Revoke,
                    "refresh.rotate",
                    30,
                    false,
                ),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].artifact_ids.len(), 3);
        assert!(has_stage(&paths[0], LifecycleStage::Store));
        assert!(has_stage(&paths[0], LifecycleStage::Refresh));
        assert!(has_stage(&paths[0], LifecycleStage::Revoke));
    }

    #[test]
    fn query_param_transmit_path_merges_with_compatible_local_token_path() {
        let report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_query_access",
                    ArtifactType::AccessJwt,
                    "access_token",
                    LifecycleEvidence {
                        transmit: vec![EvidenceId("evidence_query".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_access_validate",
                    ArtifactType::AccessJwt,
                    "access_token",
                    LifecycleEvidence {
                        validate: vec![EvidenceId("evidence_validate".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence_with_detector(
                    "evidence_query",
                    LifecycleStage::Transmit,
                    "query_param.read",
                    10,
                    false,
                ),
                evidence("evidence_validate", LifecycleStage::Validate, 12, false),
            ],
        );

        let paths = link(&report);

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].artifact_ids.len(), 2);
        assert!(has_stage(&paths[0], LifecycleStage::Transmit));
        assert!(has_stage(&paths[0], LifecycleStage::Validate));
    }

    #[test]
    fn refresh_rotate_revoke_prevents_lifecycle_gap() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_refresh",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        refresh: vec![EvidenceId("evidence_refresh".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_revoke",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_revoke".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence_with_detector(
                    "evidence_refresh",
                    LifecycleStage::Refresh,
                    "refresh.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_revoke",
                    LifecycleStage::Revoke,
                    "refresh.rotate",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        assert!(classify(&report).is_empty());
    }

    #[test]
    fn unrelated_refresh_paths_do_not_merge_by_display_name_only() {
        let mut report = report_with_artifacts(
            vec![
                artifact(
                    "artifact_refresh_missing_revoke",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        refresh: vec![EvidenceId("evidence_refresh".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
                artifact(
                    "artifact_refresh_revoke_elsewhere",
                    ArtifactType::Unknown,
                    "refresh_token",
                    LifecycleEvidence {
                        revoke: vec![EvidenceId("evidence_revoke".to_string())],
                        ..LifecycleEvidence::default()
                    },
                ),
            ],
            vec![
                evidence_with_path(
                    "evidence_refresh",
                    LifecycleStage::Refresh,
                    "refresh.handler",
                    "fixtures/express/refresh-without-rotation/app.ts",
                    10,
                    false,
                ),
                evidence_with_path(
                    "evidence_revoke",
                    LifecycleStage::Revoke,
                    "refresh.rotate",
                    "fixtures/express/refresh-rotation/app.ts",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(report.lifecycle_paths.len() >= 2);
        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("refresh evidence"))
        );
    }

    #[test]
    fn provider_dynamic_refresh_without_revoke_is_review_required() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_provider_refresh",
                ArtifactType::Unknown,
                "refresh_token",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_provider".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence_with_detector(
                "evidence_provider",
                LifecycleStage::Refresh,
                "refresh.provider",
                10,
                true,
            )],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);
        let finding = findings.first().expect("dynamic review finding");

        assert_eq!(finding.category, FindingCategory::DynamicReviewRequired);
        assert!(finding.title.contains("dynamic refresh behavior"));
    }

    #[test]
    fn jwt_logout_without_denylist_is_lifecycle_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence_with_detector(
                    "evidence_logout",
                    LifecycleStage::Revoke,
                    "logout.handler",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("without linked denylist"))
            .expect("JWT logout denylist review finding");

        assert_eq!(finding.category, FindingCategory::LifecycleGap);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.reviewer_question.is_some());
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_issue".to_string()))
        );
        assert!(
            finding
                .evidence_ids
                .contains(&EvidenceId("evidence_logout".to_string()))
        );
    }

    #[test]
    fn linked_jwt_revoke_prevents_logout_denylist_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_access",
                ArtifactType::AccessJwt,
                "access_token",
                LifecycleEvidence {
                    issue: vec![EvidenceId("evidence_issue".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence("evidence_issue", LifecycleStage::Issue, 10, false),
                evidence_with_detector(
                    "evidence_logout",
                    LifecycleStage::Revoke,
                    "logout.handler",
                    20,
                    false,
                ),
                evidence_with_detector(
                    "evidence_revoke",
                    LifecycleStage::Revoke,
                    "logout.token_revoke",
                    21,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("without linked denylist")),
            "{findings:?}"
        );
    }

    #[test]
    fn refresh_logout_without_family_revoke_is_lifecycle_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_token",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_detector(
                    "evidence_refresh",
                    LifecycleStage::Refresh,
                    "refresh.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_logout",
                    LifecycleStage::Revoke,
                    "logout.handler",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("without family revocation"))
            .expect("refresh family revocation review finding");

        assert_eq!(finding.category, FindingCategory::LifecycleGap);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn linked_refresh_family_revoke_prevents_logout_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_refresh",
                ArtifactType::RefreshJwt,
                "refresh_token",
                LifecycleEvidence {
                    refresh: vec![EvidenceId("evidence_refresh".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_detector(
                    "evidence_refresh",
                    LifecycleStage::Refresh,
                    "refresh.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_logout",
                    LifecycleStage::Revoke,
                    "logout.handler",
                    20,
                    false,
                ),
                evidence_with_excerpt(
                    "evidence_family_revoke",
                    LifecycleStage::Revoke,
                    "refresh.revoke",
                    21,
                    "revokeRefreshFamily(user.id)",
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("without family revocation")),
            "{findings:?}"
        );
    }

    #[test]
    fn sliding_expiry_without_rotation_is_lifecycle_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_session",
                ArtifactType::SessionRecord,
                "session",
                LifecycleEvidence {
                    store: vec![EvidenceId("evidence_sliding".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence_with_excerpt(
                "evidence_sliding",
                LifecycleStage::Store,
                "session.middleware",
                10,
                "session({ rolling: true, cookie: { maxAge: 900000 } })",
            )],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("sliding expiry"))
            .expect("sliding expiry review finding");

        assert_eq!(finding.category, FindingCategory::LifecycleGap);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn linked_session_rotation_prevents_sliding_expiry_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_session",
                ArtifactType::SessionRecord,
                "session",
                LifecycleEvidence {
                    store: vec![EvidenceId("evidence_sliding".to_string())],
                    refresh: vec![EvidenceId("evidence_rotate".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_excerpt(
                    "evidence_sliding",
                    LifecycleStage::Store,
                    "session.middleware",
                    10,
                    "session({ rolling: true, cookie: { maxAge: 900000 } })",
                ),
                evidence_with_detector(
                    "evidence_rotate",
                    LifecycleStage::Refresh,
                    "session.regenerate",
                    20,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("sliding expiry")),
            "{findings:?}"
        );
    }

    #[test]
    fn fixed_expiry_session_does_not_trigger_sliding_review() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_session",
                ArtifactType::SessionRecord,
                "session",
                LifecycleEvidence {
                    store: vec![EvidenceId("evidence_store".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence_with_excerpt(
                "evidence_store",
                LifecycleStage::Store,
                "session.middleware",
                10,
                "session({ cookie: { maxAge: 900000 } })",
            )],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("sliding expiry")),
            "{findings:?}"
        );
    }

    #[test]
    fn password_change_without_global_revoke_is_lifecycle_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_password_change",
                ArtifactType::Unknown,
                "password_change",
                LifecycleEvidence {
                    revoke: vec![EvidenceId("evidence_handler".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![evidence_with_detector(
                "evidence_handler",
                LifecycleStage::Revoke,
                "password_change.handler",
                10,
                false,
            )],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);
        let finding = findings
            .iter()
            .find(|finding| finding.title.contains("Password-change handler"))
            .expect("password-change global revocation review finding");

        assert_eq!(finding.category, FindingCategory::LifecycleGap);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn linked_global_revoke_prevents_password_change_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_password_change",
                ArtifactType::Unknown,
                "password_change",
                LifecycleEvidence {
                    revoke: vec![EvidenceId("evidence_handler".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_detector(
                    "evidence_handler",
                    LifecycleStage::Revoke,
                    "password_change.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_global_revoke",
                    LifecycleStage::Revoke,
                    "password_change.global_revoke",
                    12,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("Password-change handler")),
            "{findings:?}"
        );
    }

    #[test]
    fn current_session_rotation_does_not_prevent_password_change_gap() {
        let mut report = report_with_artifacts(
            vec![artifact(
                "artifact_password_change",
                ArtifactType::Unknown,
                "password_change",
                LifecycleEvidence {
                    revoke: vec![
                        EvidenceId("evidence_handler".to_string()),
                        EvidenceId("evidence_session_destroy".to_string()),
                    ],
                    refresh: vec![EvidenceId("evidence_session_regenerate".to_string())],
                    ..LifecycleEvidence::default()
                },
            )],
            vec![
                evidence_with_detector(
                    "evidence_handler",
                    LifecycleStage::Revoke,
                    "password_change.handler",
                    10,
                    false,
                ),
                evidence_with_detector(
                    "evidence_session_destroy",
                    LifecycleStage::Revoke,
                    "logout.session_destroy",
                    12,
                    false,
                ),
                evidence_with_detector(
                    "evidence_session_regenerate",
                    LifecycleStage::Refresh,
                    "session.regenerate",
                    13,
                    false,
                ),
            ],
        );
        report.lifecycle_paths = link(&report);

        let findings = classify(&report);

        assert!(
            findings
                .iter()
                .any(|finding| finding.title.contains("Password-change handler")),
            "{findings:?}"
        );
    }

    #[test]
    fn sort_paths_orders_paths_by_artifact() {
        let mut paths = vec![
            LifecyclePath {
                id: LifecyclePathId("lifecycle_path_b".to_string()),
                artifact_ids: vec![ArtifactId("artifact_b".to_string())],
                stages: Vec::new(),
                confidence: Confidence::High,
                dynamic: false,
                reviewer_question: None,
            },
            LifecyclePath {
                id: LifecyclePathId("lifecycle_path_a".to_string()),
                artifact_ids: vec![ArtifactId("artifact_a".to_string())],
                stages: Vec::new(),
                confidence: Confidence::High,
                dynamic: false,
                reviewer_question: None,
            },
        ];

        sort_paths(&mut paths);

        assert_eq!(
            paths[0].artifact_ids[0],
            ArtifactId("artifact_a".to_string())
        );
    }
}
