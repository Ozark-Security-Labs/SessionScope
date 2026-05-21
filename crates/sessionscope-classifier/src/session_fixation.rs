use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    Artifact, Evidence, Finding, FindingCategory, LifecycleStage, ScanReport, Severity,
    stable_finding_id,
};

const LINK_DISTANCE: usize = 80;

pub fn classify(report: &ScanReport) -> Vec<Finding> {
    let records = fixation_records(report);
    let transitions = records
        .iter()
        .filter(|record| is_transition_evidence(record.evidence))
        .collect::<Vec<_>>();
    let regenerations = records
        .iter()
        .filter(|record| is_regeneration_evidence(record.evidence))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for transition in &transitions {
        if has_nearby_regeneration(transition, &regenerations, &transitions) {
            continue;
        }

        let transition_kind = if transition.evidence.detector_id == "session.privilege_transition" {
            "privilege"
        } else {
            "auth"
        };
        let key = (
            transition_kind,
            transition.evidence.location.path.clone(),
            transition.evidence.location.line.unwrap_or_default(),
        );
        if !seen.insert(key) {
            continue;
        }

        let nearby_stores = records
            .iter()
            .filter(|record| {
                record.evidence.detector_id == "session.store_after_auth"
                    && nearby(transition.evidence, record.evidence)
            })
            .collect::<Vec<_>>();
        findings.push(fixation_finding(
            transition,
            &nearby_stores,
            transition_kind,
        ));
    }

    findings
}

#[derive(Clone, Copy)]
struct FixationRecord<'a> {
    artifact: &'a Artifact,
    evidence: &'a Evidence,
}

fn fixation_records(report: &ScanReport) -> Vec<FixationRecord<'_>> {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut records = Vec::new();

    for artifact in &report.artifacts {
        for evidence_id in artifact
            .lifecycle_evidence
            .issue
            .iter()
            .chain(artifact.lifecycle_evidence.store.iter())
            .chain(artifact.lifecycle_evidence.refresh.iter())
        {
            let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) else {
                continue;
            };
            if evidence.detector_id.starts_with("session.") {
                records.push(FixationRecord { artifact, evidence });
            }
        }
    }

    records
}

fn is_transition_evidence(evidence: &Evidence) -> bool {
    evidence.lifecycle_stage == LifecycleStage::Issue
        && matches!(
            evidence.detector_id.as_str(),
            "session.auth_transition" | "session.privilege_transition"
        )
}

fn is_regeneration_evidence(evidence: &Evidence) -> bool {
    evidence.lifecycle_stage == LifecycleStage::Refresh
        && matches!(
            evidence.detector_id.as_str(),
            "session.regenerate" | "session.reissue" | "session.framework_default_regenerate"
        )
}

fn has_nearby_regeneration(
    transition: &FixationRecord<'_>,
    regenerations: &[&FixationRecord<'_>],
    transitions: &[&FixationRecord<'_>],
) -> bool {
    let Some(transition_line) = transition.evidence.location.line else {
        return false;
    };
    let next_transition_line = transitions
        .iter()
        .filter_map(|record| {
            if record.evidence.location.path == transition.evidence.location.path
                && same_scope(transition, record)
            {
                record.evidence.location.line
            } else {
                None
            }
        })
        .filter(|line| *line > transition_line)
        .min();
    let max_line = next_transition_line
        .and_then(|line| line.checked_sub(1))
        .unwrap_or(transition_line + LINK_DISTANCE)
        .min(transition_line + LINK_DISTANCE);

    regenerations
        .iter()
        .any(|record| regeneration_in_transition_range(transition, record, max_line))
}

fn regeneration_in_transition_range(
    transition: &FixationRecord<'_>,
    regeneration: &FixationRecord<'_>,
    max_line: usize,
) -> bool {
    if transition.evidence.location.path != regeneration.evidence.location.path
        || !same_scope(transition, regeneration)
    {
        return false;
    }
    if transition.evidence.detector_id == "session.privilege_transition"
        && regeneration.evidence.framework_default
    {
        return false;
    }
    let Some(transition_line) = transition.evidence.location.line else {
        return false;
    };
    let Some(regeneration_line) = regeneration.evidence.location.line else {
        return false;
    };
    regeneration_line <= max_line && transition_line.abs_diff(regeneration_line) <= LINK_DISTANCE
}

fn same_scope(left: &FixationRecord<'_>, right: &FixationRecord<'_>) -> bool {
    match (scope_hint(left.artifact), scope_hint(right.artifact)) {
        (Some(left), Some(right)) => left == right,
        (Some(_), None) | (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn scope_hint(artifact: &Artifact) -> Option<&str> {
    artifact
        .framework_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("scope:"))
}

fn nearby(left: &Evidence, right: &Evidence) -> bool {
    if left.location.path != right.location.path {
        return false;
    }
    let Some(left_line) = left.location.line else {
        return false;
    };
    let Some(right_line) = right.location.line else {
        return false;
    };
    left_line.abs_diff(right_line) <= LINK_DISTANCE
}

fn fixation_finding(
    transition: &FixationRecord<'_>,
    stores: &[&FixationRecord<'_>],
    transition_kind: &str,
) -> Finding {
    let mut evidence_ids = vec![transition.evidence.id.clone()];
    evidence_ids.extend(stores.iter().map(|record| record.evidence.id.clone()));
    evidence_ids.sort();
    evidence_ids.dedup();

    let mut artifact_ids = vec![transition.artifact.id.clone()];
    artifact_ids.extend(stores.iter().map(|record| record.artifact.id.clone()));
    artifact_ids.sort();
    artifact_ids.dedup();

    let framework = framework_for(transition.artifact, stores);
    let title = if transition_kind == "privilege" {
        "Session regeneration evidence was not found near a privilege transition".to_string()
    } else {
        "Session regeneration evidence was not found near login".to_string()
    };
    let description = if transition_kind == "privilege" {
        "A privilege-changing session transition was detected, but nearby static evidence did not show an explicit session regeneration, cookie reissue, or recognized framework-default rotation point."
            .to_string()
    } else {
        "An authentication transition was detected, but nearby static evidence did not show an explicit session regeneration, cookie reissue, or recognized framework-default rotation point."
            .to_string()
    };
    let reviewer_question = if transition_kind == "privilege" {
        "Where is the session identifier rotated after this privilege change?".to_string()
    } else {
        "Where is the session identifier rotated after this authentication transition?".to_string()
    };

    let evidence_part = evidence_ids
        .iter()
        .map(|id| id.0.as_str())
        .collect::<Vec<_>>()
        .join("|");
    let detector_part = transition.evidence.detector_id.as_str();
    let path_part = transition.evidence.location.path.as_str();
    let line_part = transition
        .evidence
        .location
        .line
        .map(|line| line.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let rule_id = if transition_kind == "privilege" {
        "session_fixation_privilege_regeneration_review"
    } else {
        "session_fixation_login_regeneration_review"
    };

    Finding {
        id: stable_finding_id(&[
            rule_id,
            path_part,
            line_part.as_str(),
            evidence_part.as_str(),
            detector_part,
        ]),
        category: FindingCategory::DynamicReviewRequired,
        severity: Severity::Medium,
        artifact_ids,
        evidence_ids,
        title,
        description,
        suggested_fix: Some(suggested_fix_for_framework(framework).to_string()),
        reviewer_question: Some(reviewer_question),
    }
}

fn framework_for<'a>(artifact: &'a Artifact, stores: &[&FixationRecord<'a>]) -> &'a str {
    artifact
        .framework_hints
        .iter()
        .chain(
            stores
                .iter()
                .flat_map(|record| record.artifact.framework_hints.iter()),
        )
        .map(String::as_str)
        .find(|hint| matches!(*hint, "express" | "cookie-session" | "django"))
        .unwrap_or_else(|| {
            artifact
                .framework_hints
                .first()
                .map(String::as_str)
                .unwrap_or("session")
        })
}

fn suggested_fix_for_framework(framework: &str) -> &'static str {
    match framework {
        "express" => {
            "Regenerate the server-side session with req.session.regenerate(...) after authentication and privilege changes before storing the authenticated user state."
        }
        "cookie-session" => {
            "Clear and reissue the signed session cookie, or document the framework-specific point where the session identifier is rotated after the transition."
        }
        "django" => {
            "Use Django login(request, user), auth_login(request, user), or request.session.cycle_key() in the transition path so session rotation is visible."
        }
        _ => {
            "Identify the framework's session rotation primitive and call it during authentication and privilege transitions."
        }
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, ArtifactType, Confidence, EvidenceId, LifecycleEvidence, SCHEMA_VERSION,
        SanitizedExcerpt, ScanSummary, SourceLocation,
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
        framework: &str,
        issue: &[&str],
        store: &[&str],
        refresh: &[&str],
    ) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type: ArtifactType::SessionRecord,
            display_name: Some("session".to_string()),
            locations: vec![location(1)],
            lifecycle_evidence: LifecycleEvidence {
                issue: ids(issue),
                store: ids(store),
                refresh: ids(refresh),
                ..LifecycleEvidence::default()
            },
            confidence: Confidence::High,
            framework_hints: vec![framework.to_string()],
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn scoped_artifact(
        id: &str,
        framework: &str,
        scope: &str,
        issue: &[&str],
        store: &[&str],
        refresh: &[&str],
    ) -> Artifact {
        let mut artifact = artifact(id, framework, issue, store, refresh);
        artifact.framework_hints.push(format!("scope:{scope}"));
        artifact
    }

    fn ids(values: &[&str]) -> Vec<EvidenceId> {
        values
            .iter()
            .map(|value| EvidenceId((*value).to_string()))
            .collect()
    }

    fn evidence(id: &str, detector_id: &str, stage: LifecycleStage, line: usize) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: location(line),
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: Some(SanitizedExcerpt::from_sanitized(
                "redacted session evidence".to_string(),
            )),
            dynamic: false,
            framework_default: detector_id == "session.framework_default_regenerate",
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
    fn login_transition_without_regeneration_is_review_required() {
        let findings = classify_artifacts(
            vec![artifact("artifact_login", "express", &["e1"], &["e2"], &[])],
            vec![
                evidence("e1", "session.auth_transition", LifecycleStage::Issue, 10),
                evidence("e2", "session.store_after_auth", LifecycleStage::Store, 14),
            ],
        );

        let finding = findings.first().expect("fixation finding");
        assert_eq!(finding.category, FindingCategory::DynamicReviewRequired);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.title.contains("login"));
        assert!(
            finding
                .suggested_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("req.session.regenerate"))
        );
    }

    #[test]
    fn privilege_transition_without_regeneration_is_review_required() {
        let findings = classify_artifacts(
            vec![artifact("artifact_priv", "express", &["e1"], &[], &[])],
            vec![evidence(
                "e1",
                "session.privilege_transition",
                LifecycleStage::Issue,
                40,
            )],
        );

        let finding = findings.first().expect("fixation finding");
        assert!(finding.title.contains("privilege transition"));
        assert!(finding.reviewer_question.is_some());
    }

    #[test]
    fn explicit_regeneration_suppresses_review() {
        let findings = classify_artifacts(
            vec![
                artifact("artifact_login", "express", &["e1"], &[], &[]),
                artifact("artifact_refresh", "express", &[], &[], &["e2"]),
            ],
            vec![
                evidence("e1", "session.auth_transition", LifecycleStage::Issue, 10),
                evidence("e2", "session.regenerate", LifecycleStage::Refresh, 15),
            ],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn regeneration_before_store_suppresses_review_in_same_scope() {
        let findings = classify_artifacts(
            vec![
                scoped_artifact("artifact_login", "express", "login", &["e1"], &["e3"], &[]),
                scoped_artifact("artifact_refresh", "express", "login", &[], &[], &["e2"]),
            ],
            vec![
                evidence("e1", "session.auth_transition", LifecycleStage::Issue, 10),
                evidence("e2", "session.regenerate", LifecycleStage::Refresh, 8),
                evidence("e3", "session.store_after_auth", LifecycleStage::Store, 12),
            ],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn sibling_handler_regeneration_does_not_suppress_review() {
        let findings = classify_artifacts(
            vec![
                scoped_artifact("artifact_login", "django", "login", &["e1"], &[], &[]),
                scoped_artifact("artifact_refresh", "django", "other", &[], &[], &["e2"]),
            ],
            vec![
                evidence("e1", "session.auth_transition", LifecycleStage::Issue, 40),
                evidence(
                    "e2",
                    "session.framework_default_regenerate",
                    LifecycleStage::Refresh,
                    45,
                ),
            ],
        );

        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn framework_default_does_not_suppress_privilege_transition() {
        let findings = classify_artifacts(
            vec![
                scoped_artifact("artifact_priv", "django", "admin", &["e1"], &[], &[]),
                scoped_artifact("artifact_default", "django", "admin", &[], &[], &["e2"]),
            ],
            vec![
                evidence(
                    "e1",
                    "session.privilege_transition",
                    LifecycleStage::Issue,
                    20,
                ),
                evidence(
                    "e2",
                    "session.framework_default_regenerate",
                    LifecycleStage::Refresh,
                    21,
                ),
            ],
        );

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].title.contains("privilege"));
    }

    #[test]
    fn django_framework_default_regeneration_suppresses_review() {
        let findings = classify_artifacts(
            vec![
                artifact("artifact_login", "django", &["e1"], &[], &[]),
                artifact("artifact_default", "django", &[], &[], &["e2"]),
            ],
            vec![
                evidence("e1", "session.auth_transition", LifecycleStage::Issue, 10),
                evidence(
                    "e2",
                    "session.framework_default_regenerate",
                    LifecycleStage::Refresh,
                    10,
                ),
            ],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn logout_only_evidence_does_not_trigger_fixation_review() {
        let findings = classify_artifacts(
            vec![artifact("artifact_logout", "express", &[], &[], &[])],
            vec![evidence(
                "e1",
                "logout.session_destroy",
                LifecycleStage::Revoke,
                10,
            )],
        );

        assert!(findings.is_empty(), "{findings:?}");
    }
}
