use std::collections::BTreeSet;

use sessionscope_model::{
    Artifact, ArtifactId, ArtifactType, Evidence, EvidenceId, FileScanResult, JwtAttributeState,
    LifecyclePath, LifecycleStage, ScanReport, ScanSummary,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityArea {
    Cookies,
    Claims,
    Logout,
    Refresh,
}

pub fn filter_report(report: &ScanReport, area: CapabilityArea) -> ScanReport {
    let mut artifact_ids = report
        .artifacts
        .iter()
        .filter(|artifact| artifact_matches(area, artifact))
        .map(|artifact| artifact.id.clone())
        .collect::<BTreeSet<_>>();
    let mut evidence_ids = report
        .evidence
        .iter()
        .filter(|evidence| evidence_matches(area, evidence))
        .map(|evidence| evidence.id.clone())
        .collect::<BTreeSet<_>>();

    for artifact in &report.artifacts {
        if artifact_has_evidence(artifact, &evidence_ids) {
            artifact_ids.insert(artifact.id.clone());
        }
    }

    for artifact in &report.artifacts {
        if artifact_ids.contains(&artifact.id) {
            collect_artifact_evidence(artifact, &mut evidence_ids, area);
        }
    }

    for path in &report.lifecycle_paths {
        if path_matches(path, &artifact_ids, &evidence_ids) {
            artifact_ids.extend(path.artifact_ids.iter().cloned());
            for step in &path.stages {
                if lifecycle_stage_matches(area, step.stage) {
                    evidence_ids.extend(step.evidence_ids.iter().cloned());
                }
            }
        }
    }

    let findings = report
        .findings
        .iter()
        .filter(|finding| finding_matches(area, finding, &artifact_ids, &evidence_ids))
        .cloned()
        .collect::<Vec<_>>();

    for finding in &findings {
        artifact_ids.extend(finding.artifact_ids.iter().cloned());
        evidence_ids.extend(finding.evidence_ids.iter().cloned());
    }

    let artifacts = report
        .artifacts
        .iter()
        .filter(|artifact| artifact_ids.contains(&artifact.id))
        .cloned()
        .collect::<Vec<_>>();
    let evidence = report
        .evidence
        .iter()
        .filter(|evidence| evidence_ids.contains(&evidence.id))
        .cloned()
        .collect::<Vec<_>>();
    let lifecycle_paths = report
        .lifecycle_paths
        .iter()
        .filter(|path| path_matches(path, &artifact_ids, &evidence_ids))
        .cloned()
        .collect::<Vec<_>>();
    let files = report
        .files
        .iter()
        .map(|file| filter_file(file, &artifact_ids, &evidence_ids))
        .filter(|file| {
            !file.artifacts.is_empty() || !file.evidence.is_empty() || !file.diagnostics.is_empty()
        })
        .collect::<Vec<_>>();
    let summary = summarize_files(&files);

    ScanReport {
        schema_version: report.schema_version.clone(),
        summary,
        files,
        artifacts,
        evidence,
        lifecycle_paths,
        findings,
    }
}

fn artifact_matches(area: CapabilityArea, artifact: &Artifact) -> bool {
    match area {
        CapabilityArea::Cookies => {
            matches!(
                artifact.artifact_type,
                ArtifactType::SessionCookie | ArtifactType::SignedCookie
            ) || artifact.cookie_attributes.is_some()
        }
        CapabilityArea::Claims => artifact
            .jwt_attributes
            .as_ref()
            .and_then(|attributes| attributes.identity_claims.as_ref())
            .is_some_and(|claims| {
                [
                    &claims.subject,
                    &claims.user_id,
                    &claims.tenant_id,
                    &claims.org_id,
                    &claims.workspace_id,
                    &claims.roles,
                    &claims.scopes,
                    &claims.groups,
                    &claims.email,
                    &claims.email_verified,
                    &claims.auth_method,
                    &claims.auth_class,
                ]
                .iter()
                .any(|claim| claim.state != JwtAttributeState::Unknown)
            }),
        CapabilityArea::Logout => {
            artifact.lifecycle_evidence.revoke.iter().any(|id| {
                id.0.contains("logout") || id.0.contains("revoke") || id.0.contains("clear")
            })
        }
        CapabilityArea::Refresh => {
            artifact.artifact_type == ArtifactType::RefreshJwt
                || artifact
                    .display_name
                    .as_deref()
                    .is_some_and(|name| name.to_ascii_lowercase().contains("refresh"))
                || !artifact.lifecycle_evidence.refresh.is_empty()
        }
    }
}

fn evidence_matches(area: CapabilityArea, evidence: &Evidence) -> bool {
    match area {
        CapabilityArea::Cookies => evidence.detector_id.starts_with("cookie."),
        CapabilityArea::Claims => is_identity_claim_detector(&evidence.detector_id),
        CapabilityArea::Logout => {
            evidence.detector_id.starts_with("logout.")
                || evidence.detector_id.contains("provider_revoke")
        }
        CapabilityArea::Refresh => {
            evidence.lifecycle_stage == LifecycleStage::Refresh
                || evidence.detector_id.starts_with("refresh.")
                || evidence.detector_id.contains("refresh")
        }
    }
}

fn lifecycle_stage_matches(area: CapabilityArea, stage: LifecycleStage) -> bool {
    match area {
        CapabilityArea::Cookies => true,
        CapabilityArea::Claims => false,
        CapabilityArea::Logout => stage == LifecycleStage::Revoke,
        CapabilityArea::Refresh => stage == LifecycleStage::Refresh,
    }
}

fn is_identity_claim_detector(detector_id: &str) -> bool {
    matches!(
        detector_id,
        "jwt.attribute.subject"
            | "jwt.attribute.user_id"
            | "jwt.attribute.tenant_id"
            | "jwt.attribute.org_id"
            | "jwt.attribute.workspace_id"
            | "jwt.attribute.roles"
            | "jwt.attribute.scopes"
            | "jwt.attribute.groups"
            | "jwt.attribute.email"
            | "jwt.attribute.email_verified"
            | "jwt.attribute.auth_method"
            | "jwt.attribute.auth_class"
    )
}

fn collect_artifact_evidence(
    artifact: &Artifact,
    evidence_ids: &mut BTreeSet<EvidenceId>,
    area: CapabilityArea,
) {
    match area {
        CapabilityArea::Claims => {
            if let Some(claims) = artifact
                .jwt_attributes
                .as_ref()
                .and_then(|attributes| attributes.identity_claims.as_ref())
            {
                evidence_ids.extend(claims.subject.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.user_id.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.tenant_id.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.org_id.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.workspace_id.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.roles.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.scopes.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.groups.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.email.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.email_verified.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.auth_method.evidence_ids.iter().cloned());
                evidence_ids.extend(claims.auth_class.evidence_ids.iter().cloned());
            }
        }
        CapabilityArea::Cookies => {
            evidence_ids.extend(artifact.lifecycle_evidence.issue.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.store.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.transmit.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.validate.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.refresh.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.revoke.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.expire.iter().cloned());
            evidence_ids.extend(artifact.lifecycle_evidence.introspect.iter().cloned());
            if let Some(attributes) = &artifact.cookie_attributes {
                evidence_ids.extend(attributes.http_only.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.secure.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.same_site.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.max_age.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.expires.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.path.evidence_ids.iter().cloned());
                evidence_ids.extend(attributes.domain.evidence_ids.iter().cloned());
            }
        }
        CapabilityArea::Logout => {
            evidence_ids.extend(artifact.lifecycle_evidence.revoke.iter().cloned());
        }
        CapabilityArea::Refresh => {
            evidence_ids.extend(artifact.lifecycle_evidence.refresh.iter().cloned());
        }
    }
}

fn artifact_has_evidence(artifact: &Artifact, evidence_ids: &BTreeSet<EvidenceId>) -> bool {
    artifact
        .lifecycle_evidence
        .issue
        .iter()
        .chain(&artifact.lifecycle_evidence.store)
        .chain(&artifact.lifecycle_evidence.transmit)
        .chain(&artifact.lifecycle_evidence.validate)
        .chain(&artifact.lifecycle_evidence.refresh)
        .chain(&artifact.lifecycle_evidence.revoke)
        .chain(&artifact.lifecycle_evidence.expire)
        .chain(&artifact.lifecycle_evidence.introspect)
        .any(|id| evidence_ids.contains(id))
}

fn path_matches(
    path: &LifecyclePath,
    artifact_ids: &BTreeSet<ArtifactId>,
    evidence_ids: &BTreeSet<EvidenceId>,
) -> bool {
    path.artifact_ids.iter().any(|id| artifact_ids.contains(id))
        || path
            .stages
            .iter()
            .flat_map(|step| step.evidence_ids.iter())
            .any(|id| evidence_ids.contains(id))
}

fn finding_matches(
    area: CapabilityArea,
    finding: &sessionscope_model::Finding,
    artifact_ids: &BTreeSet<ArtifactId>,
    evidence_ids: &BTreeSet<EvidenceId>,
) -> bool {
    if finding
        .evidence_ids
        .iter()
        .any(|id| evidence_ids.contains(id))
    {
        return true;
    }

    let title = finding.title.to_ascii_lowercase();
    match area {
        CapabilityArea::Cookies => {
            finding
                .artifact_ids
                .iter()
                .any(|id| artifact_ids.contains(id))
                && (title.contains("cookie")
                    || title.contains("samesite")
                    || title.contains("secure")
                    || title.contains("httponly"))
        }
        CapabilityArea::Claims => {
            title.contains("claim")
                || title.contains("subject")
                || title.contains("tenant")
                || title.contains("role")
                || title.contains("scope")
                || title.contains("group")
                || title.contains("email")
        }
        CapabilityArea::Logout => {
            title.contains("logout") || title.contains("revoke") || title.contains("revocation")
        }
        CapabilityArea::Refresh => {
            title.contains("refresh")
                && finding
                    .artifact_ids
                    .iter()
                    .any(|id| artifact_ids.contains(id))
        }
    }
}

fn filter_file(
    file: &FileScanResult,
    artifact_ids: &BTreeSet<ArtifactId>,
    evidence_ids: &BTreeSet<EvidenceId>,
) -> FileScanResult {
    let mut file = file.clone();
    file.artifacts
        .retain(|artifact| artifact_ids.contains(&artifact.id));
    file.evidence
        .retain(|evidence| evidence_ids.contains(&evidence.id));
    file.diagnostics.clear();
    file
}

fn summarize_files(files: &[FileScanResult]) -> ScanSummary {
    ScanSummary {
        files_discovered: files.len(),
        files_scanned: files
            .iter()
            .filter(|file| file.skipped_reason.is_none())
            .count(),
        files_skipped: files
            .iter()
            .filter(|file| file.skipped_reason.is_some())
            .count(),
        diagnostics: files
            .iter()
            .flat_map(|file| file.diagnostics.iter().cloned())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Artifact, ArtifactId, ArtifactType, Confidence, Evidence, EvidenceId, FileScanResult,
        Finding, FindingCategory, FindingId, JwtAttributeObservation, JwtAttributeState,
        JwtAttributes, JwtIdentityClaims, Language, LifecycleEvidence, LifecycleStage,
        SCHEMA_VERSION, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::{CapabilityArea, filter_report};

    #[test]
    fn cookies_filter_keeps_cookie_artifacts_and_evidence() {
        let report = report(
            vec![artifact("cookie", ArtifactType::SessionCookie, "session")],
            vec![evidence(
                "cookie_evidence",
                "cookie.set",
                LifecycleStage::Store,
            )],
        );

        let filtered = filter_report(&report, CapabilityArea::Cookies);

        assert_eq!(filtered.artifacts.len(), 1);
        assert_eq!(filtered.evidence.len(), 1);
    }

    #[test]
    fn claims_filter_keeps_identity_claim_inventory() {
        let mut artifact = artifact("jwt", ArtifactType::AccessJwt, "access_jwt");
        let claim_evidence = EvidenceId("claim_evidence".to_string());
        artifact.jwt_attributes = Some(jwt_attributes_with_subject(claim_evidence.clone()));
        let report = report(
            vec![artifact],
            vec![evidence(
                &claim_evidence.0,
                "jwt.attribute.subject",
                LifecycleStage::Issue,
            )],
        );

        let filtered = filter_report(&report, CapabilityArea::Claims);

        assert_eq!(filtered.artifacts.len(), 1);
        assert_eq!(filtered.evidence[0].id, claim_evidence);
    }

    #[test]
    fn logout_filter_keeps_revoke_evidence() {
        let report = report(
            vec![artifact("logout", ArtifactType::Unknown, "logout")],
            vec![evidence(
                "logout_evidence",
                "logout.cookie_clear",
                LifecycleStage::Revoke,
            )],
        );

        let filtered = filter_report(&report, CapabilityArea::Logout);

        assert_eq!(filtered.evidence.len(), 1);
        assert_eq!(filtered.evidence[0].lifecycle_stage, LifecycleStage::Revoke);
    }

    #[test]
    fn refresh_filter_keeps_refresh_artifacts_and_evidence() {
        let mut refresh = artifact("refresh", ArtifactType::RefreshJwt, "refresh_token");
        refresh.lifecycle_evidence.refresh = vec![EvidenceId("refresh_evidence".to_string())];
        let report = report(
            vec![refresh],
            vec![evidence(
                "refresh_evidence",
                "refresh.handler",
                LifecycleStage::Refresh,
            )],
        );

        let filtered = filter_report(&report, CapabilityArea::Refresh);

        assert_eq!(filtered.artifacts.len(), 1);
        assert_eq!(filtered.evidence.len(), 1);
    }

    #[test]
    fn logout_filter_excludes_unrelated_same_artifact_findings() {
        let mut cookie = artifact("cookie", ArtifactType::SessionCookie, "session");
        cookie.lifecycle_evidence.revoke = vec![EvidenceId("logout_evidence".to_string())];
        cookie.lifecycle_evidence.expire = vec![EvidenceId("expiry_evidence".to_string())];
        let mut report = report(
            vec![cookie],
            vec![
                evidence(
                    "logout_evidence",
                    "logout.cookie_clear",
                    LifecycleStage::Revoke,
                ),
                evidence("expiry_evidence", "cookie.set", LifecycleStage::Expire),
            ],
        );
        report.findings = vec![
            finding(
                "finding_logout",
                "Cookie is cleared on logout without linked server-side revocation",
                "cookie",
                "logout_evidence",
            ),
            finding(
                "finding_expiry",
                "Cookie 'session' has no explicit expiry evidence",
                "cookie",
                "expiry_evidence",
            ),
        ];

        let filtered = filter_report(&report, CapabilityArea::Logout);

        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].id.0, "finding_logout");
    }

    #[test]
    fn capability_filter_drops_unrelated_file_metadata() {
        let cookie_evidence = evidence("cookie_evidence", "cookie.set", LifecycleStage::Store);
        let unrelated_evidence = evidence(
            "unrelated_evidence",
            "jwt.validation.expiry",
            LifecycleStage::Validate,
        );
        let mut report = report(
            vec![artifact("cookie", ArtifactType::SessionCookie, "session")],
            vec![cookie_evidence.clone(), unrelated_evidence.clone()],
        );
        report.files = vec![
            file("src/cookie.ts", vec![cookie_evidence], Vec::new()),
            file(
                "src/unrelated.ts",
                vec![unrelated_evidence],
                vec!["PLACEHOLDER_SECRET_DO_NOT_USE".to_string()],
            ),
        ];
        report.summary.files_discovered = 2;
        report.summary.files_scanned = 2;
        report.summary.diagnostics = vec!["unrelated diagnostic".to_string()];

        let filtered = filter_report(&report, CapabilityArea::Cookies);

        assert_eq!(filtered.files.len(), 1);
        assert_eq!(filtered.files[0].path, "src/cookie.ts");
        assert_eq!(filtered.summary.files_discovered, 1);
        assert_eq!(filtered.summary.files_scanned, 1);
        assert!(filtered.summary.diagnostics.is_empty());
    }

    fn report(artifacts: Vec<Artifact>, evidence: Vec<Evidence>) -> ScanReport {
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

    fn artifact(id: &str, artifact_type: ArtifactType, name: &str) -> Artifact {
        Artifact {
            id: ArtifactId(id.to_string()),
            artifact_type,
            display_name: Some(name.to_string()),
            locations: Vec::new(),
            lifecycle_evidence: LifecycleEvidence::default(),
            confidence: Confidence::High,
            framework_hints: Vec::new(),
            cookie_attributes: None,
            jwt_attributes: None,
            token_boundary_attributes: None,
        }
    }

    fn evidence(id: &str, detector_id: &str, stage: LifecycleStage) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: stage,
            location: SourceLocation {
                path: "src/app.ts".to_string(),
                line: Some(1),
                column: Some(1),
            },
            detector_id: detector_id.to_string(),
            confidence: Confidence::High,
            excerpt: None,
            dynamic: false,
            framework_default: false,
        }
    }

    fn finding(id: &str, title: &str, artifact_id: &str, evidence_id: &str) -> Finding {
        Finding {
            id: FindingId(id.to_string()),
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            artifact_ids: vec![ArtifactId(artifact_id.to_string())],
            evidence_ids: vec![EvidenceId(evidence_id.to_string())],
            title: title.to_string(),
            description: "description".to_string(),
            suggested_fix: None,
            reviewer_question: None,
        }
    }

    fn file(path: &str, evidence: Vec<Evidence>, diagnostics: Vec<String>) -> FileScanResult {
        FileScanResult {
            path: path.to_string(),
            language: Language::TypeScript,
            artifacts: Vec::new(),
            evidence,
            diagnostics,
            skipped_reason: None,
        }
    }

    fn jwt_attributes_with_subject(evidence_id: EvidenceId) -> JwtAttributes {
        let unknown = JwtAttributeObservation {
            state: JwtAttributeState::Unknown,
            value: None,
            evidence_ids: Vec::new(),
            confidence: Confidence::Low,
        };
        let subject = JwtAttributeObservation {
            state: JwtAttributeState::Present,
            value: Some("userId".to_string()),
            evidence_ids: vec![evidence_id],
            confidence: Confidence::High,
        };
        JwtAttributes {
            operation: unknown.clone(),
            algorithm: unknown.clone(),
            key_reference: unknown.clone(),
            issuer: unknown.clone(),
            audience: unknown.clone(),
            expiration: unknown.clone(),
            signature_verification: unknown.clone(),
            expiry_enforcement: unknown.clone(),
            identity_claims: Some(JwtIdentityClaims {
                subject,
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
            }),
        }
    }
}
