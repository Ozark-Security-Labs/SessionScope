use std::collections::{BTreeMap, BTreeSet};

use sessionscope_model::{
    BASELINE_SCHEMA_VERSION, Baseline, BaselineFinding, DIFF_SCHEMA_VERSION, DiffChangeKind,
    DiffFindingChange, DiffReport, DiffSummary, Evidence, Finding, ScanReport, SourceLocation,
};

pub fn create_baseline(report: &ScanReport, created_by: impl Into<String>) -> Baseline {
    let evidence_by_id = evidence_by_id(report);
    let mut findings = report
        .findings
        .iter()
        .map(|finding| baseline_finding(finding, &evidence_by_id))
        .collect::<Vec<_>>();

    sort_baseline_findings(&mut findings);

    Baseline {
        schema_version: BASELINE_SCHEMA_VERSION.to_string(),
        report_schema_version: report.schema_version.clone(),
        created_by: created_by.into(),
        findings,
    }
}

pub fn diff_baseline(baseline: &Baseline, current_report: &ScanReport) -> DiffReport {
    let current_baseline = create_baseline(current_report, baseline.created_by.clone());
    let mut changes = Vec::new();
    let mut matched_current = BTreeSet::new();
    let current_by_id = current_baseline
        .findings
        .iter()
        .map(|finding| (finding.id.0.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    for baseline_finding in &baseline.findings {
        if let Some(current) = current_by_id.get(baseline_finding.id.0.as_str()) {
            matched_current.insert(current.id.0.clone());
            changes.push(compare_matched(baseline_finding, current));
        }
    }

    for baseline_finding in &baseline.findings {
        if changes.iter().any(|change| {
            change
                .baseline
                .as_ref()
                .is_some_and(|finding| finding.id == baseline_finding.id)
        }) {
            continue;
        }

        if let Some(current) = find_fingerprint_match(
            baseline_finding,
            &current_baseline.findings,
            &matched_current,
        ) {
            matched_current.insert(current.id.0.clone());
            changes.push(DiffFindingChange {
                kind: DiffChangeKind::Moved,
                baseline: Some(baseline_finding.clone()),
                current: Some(current.clone()),
            });
        } else {
            changes.push(DiffFindingChange {
                kind: DiffChangeKind::Resolved,
                baseline: Some(baseline_finding.clone()),
                current: None,
            });
        }
    }

    for current in &current_baseline.findings {
        if !matched_current.contains(&current.id.0) {
            changes.push(DiffFindingChange {
                kind: DiffChangeKind::New,
                baseline: None,
                current: Some(current.clone()),
            });
        }
    }

    changes.sort_by_key(change_key);
    let summary = summarize(&changes);

    DiffReport {
        schema_version: DIFF_SCHEMA_VERSION.to_string(),
        baseline_schema_version: baseline.schema_version.clone(),
        current_report_schema_version: current_report.schema_version.clone(),
        summary,
        changes,
    }
}

fn compare_matched(baseline: &BaselineFinding, current: &BaselineFinding) -> DiffFindingChange {
    let kind = if baseline.semantic_fingerprint == current.semantic_fingerprint
        && baseline.evidence_fingerprint == current.evidence_fingerprint
    {
        if baseline.source_locations == current.source_locations {
            DiffChangeKind::Unchanged
        } else {
            DiffChangeKind::Moved
        }
    } else {
        DiffChangeKind::Changed
    };

    DiffFindingChange {
        kind,
        baseline: Some(baseline.clone()),
        current: Some(current.clone()),
    }
}

fn find_fingerprint_match<'a>(
    baseline: &BaselineFinding,
    current_findings: &'a [BaselineFinding],
    matched_current: &BTreeSet<String>,
) -> Option<&'a BaselineFinding> {
    current_findings.iter().find(|current| {
        !matched_current.contains(&current.id.0)
            && current.semantic_fingerprint == baseline.semantic_fingerprint
            && current.evidence_fingerprint == baseline.evidence_fingerprint
    })
}

fn baseline_finding(
    finding: &Finding,
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> BaselineFinding {
    let mut artifact_ids = finding.artifact_ids.clone();
    artifact_ids.sort();
    let mut evidence_ids = finding.evidence_ids.clone();
    evidence_ids.sort();
    let mut source_locations = evidence_ids
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()))
        .map(|evidence| evidence.location.clone())
        .collect::<Vec<_>>();
    sort_locations(&mut source_locations);
    source_locations.dedup();

    BaselineFinding {
        id: finding.id.clone(),
        category: finding.category,
        severity: finding.severity,
        title: finding.title.clone(),
        semantic_fingerprint: semantic_fingerprint(finding),
        evidence_fingerprint: evidence_fingerprint(&evidence_ids, evidence_by_id),
        artifact_ids,
        evidence_ids,
        source_locations,
    }
}

fn semantic_fingerprint(finding: &Finding) -> String {
    stable_fingerprint(&[
        format!("{:?}", finding.category),
        format!("{:?}", finding.severity),
        finding.title.clone(),
        finding.description.clone(),
        finding.suggested_fix.clone().unwrap_or_default(),
        finding.reviewer_question.clone().unwrap_or_default(),
    ])
}

fn evidence_fingerprint(
    evidence_ids: &[sessionscope_model::EvidenceId],
    evidence_by_id: &BTreeMap<&str, &Evidence>,
) -> String {
    let mut parts = Vec::new();
    for evidence_id in evidence_ids {
        if let Some(evidence) = evidence_by_id.get(evidence_id.0.as_str()) {
            parts.push(format!("{:?}", evidence.lifecycle_stage));
            parts.push(evidence.detector_id.clone());
            parts.push(format!("{:?}", evidence.confidence));
            parts.push(evidence.dynamic.to_string());
            parts.push(evidence.framework_default.to_string());
            parts.push(
                evidence
                    .excerpt
                    .as_ref()
                    .map(|excerpt| excerpt.0.clone())
                    .unwrap_or_default(),
            );
        } else {
            parts.push(evidence_id.0.clone());
        }
    }

    stable_fingerprint(&parts)
}

fn stable_fingerprint(parts: &[String]) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for part in parts {
        for byte in part.trim().replace('\\', "/").bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    format!("fingerprint_{hash:016x}")
}

fn evidence_by_id(report: &ScanReport) -> BTreeMap<&str, &Evidence> {
    report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect()
}

fn sort_baseline_findings(findings: &mut [BaselineFinding]) {
    for finding in findings.iter_mut() {
        finding.artifact_ids.sort();
        finding.evidence_ids.sort();
        sort_locations(&mut finding.source_locations);
    }

    findings.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.semantic_fingerprint.cmp(&right.semantic_fingerprint))
            .then_with(|| left.evidence_fingerprint.cmp(&right.evidence_fingerprint))
    });
}

fn sort_locations(locations: &mut [SourceLocation]) {
    locations.sort_by(|left, right| location_key(left).cmp(&location_key(right)));
}

fn location_key(location: &SourceLocation) -> (&str, usize, usize) {
    (
        location.path.as_str(),
        location.line.unwrap_or(usize::MAX),
        location.column.unwrap_or(usize::MAX),
    )
}

fn change_key(change: &DiffFindingChange) -> (DiffChangeKind, String) {
    let id = change
        .current
        .as_ref()
        .or(change.baseline.as_ref())
        .map(|finding| finding.id.0.clone())
        .unwrap_or_default();
    (change.kind, id)
}

fn summarize(changes: &[DiffFindingChange]) -> DiffSummary {
    let mut summary = DiffSummary::default();
    for change in changes {
        match change.kind {
            DiffChangeKind::New => summary.new += 1,
            DiffChangeKind::Unchanged => summary.unchanged += 1,
            DiffChangeKind::Changed => summary.changed += 1,
            DiffChangeKind::Moved => summary.moved += 1,
            DiffChangeKind::Resolved => summary.resolved += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        Confidence, Evidence, EvidenceId, Finding, FindingCategory, FindingId, LifecycleStage,
        SCHEMA_VERSION, SanitizedExcerpt, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::{create_baseline, diff_baseline};
    use sessionscope_model::DiffChangeKind;

    #[test]
    fn diff_classifies_unchanged_new_resolved_changed_and_moved_findings() {
        let baseline_report = report(vec![
            finding("finding_unchanged", "unchanged", "evidence_unchanged"),
            finding("finding_changed", "changed", "evidence_changed"),
            finding("finding_moved_old", "moved", "evidence_moved_old"),
            finding("finding_resolved", "resolved", "evidence_resolved"),
        ]);
        let current_report = report(vec![
            finding("finding_unchanged", "unchanged", "evidence_unchanged"),
            finding_with_description("finding_changed", "changed", "evidence_changed", "updated"),
            finding("finding_moved_new", "moved", "evidence_moved_new"),
            finding("finding_new", "new", "evidence_new"),
        ]);

        let baseline = create_baseline(&baseline_report, "test");
        let diff = diff_baseline(&baseline, &current_report);

        assert_eq!(diff.summary.unchanged, 1);
        assert_eq!(diff.summary.changed, 1);
        assert_eq!(diff.summary.moved, 1);
        assert_eq!(diff.summary.resolved, 1);
        assert_eq!(diff.summary.new, 1);
        assert!(diff.changes.iter().any(|change| {
            change.kind == DiffChangeKind::Moved
                && change
                    .baseline
                    .as_ref()
                    .is_some_and(|finding| finding.id.0 == "finding_moved_old")
                && change
                    .current
                    .as_ref()
                    .is_some_and(|finding| finding.id.0 == "finding_moved_new")
        }));
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        let evidence = findings
            .iter()
            .flat_map(|finding| {
                finding.evidence_ids.iter().map(|id| Evidence {
                    id: id.clone(),
                    lifecycle_stage: LifecycleStage::Validate,
                    location: SourceLocation {
                        path: "src/auth.ts".to_string(),
                        line: Some(if id.0.contains("moved_new") { 20 } else { 10 }),
                        column: Some(1),
                    },
                    detector_id: "test.detector".to_string(),
                    confidence: Confidence::High,
                    excerpt: Some(SanitizedExcerpt(format!("evidence for {}", finding.title))),
                    dynamic: false,
                    framework_default: false,
                })
            })
            .collect();

        ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence,
            lifecycle_paths: Vec::new(),
            findings,
        }
    }

    fn finding(id: &str, title: &str, evidence_id: &str) -> Finding {
        finding_with_description(id, title, evidence_id, "description")
    }

    fn finding_with_description(
        id: &str,
        title: &str,
        evidence_id: &str,
        description: &str,
    ) -> Finding {
        Finding {
            id: FindingId(id.to_string()),
            category: FindingCategory::LifecycleGap,
            severity: Severity::Medium,
            artifact_ids: Vec::new(),
            evidence_ids: vec![EvidenceId(evidence_id.to_string())],
            title: title.to_string(),
            description: description.to_string(),
            suggested_fix: None,
            reviewer_question: None,
        }
    }
}
