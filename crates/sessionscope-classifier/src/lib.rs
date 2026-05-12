pub mod bearer;
pub mod cookies;
pub mod jwt;
pub mod lifecycle;
pub mod trust_boundary;

use sessionscope_model::ScanReport;

pub fn classify(mut report: ScanReport) -> ScanReport {
    report.lifecycle_paths = lifecycle::link(&report);
    report.findings = cookies::classify(&report);
    report.findings.extend(jwt::classify(&report));
    report.findings.extend(bearer::classify(&report));
    report.findings.extend(lifecycle::classify(&report));
    sort_findings(&mut report);
    report
}

fn sort_findings(report: &mut ScanReport) {
    report.findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.artifact_ids.cmp(&right.artifact_ids))
            .then_with(|| left.evidence_ids.cmp(&right.evidence_ids))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn severity_rank(severity: sessionscope_model::Severity) -> u8 {
    match severity {
        sessionscope_model::Severity::Info => 0,
        sessionscope_model::Severity::Low => 1,
        sessionscope_model::Severity::Medium => 2,
        sessionscope_model::Severity::High => 3,
    }
}
