pub mod bearer;
pub mod cookies;
pub mod jwt;
pub mod lifecycle;
pub mod trust_boundary;

use sessionscope_model::ScanReport;

pub fn classify(mut report: ScanReport) -> ScanReport {
    report.findings = Vec::new();
    report
}
