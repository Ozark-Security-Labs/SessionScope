use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use sessionscope_model::{Finding, FindingCategory, FindingId, ScanReport, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementOptions {
    pub mode: PolicyMode,
    pub fail_severity: Severity,
    pub fail_categories: Option<BTreeSet<FindingCategory>>,
    pub include_finding_ids: BTreeSet<String>,
    pub exclude_finding_ids: BTreeSet<String>,
    pub baseline: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Advisory,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementResult {
    pub blocking_findings: Vec<Finding>,
}

impl Default for EnforcementOptions {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Advisory,
            fail_severity: Severity::High,
            fail_categories: None,
            include_finding_ids: BTreeSet::new(),
            exclude_finding_ids: BTreeSet::new(),
            baseline: None,
        }
    }
}

impl EnforcementOptions {
    pub fn evaluate(&self, report: &ScanReport) -> Result<EnforcementResult, String> {
        let baseline_ids = match &self.baseline {
            Some(path) => load_baseline_ids(path)?,
            None => BTreeSet::new(),
        };

        if self.mode == PolicyMode::Advisory {
            return Ok(EnforcementResult {
                blocking_findings: Vec::new(),
            });
        }

        let blocking_findings = report
            .findings
            .iter()
            .filter(|finding| self.blocks(finding, &baseline_ids))
            .cloned()
            .collect();

        Ok(EnforcementResult { blocking_findings })
    }

    fn blocks(&self, finding: &Finding, baseline_ids: &BTreeSet<String>) -> bool {
        let id = finding.id.0.as_str();
        if self.exclude_finding_ids.contains(id) {
            return false;
        }

        if self.include_finding_ids.contains(id) {
            return true;
        }

        if baseline_ids.contains(id) {
            return false;
        }

        finding.severity >= self.fail_severity
            && self
                .fail_categories
                .as_ref()
                .is_none_or(|categories| categories.contains(&finding.category))
    }
}

pub fn parse_mode(value: &str) -> Result<PolicyMode, String> {
    match value {
        "advisory" => Ok(PolicyMode::Advisory),
        "enforce" => Ok(PolicyMode::Enforce),
        _ => Err("mode must be advisory or enforce".to_string()),
    }
}

pub fn parse_severity(value: &str) -> Result<Severity, String> {
    match value {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        _ => Err("fail severity must be info, low, medium, or high".to_string()),
    }
}

pub fn parse_category(value: &str) -> Result<FindingCategory, String> {
    match value {
        "high_confidence_misconfiguration" => Ok(FindingCategory::HighConfidenceMisconfiguration),
        "missing_validation_evidence" => Ok(FindingCategory::MissingValidationEvidence),
        "lifecycle_gap" => Ok(FindingCategory::LifecycleGap),
        "dynamic_review_required" => Ok(FindingCategory::DynamicReviewRequired),
        "framework_default_assumed" => Ok(FindingCategory::FrameworkDefaultAssumed),
        _ => Err("fail category must match a SessionScope finding category".to_string()),
    }
}

pub fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

pub fn category_name(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::HighConfidenceMisconfiguration => "high_confidence_misconfiguration",
        FindingCategory::MissingValidationEvidence => "missing_validation_evidence",
        FindingCategory::LifecycleGap => "lifecycle_gap",
        FindingCategory::DynamicReviewRequired => "dynamic_review_required",
        FindingCategory::FrameworkDefaultAssumed => "framework_default_assumed",
    }
}

pub fn format_failure(result: &EnforcementResult) -> String {
    let mut lines = vec![format!(
        "enforce mode blocked {} finding(s)",
        result.blocking_findings.len()
    )];

    for finding in result.blocking_findings.iter().take(5) {
        lines.push(format!(
            "- {} {} {} {}",
            finding.id.0,
            severity_name(finding.severity),
            category_name(finding.category),
            finding.title.replace('\n', " ")
        ));
    }

    if result.blocking_findings.len() > 5 {
        lines.push(format!(
            "- ...and {} more blocking finding(s)",
            result.blocking_findings.len() - 5
        ));
    }

    lines.join("\n")
}

pub fn split_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn load_baseline_ids(path: &PathBuf) -> Result<BTreeSet<String>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read baseline {}: {error}", path.display()))?;
    let baseline: BaselineReport = serde_json::from_str(&contents)
        .map_err(|_| format!("failed to parse baseline {} as JSON report", path.display()))?;

    Ok(baseline
        .findings
        .into_iter()
        .map(|finding| finding.id.0)
        .collect())
}

#[derive(Debug, Deserialize)]
struct BaselineReport {
    findings: Vec<BaselineFinding>,
}

#[derive(Debug, Deserialize)]
struct BaselineFinding {
    id: FindingId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessionscope_model::ScanSummary;

    fn finding(id: &str, severity: Severity, category: FindingCategory) -> Finding {
        Finding {
            id: FindingId(id.to_string()),
            category,
            severity,
            artifact_ids: Vec::new(),
            evidence_ids: Vec::new(),
            title: format!("Finding {id}"),
            description: String::new(),
            suggested_fix: None,
            reviewer_question: None,
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            schema_version: "0.1.0".to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: Vec::new(),
            lifecycle_paths: Vec::new(),
            findings,
        }
    }

    #[test]
    fn advisory_mode_never_blocks_findings() {
        let options = EnforcementOptions::default();
        let result = options
            .evaluate(&report(vec![finding(
                "one",
                Severity::High,
                FindingCategory::HighConfidenceMisconfiguration,
            )]))
            .expect("evaluation should succeed");

        assert!(result.blocking_findings.is_empty());
    }

    #[test]
    fn enforce_default_blocks_high_findings_only() {
        let options = EnforcementOptions {
            mode: PolicyMode::Enforce,
            ..EnforcementOptions::default()
        };
        let result = options
            .evaluate(&report(vec![
                finding(
                    "medium",
                    Severity::Medium,
                    FindingCategory::HighConfidenceMisconfiguration,
                ),
                finding(
                    "high",
                    Severity::High,
                    FindingCategory::HighConfidenceMisconfiguration,
                ),
            ]))
            .expect("evaluation should succeed");

        assert_eq!(result.blocking_findings.len(), 1);
        assert_eq!(result.blocking_findings[0].id.0, "high");
    }

    #[test]
    fn include_and_exclude_ids_follow_precedence() {
        let options = EnforcementOptions {
            mode: PolicyMode::Enforce,
            include_finding_ids: ["included".to_string(), "excluded".to_string()].into(),
            exclude_finding_ids: ["excluded".to_string()].into(),
            ..EnforcementOptions::default()
        };
        let result = options
            .evaluate(&report(vec![
                finding(
                    "included",
                    Severity::Info,
                    FindingCategory::FrameworkDefaultAssumed,
                ),
                finding(
                    "excluded",
                    Severity::High,
                    FindingCategory::HighConfidenceMisconfiguration,
                ),
            ]))
            .expect("evaluation should succeed");

        assert_eq!(result.blocking_findings.len(), 1);
        assert_eq!(result.blocking_findings[0].id.0, "included");
    }
}
