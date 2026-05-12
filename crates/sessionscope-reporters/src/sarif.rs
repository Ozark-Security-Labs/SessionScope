use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sessionscope_model::{
    Evidence, Finding, FindingCategory, ScanReport, Severity, SourceLocation,
};

pub fn render(report: &ScanReport) -> String {
    let evidence_by_id = report
        .evidence
        .iter()
        .map(|evidence| (evidence.id.0.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let rules = rules(report);
    let results = report
        .findings
        .iter()
        .map(|finding| result(finding, &evidence_by_id))
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SessionScope",
                    "rules": rules
                }
            },
            "results": results
        }]
    }))
    .expect("SARIF serialization should not fail")
}

fn rules(report: &ScanReport) -> Vec<Value> {
    report
        .findings
        .iter()
        .map(|finding| finding.category)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|category| {
            json!({
                "id": format_category(category),
                "name": format_category(category),
                "shortDescription": {
                    "text": format_category(category)
                }
            })
        })
        .collect()
}

fn result(finding: &Finding, evidence_by_id: &BTreeMap<&str, &Evidence>) -> Value {
    let locations = finding_locations(finding, evidence_by_id);
    let artifact_ids = finding
        .artifact_ids
        .iter()
        .map(|id| id.0.as_str())
        .collect::<Vec<_>>();
    let evidence_ids = finding
        .evidence_ids
        .iter()
        .map(|id| id.0.as_str())
        .collect::<Vec<_>>();

    json!({
        "ruleId": format_category(finding.category),
        "level": sarif_level(finding.severity),
        "message": {
            "text": finding.description.as_str()
        },
        "locations": locations,
        "partialFingerprints": {
            "sessionscopeFindingId": finding.id.0
        },
        "properties": {
            "finding_id": finding.id.0.as_str(),
            "title": finding.title.as_str(),
            "severity": format_severity(finding.severity),
            "category": format_category(finding.category),
            "artifact_ids": artifact_ids,
            "evidence_ids": evidence_ids,
            "suggested_fix": finding.suggested_fix.as_deref(),
            "reviewer_question": finding.reviewer_question.as_deref()
        }
    })
}

fn finding_locations(finding: &Finding, evidence_by_id: &BTreeMap<&str, &Evidence>) -> Vec<Value> {
    finding
        .evidence_ids
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()))
        .map(|evidence| location(&evidence.location))
        .collect()
}

fn location(location: &SourceLocation) -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": location.path
            },
            "region": {
                "startLine": location.line.unwrap_or(1),
                "startColumn": location.column.unwrap_or(1)
            }
        }
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn format_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

fn format_category(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::HighConfidenceMisconfiguration => "high_confidence_misconfiguration",
        FindingCategory::MissingValidationEvidence => "missing_validation_evidence",
        FindingCategory::LifecycleGap => "lifecycle_gap",
        FindingCategory::DynamicReviewRequired => "dynamic_review_required",
        FindingCategory::FrameworkDefaultAssumed => "framework_default_assumed",
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Evidence, EvidenceId, Finding, FindingCategory, FindingId, LifecycleStage,
        SCHEMA_VERSION, SanitizedExcerpt, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::render;

    #[test]
    fn renders_findings_as_sarif_results() {
        let evidence_id = EvidenceId("evidence_cookie_secure".to_string());
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary::default(),
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: vec![Evidence {
                id: evidence_id.clone(),
                lifecycle_stage: LifecycleStage::Transmit,
                location: SourceLocation {
                    path: "src/app.ts".to_string(),
                    line: Some(7),
                    column: Some(3),
                },
                detector_id: "cookie.attribute.secure".to_string(),
                confidence: sessionscope_model::Confidence::High,
                excerpt: Some(SanitizedExcerpt("Secure is omitted".to_string())),
                dynamic: false,
                framework_default: false,
            }],
            findings: vec![Finding {
                id: FindingId("finding_cookie".to_string()),
                category: FindingCategory::HighConfidenceMisconfiguration,
                severity: Severity::High,
                artifact_ids: vec![ArtifactId("artifact_cookie".to_string())],
                evidence_ids: vec![evidence_id],
                title: "Cookie does not set Secure".to_string(),
                description: "No Secure attribute evidence was detected.".to_string(),
                suggested_fix: Some("Set Secure.".to_string()),
                reviewer_question: Some("Is this production?".to_string()),
            }],
        };

        let rendered = render(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("SARIF should parse as JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "high_confidence_misconfiguration"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["ruleId"],
            "high_confidence_misconfiguration"
        );
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/app.ts"
        );
    }
}
