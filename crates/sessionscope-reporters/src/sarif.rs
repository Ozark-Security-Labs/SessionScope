use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sessionscope_model::{Evidence, Finding, FindingCategory, ScanReport, Severity};

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
            let metadata = rule_metadata(category);
            let mut properties = json!({
                "category": format_category(category),
                "tags": metadata.tags,
                "precision": metadata.precision
            });
            if let Some(security_severity) = metadata.security_severity {
                properties["security-severity"] = json!(security_severity);
            }
            json!({
                "id": format_category(category),
                "name": metadata.name,
                "shortDescription": {
                    "text": metadata.short_description
                },
                "fullDescription": {
                    "text": metadata.full_description
                },
                "help": {
                    "text": metadata.help
                },
                "properties": properties
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

    let message = result_message(finding);

    json!({
        "ruleId": format_category(finding.category),
        "level": sarif_level(finding.severity),
        "message": {
            "text": message
        },
        "locations": locations,
        "partialFingerprints": {
            "sessionscopeFindingId": finding.id.0
        },
        "properties": {
            "finding_id": finding.id.0.as_str(),
            "title": finding.title.as_str(),
            "description": finding.description.as_str(),
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
    let mut seen = BTreeSet::new();
    finding
        .evidence_ids
        .iter()
        .filter_map(|id| evidence_by_id.get(id.0.as_str()))
        .filter_map(|evidence| {
            let key = (
                evidence.location.path.as_str(),
                evidence.location.line,
                evidence.location.column,
            );
            seen.insert(key).then(|| location(evidence))
        })
        .collect()
}

fn location(evidence: &Evidence) -> Value {
    let location = &evidence.location;
    let mut region = json!({
        "startLine": location.line.unwrap_or(1),
        "startColumn": location.column.unwrap_or(1)
    });
    if let Some(excerpt) = evidence
        .excerpt
        .as_ref()
        .filter(|excerpt| !excerpt.is_empty())
    {
        region["snippet"] = json!({
            "text": excerpt.as_str()
        });
    }

    json!({
        "physicalLocation": {
            "artifactLocation": {
                "uri": location.path
            },
            "region": region
        }
    })
}

fn result_message(finding: &Finding) -> String {
    let mut parts = vec![format!("{}: {}", finding.title, finding.description)];
    if let Some(suggested_fix) = finding.suggested_fix.as_ref() {
        parts.push(format!("Suggested fix: {suggested_fix}"));
    }
    if let Some(reviewer_question) = finding.reviewer_question.as_ref() {
        parts.push(format!("Reviewer question: {reviewer_question}"));
    }
    parts.join("\n\n")
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

struct RuleMetadata {
    name: &'static str,
    short_description: &'static str,
    full_description: &'static str,
    help: &'static str,
    tags: &'static [&'static str],
    precision: &'static str,
    security_severity: Option<&'static str>,
}

// security-severity is a GitHub Code Scanning convention. Values map to bands:
//   high   >= 7.0   HighConfidenceMisconfiguration -> 8.0 (deterministic source evidence)
//   medium >= 4.0   MissingValidationEvidence      -> 6.5 (validation gap, framework-dependent)
//   medium >= 4.0   LifecycleGap                   -> 5.5 (complementary control missing)
//   omitted         DynamicReviewRequired, FrameworkDefaultAssumed render as "note"
// Adjust tiers only with a corresponding SS-DEC entry; downstream consumers may pin to them.
fn rule_metadata(category: FindingCategory) -> RuleMetadata {
    match category {
        FindingCategory::HighConfidenceMisconfiguration => RuleMetadata {
            name: "High-confidence session or token misconfiguration",
            short_description: "Deterministic session or token misconfiguration evidence.",
            full_description: "SessionScope found direct source evidence of an unsafe session, cookie, JWT, or token lifecycle setting.",
            help: "Review the source location and apply the suggested fix. These findings are based on deterministic local evidence.",
            tags: &[
                "security",
                "sessionscope",
                "session-management",
                "token-lifecycle",
            ],
            precision: "high",
            security_severity: Some("8.0"),
        },
        FindingCategory::MissingValidationEvidence => RuleMetadata {
            name: "Missing validation evidence",
            short_description: "Expected token validation evidence was not found near token use.",
            full_description: "SessionScope found token validation code without nearby evidence for required validation attributes such as issuer, audience, signature, or expiry enforcement.",
            help: "Confirm whether validation is enforced by framework or wrapper code. Add explicit validation when the current source path accepts tokens without the expected checks.",
            tags: &[
                "security",
                "sessionscope",
                "authentication",
                "token-validation",
            ],
            precision: "medium",
            security_severity: Some("6.5"),
        },
        FindingCategory::LifecycleGap => RuleMetadata {
            name: "Token lifecycle gap",
            short_description: "Token lifecycle evidence is missing a related lifecycle control.",
            full_description: "SessionScope found evidence for one part of a token lifecycle without linked evidence for a complementary control such as rotation, revocation, or expiry.",
            help: "Review the linked artifact and evidence to determine whether the missing lifecycle control exists outside the scanned source path.",
            tags: &[
                "security",
                "sessionscope",
                "session-management",
                "token-lifecycle",
            ],
            precision: "medium",
            security_severity: Some("5.5"),
        },
        FindingCategory::DynamicReviewRequired => RuleMetadata {
            name: "Dynamic review required",
            short_description: "Session or token behavior depends on dynamic runtime context.",
            full_description: "SessionScope found evidence that requires human review because static source alone cannot determine the effective session or token behavior.",
            help: "Inspect the referenced source and runtime configuration to confirm the effective behavior in the relevant environment.",
            tags: &["sessionscope", "review-required", "token-lifecycle"],
            precision: "low",
            security_severity: None,
        },
        FindingCategory::FrameworkDefaultAssumed => RuleMetadata {
            name: "Framework default assumed",
            short_description: "SessionScope inferred behavior from framework defaults.",
            full_description: "SessionScope found behavior that appears to rely on framework defaults rather than explicit local configuration.",
            help: "Verify the framework version and runtime settings, then make security-relevant behavior explicit when practical.",
            tags: &["sessionscope", "framework-default", "token-lifecycle"],
            precision: "low",
            security_severity: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{
        ArtifactId, Evidence, EvidenceId, Finding, FindingCategory, FindingId, LifecycleStage,
        SCHEMA_VERSION, SanitizedExcerpt, ScanReport, ScanSummary, Severity, SourceLocation,
    };

    use super::render;

    fn report_with_findings(findings: Vec<Finding>, evidence: Vec<Evidence>) -> ScanReport {
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

    fn evidence(id: &str, path: &str, excerpt: Option<&str>) -> Evidence {
        Evidence {
            id: EvidenceId(id.to_string()),
            lifecycle_stage: LifecycleStage::Transmit,
            location: SourceLocation {
                path: path.to_string(),
                line: Some(7),
                column: Some(3),
            },
            detector_id: "cookie.attribute.secure".to_string(),
            confidence: sessionscope_model::Confidence::High,
            excerpt: excerpt.map(|value| SanitizedExcerpt::from_sanitized(value.to_string())),
            dynamic: false,
            framework_default: false,
        }
    }

    fn finding(
        id: &str,
        category: FindingCategory,
        severity: Severity,
        evidence_ids: Vec<&str>,
    ) -> Finding {
        Finding {
            id: FindingId(id.to_string()),
            category,
            severity,
            artifact_ids: vec![ArtifactId("artifact_cookie".to_string())],
            evidence_ids: evidence_ids
                .into_iter()
                .map(|id| EvidenceId(id.to_string()))
                .collect(),
            title: "Cookie does not set Secure".to_string(),
            description: "No Secure attribute evidence was detected.".to_string(),
            suggested_fix: Some("Set Secure.".to_string()),
            reviewer_question: Some("Is this production?".to_string()),
        }
    }

    #[test]
    fn renders_findings_as_sarif_results() {
        let report = report_with_findings(
            vec![finding(
                "finding_cookie",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                vec!["evidence_cookie_secure"],
            )],
            vec![evidence(
                "evidence_cookie_secure",
                "src/app.ts",
                Some("response.cookie(\"session\", [REDACTED])"),
            )],
        );

        let rendered = render(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("SARIF should parse as JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "high_confidence_misconfiguration"
        );
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"],
            "Deterministic session or token misconfiguration evidence."
        );
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"][0],
            "security"
        );
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
            "8.0"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["ruleId"],
            "high_confidence_misconfiguration"
        );
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert!(
            parsed["runs"][0]["results"][0]["message"]["text"]
                .as_str()
                .expect("result message")
                .contains("Suggested fix: Set Secure.")
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["properties"]["description"],
            "No Secure attribute evidence was detected."
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/app.ts"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"]
                ["text"],
            "response.cookie(\"session\", [REDACTED])"
        );
        assert_eq!(
            parsed["runs"][0]["results"][0]["partialFingerprints"]["sessionscopeFindingId"],
            "finding_cookie"
        );
    }

    #[test]
    fn dynamic_review_results_are_notes_without_security_severity() {
        let report = report_with_findings(
            vec![finding(
                "finding_dynamic",
                FindingCategory::DynamicReviewRequired,
                Severity::Info,
                vec!["evidence_dynamic_cookie"],
            )],
            vec![evidence("evidence_dynamic_cookie", "src/app.ts", None)],
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&render(&report)).expect("SARIF should parse as JSON");

        assert_eq!(parsed["runs"][0]["results"][0]["level"], "note");
        assert!(
            parsed["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
                .as_object()
                .expect("rule properties")
                .get("security-severity")
                .is_none()
        );
    }

    #[test]
    fn deduplicates_repeated_evidence_locations() {
        let mut duplicate = evidence(
            "evidence_cookie_secure_duplicate",
            "src/app.ts",
            Some("duplicate"),
        );
        duplicate.detector_id = "cookie.attribute.secure.duplicate".to_string();
        let report = report_with_findings(
            vec![finding(
                "finding_cookie",
                FindingCategory::HighConfidenceMisconfiguration,
                Severity::High,
                vec!["evidence_cookie_secure", "evidence_cookie_secure_duplicate"],
            )],
            vec![
                evidence("evidence_cookie_secure", "src/app.ts", Some("original")),
                duplicate,
            ],
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&render(&report)).expect("SARIF should parse as JSON");

        assert_eq!(
            parsed["runs"][0]["results"][0]["locations"]
                .as_array()
                .expect("locations")
                .len(),
            1
        );
    }
}
