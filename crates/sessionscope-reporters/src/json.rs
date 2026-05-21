use sessionscope_model::ScanReport;

pub fn render(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).expect("ScanReport serialization should not fail")
}

#[cfg(test)]
mod tests {
    use sessionscope_model::{SCHEMA_VERSION, ScanReport, ScanSummary};

    use super::render;

    #[test]
    fn renders_parseable_full_scan_report() {
        let report = ScanReport {
            schema_version: SCHEMA_VERSION.to_string(),
            summary: ScanSummary {
                files_discovered: 1,
                files_scanned: 1,
                files_skipped: 0,
                diagnostics: Vec::new(),
                worker_panic_count: 0,
            },
            files: Vec::new(),
            artifacts: Vec::new(),
            evidence: Vec::new(),
            lifecycle_paths: Vec::new(),
            findings: Vec::new(),
        };

        let rendered = render(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("rendered JSON should parse");
        let deserialized: ScanReport =
            serde_json::from_str(&rendered).expect("rendered JSON should match ScanReport schema");

        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert_eq!(parsed["summary"]["files_discovered"], 1);
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("summary").is_some());
        assert!(parsed.get("files").is_some());
        assert!(parsed.get("artifacts").is_some());
        assert!(parsed.get("evidence").is_some());
        assert!(parsed.get("lifecycle_paths").is_some());
        assert!(parsed.get("findings").is_some());
        assert!(parsed["artifacts"].is_array());
        assert!(parsed["evidence"].is_array());
        assert!(parsed["lifecycle_paths"].is_array());
        assert!(parsed["findings"].is_array());
        assert_eq!(deserialized.schema_version, SCHEMA_VERSION);
    }
}
