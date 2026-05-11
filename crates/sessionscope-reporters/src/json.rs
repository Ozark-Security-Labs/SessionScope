use sessionscope_model::ScanReport;

pub fn render(report: &ScanReport) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"{}\",\n",
            "  \"summary\": {{\n",
            "    \"files_discovered\": {},\n",
            "    \"files_scanned\": {},\n",
            "    \"files_skipped\": {},\n",
            "    \"findings\": {}\n",
            "  }}\n",
            "}}\n"
        ),
        escape_json(report.schema_version),
        report.summary.files_discovered,
        report.summary.files_scanned,
        report.summary.files_skipped,
        report.findings.len()
    )
}

fn escape_json(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}
